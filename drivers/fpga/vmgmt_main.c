// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Versal PCIe device
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 */
#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/fpga/fpga-bridge.h>
#include <linux/fpga/fpga-mgr.h>
#include <linux/fpga/fpga-region.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/xclbin.h>
#include <linux/vmgmt.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include "vmgmt_xgq_cmd.h"
#include "vmgmt_common.h"

#define MAX_DEVICES		24
#define DRV_VERSION		"0.1"
#define DRV_NAME		"vmgmt"
#define CLASS_NAME		"versal"
#define PCIE_DEVICE_ID_PF_V70		0x5094
#define PCIE_DEVICE_ID_PF_V70PQ2	0x50b0

#define XGQ_SQ_TAIL_POINTER     0x0
#define XGQ_SQ_INTR_REG         0x4
#define XGQ_SQ_INTR_CTRL        0xC
#define XGQ_CQ_TAIL_POINTER     0x100
#define XGQ_CQ_INTR_REG         0x104
#define XGQ_CQ_INTR_CTRL        0x10C

#define XGQ_VMR_SQ_BAR		0
#define XGQ_VMR_SQ_BAR_OFF	0x2010000
#define XGQ_VMR_SQ_SIZE		0x1000
#define XGQ_VMR_PAYLOAD_BAR	0
#define XGQ_VMR_PAYLOAD_OFF	0x8000000
#define XGQ_VMR_PAYLOAD_SIZE	0x8000000

#define XGQ_VMR_PMC_BAR		0
#define XGQ_VMR_PMC_BAR_OFF	0x2040000

#define XGQ_INVALID_CID		0xFFFF
#define XGQ_FLASH_TIME		msecs_to_jiffies(600 * 1000)
#define XGQ_DOWNLOAD_TIME	msecs_to_jiffies(300 * 1000)
#define XGQ_CONFIG_TIME		msecs_to_jiffies(30 * 1000)
#define XGQ_WAIT_TIMEOUT	msecs_to_jiffies(60 * 1000)
#define XGQ_MSLEEP_1S		(1000)

#define COMMS_CHAN_PROTOCOL_VERSION	1
#define COMMS_CHAN_BAR		0
#define COMMS_CHAN_BAR_OFF	0x2000000
#define COMMS_CHAN_REGS_SIZE	0x1000
#define COMMS_CHAN_TIMER	(HZ / 10)
#define COMMS_DATA_LEN		16
#define COMMS_DATA_TYPE_MASK	GENMASK(7, 0)
#define COMMS_DATA_EOM_MASK	BIT(31)
#define COMMS_MSG_END		BIT(31)

#define COMMS_REG_WRDATA_OFF	0x0
#define COMMS_REG_RDDATA_OFF	0x8
#define COMMS_REG_STATUS_OFF	0x10
#define COMMS_REG_RIT_OFF	0x1C
#define COMMS_REG_IS_OFF	0x20
#define COMMS_REG_IE_OFF	0x24
#define COMMS_REG_IP_OFF	0x28
#define COMMS_REG_ERROR_OFF	0x14
#define COMMS_REG_CTRL_OFF	0x2C

#define MAX_WAIT		30

/*
 * Shared memory layout
 * ------------------- 0x0
 *  log page
 * ------------------- VMR_LOG_PAGE_SIZE
 *  data
 *  ...
 * -------------------
 */
#define VMR_LOG_PAGE_SIZE		(1024 * 1024)
#define VMR_LOG_PAGE_NUM		1
#define VMR_LOG_ADDR_OFF		0x0
#define VMR_DATA_ADDR_OFF		(VMR_LOG_PAGE_SIZE * VMR_LOG_PAGE_NUM)
#define VMR_LOG_MAXLEN			0x100

#define VMR_INFO(vmr, fmt, args...)	dev_info(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_WARN(vmr, fmt, args...)	dev_warn(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_ERR(vmr, fmt, args...)	dev_err(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_DBG(vmr, fmt, args...)	dev_dbg(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)

#define ICAP_XCLBIN_V2			"xclbin2"

int health_interval;
module_param(health_interval, int, 0644);
MODULE_PARM_DESC(health_interval, "Health check interval in seconds, range (1 minium - 5 default)");

struct vmr_drvdata;

static DEFINE_IDA(vmgmt_dev_minor_ida);
static dev_t vmgmt_devnode;
struct class *vmgmt_class;

struct vmr_char {
	int			minor;
	struct cdev		cdev;
	struct device		*sys_device;
	struct vmr_drvdata	*vmr;
};

struct vmr_cmd {
	struct xgq_cmd_sq	xgq_cmd_entry;
	struct list_head	xgq_cmd_list;
	struct completion	xgq_cmd_complete;
	void			*xgq_cmd_arg;
	struct timer_list	xgq_cmd_timer;
	struct vmr_drvdata	*xgq_vmr;
	unsigned long		xgq_cmd_timeout_jiffies; /* for time_after */
	int			xgq_cmd_rcode;
	struct xgq_cmd_cq_default_payload	xgq_cmd_cq_payload;
};

struct xgq_worker {
	struct task_struct	*complete_thread;
	bool			error;
	bool			stop;
	struct vmr_drvdata	*xgq_vmr;
};

enum comms_req_ops {
	COMMS_REQ_OPS_UNKNOWN =			0,
	COMMS_REQ_OPS_TEST_READY =		1,
	COMMS_REQ_OPS_TEST_READ =		2,
	COMMS_REQ_OPS_LOCK_BITSTREAM =		3,
	COMMS_REQ_OPS_UNLOCK_BITSTREAM =	4,
	COMMS_REQ_OPS_HOT_RESET =		5,
	COMMS_REQ_OPS_FIREWALL =		6,
	COMMS_REQ_OPS_LOAD_XCLBIN_KADDR =	7,
	COMMS_REQ_OPS_LOAD_XCLBIN =		8,
	COMMS_REQ_OPS_RECLOCK =			9,
	COMMS_REQ_OPS_PEER_DATA =		10,
	COMMS_REQ_OPS_USER_PROBE =		11,
	COMMS_REQ_OPS_MGMT_STATE =		12,
	COMMS_REQ_OPS_CHG_SHELL =		13,
	COMMS_REQ_OPS_PROGRAM_SHELL =		14,
	COMMS_REQ_OPS_READ_P2P_BAR_ADDR =	15,
	COMMS_REQ_OPS_SDR_DATA =		16,
	COMMS_REQ_OPS_LOAD_XCLBIN_SLOT_KADDR =	17,
	COMMS_REQ_OPS_LOAD_SLOT_XCLBIN =	18,
	COMMS_REQ_OPS_GET_PROTOCOL_VERSION =	19,
	COMMS_REQ_OPS_GET_XCLBIN_UUID =		20,
	COMMS_REQ_OPS_MAX,
};

enum comms_msg_type {
	COMMS_MSG_INVALID,
	COMMS_MSG_TEST,
	COMMS_MSG_START,
	COMMS_MSG_BODY,
};

enum comms_msg_service_type {
	COMMS_MSG_SRV_RESPONSE =	BIT(0),
	COMMS_MSG_SRV_REQUEST =		BIT(1),
};

struct comms_hw_msg {
	struct {
		u32		type;
		u32		payload_size;
	} header;
	struct {
		u64	id;
		u32	flags;
		u32	payload_size;
		u32	payload[COMMS_DATA_LEN - 6];
	} body;
} __attribute((packed));

struct comms_srv_req {
	u64			flags;
	u32			opcode;
	u32			data[1];
};

struct comms_srv_ver_resp {
	u32			version;
};

struct comms_srv_uuid_resp {
	uuid_t			uuid;
};

struct comms_msg {
	u64			id;
	u32			flags;
	u32			len;
	u32			bytes_read;
	u32			data[10];
};

struct comms_chan {
	struct vmr_drvdata	*vmr;
	struct mutex		lock; /* to protect comms channel data */
	struct timer_list	timer;
	struct work_struct	work;
};

struct vmr_fw_tnx {
	struct vmr_cmd		*cmd;
	enum xgq_cmd_opcode	opcode;
	int			id;
};

struct vmr_drvdata {
	struct pci_dev		*pdev;
	struct vmr_char		char_dev;
	struct xgq		xgq_queue;
	u64			xgq_io_hdl;
	void __iomem		*xgq_payload_base;
	void __iomem		*xgq_sq_base;
	void __iomem		*xgq_cq_base;
	void __iomem		*xgq_ring_base;
	void __iomem		*xgq_pmc_mux_base;
	struct mutex		xgq_lock; /* for exclusive reference to xgq command data */
	struct idr		xgq_vmr_cid_idr;
	struct vmr_shared_mem	xgq_vmr_shared_mem;
	struct list_head	xgq_submitted_cmds;
	struct xgq_worker	xgq_complete_worker;
	struct xgq_worker	xgq_health_worker;
	bool			xgq_halted;
	struct semaphore	xgq_data_sema;
	struct semaphore	xgq_log_page_sema;
	struct xgq_cmd_cq_default_payload xgq_cq_payload;
	int			xgq_vmr_debug_level;
	bool			xgq_vmr_program;
	int			xgq_vmr_need_hot_reset;

	uuid_t			xclbin_uuid;
	uuid_t			intf_uuid;
	void __iomem		*comms_chan_base;
	struct comms_chan	comms;

	struct fpga_bridge	*bridge;
	struct fpga_region	*region;
	struct fpga_manager	*mgr;
	enum fpga_mgr_states	state;
	struct vmr_fw_tnx	fw_tnx;

	u32			saved_config[8][16]; /* save config for pci reset */
	void			*debugfs_root;
};

static const struct pci_device_id versal_mgmt_id_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, PCIE_DEVICE_ID_PF_V70),},
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, PCIE_DEVICE_ID_PF_V70PQ2),},
	{0,}
};

static const struct xgq_vmr_supported_ver {
	u16	major;
	u16	minor;
} supported_vers[] = {
	{1, 0},
};

static const enum xgq_cmd_opcode opcode[] = {
	XGQ_CMD_OP_DOWNLOAD_PDI,
	XGQ_CMD_OP_PROGRAM_SCFW,
	XGQ_CMD_OP_VMR_CONTROL,
	XGQ_CMD_OP_IDENTIFY,
};

static void vmr_offline_services(struct vmr_drvdata *vmr);
static int xgq_log_page_af(struct vmr_drvdata *vmr);

static inline void vmr_memcpy_toio32(void *dst, void *buf, u32 size)
{
	int i;

	WARN_ON(size & 0x3);

	for (i = 0; i < size / 4; i++)
		iowrite32(((u32 *)buf)[i], ((char *)(dst) + sizeof(u32) * i));
}

static inline void vmr_memcpy_fromio(void *buf, void *src, u32 size)
{
	int i;

	WARN_ON(size & 0x3);

	for (i = 0; i < size / 4; i++)
		((u32 *)buf)[i] = ioread32((char *)(src) + sizeof(u32) * i);
}

void read_completion(struct xgq_com_queue_entry *ccmd, u64 addr)
{
	u32 i;
	u32 *buffer = (u32 *)ccmd;

	for (i = 0; i < XGQ_COM_Q1_SLOT_SIZE / sizeof(u32); i++)
		buffer[i] = xgq_reg_read32(0, addr + i * sizeof(u32));

	// Write 0 to first word to make sure the cmd state is not NEW
	xgq_reg_write32(0, addr, 0x0);
}

static void vmr_cmd_complete(struct vmr_cmd *cmd, struct xgq_com_queue_entry *ccmd)
{
	struct xgq_cmd_cq *cmd_cq = (struct xgq_cmd_cq *)ccmd;

	cmd->xgq_cmd_rcode = (int)ccmd->rcode;
	/* preserve payload prior to free xgq_cmd_cq */
	memcpy(&cmd->xgq_cmd_cq_payload, &cmd_cq->cq_default_payload,
	       sizeof(cmd_cq->cq_default_payload));

	complete(&cmd->xgq_cmd_complete);

	/*
	 *	if (cmd->xgq_cmd_rcode)
	 *		vmr_log_dump_debug(vmr, cmd);
	 */
}

static void cmd_complete(struct vmr_drvdata *vmr, struct xgq_com_queue_entry *ccmd)
{
	struct vmr_cmd *cmd_iter = NULL;
	struct list_head *pos = NULL, *next = NULL;

	list_for_each_safe(pos, next, &vmr->xgq_submitted_cmds) {
		cmd_iter = list_entry(pos, struct vmr_cmd, xgq_cmd_list);

		if (cmd_iter->xgq_cmd_entry.hdr.cid == ccmd->hdr.cid) {
			list_del(pos);
			vmr_cmd_complete(cmd_iter->xgq_cmd_arg, ccmd);
			return;
		}
	}

	VMR_WARN(vmr, "unknown cid %d received", ccmd->hdr.cid);

	if (ccmd->hdr.cid == XGQ_INVALID_CID) {
		VMR_ERR(vmr, "invalid cid %d, offline xgq services...", ccmd->hdr.cid);
		/*
		 * Note: xgq_lock mutex is on, release the lock and offline service.
		 */
		mutex_unlock(&vmr->xgq_lock);
		vmr_offline_services(vmr);
		mutex_lock(&vmr->xgq_lock);
	}
}

static int vmr_health_check(struct vmr_drvdata *vmr)
{
	int tripped = 0;

	if (!health_interval)
		return 0;

	/*TODO: should we check VMR and APU healthy here? */

	tripped = xgq_log_page_af(vmr);
#if 0
	if (tripped)
		VMR_ERR(vmr, "Card is in Bad state, please request pci hot reset");
#endif

	return tripped;
}

static int complete_worker(void *data)
{
	struct xgq_worker *xw = (struct xgq_worker *)data;
	struct vmr_drvdata *vmr = xw->xgq_vmr;

	while (!xw->stop) {
		while (!list_empty(&vmr->xgq_submitted_cmds)) {
			u64 slot_addr = 0;
			struct xgq_com_queue_entry ccmd;

			usleep_range(1000, 2000);
			if (kthread_should_stop())
				xw->stop = true;

			mutex_lock(&vmr->xgq_lock);

			if (xgq_consume(&vmr->xgq_queue, &slot_addr)) {
				mutex_unlock(&vmr->xgq_lock);
				continue;
			}

			read_completion(&ccmd, slot_addr);
			cmd_complete(vmr, &ccmd);

			xgq_notify_peer_consumed(&vmr->xgq_queue);

			mutex_unlock(&vmr->xgq_lock);
		}

		//polling for now, TODO fix this
		usleep_range(1000, 2000);
		/*
		 * if (vmr->xgq_polling)
		 *	usleep_range(1000, 2000);
		 * else
		 *	(void) wait_for_completion_killable(&vmr->xgq_irq_complete);
		 */

		if (kthread_should_stop())
			xw->stop = true;
	}

	return xw->error ? 1 : 0;
}

static int health_worker(void *data)
{
	struct xgq_worker *xw = (struct xgq_worker *)data;
	struct vmr_drvdata *vmr = xw->xgq_vmr;

	while (!xw->stop) {
		msleep(health_interval * 1000);

		if (vmr_health_check(vmr))
			vmr->xgq_vmr_need_hot_reset = 1;

		if (kthread_should_stop())
			xw->stop = true;
	}

	return xw->error ? 1 : 0;
}

static int init_complete_worker(struct xgq_worker *xw)
{
	xw->complete_thread =
		kthread_run(complete_worker, (void *)xw, "complete worker");

	if (IS_ERR(xw->complete_thread))
		return PTR_ERR(xw->complete_thread);

	return 0;
}

static int init_health_worker(struct xgq_worker *xw)
{
	health_interval = 5;

	xw->complete_thread =
		kthread_run(health_worker, (void *)xw, "health worker");

	if (IS_ERR(xw->complete_thread))
		return PTR_ERR(xw->complete_thread);

	return 0;
}

static int fini_worker(struct xgq_worker *xw)
{
	return kthread_stop(xw->complete_thread);
};

/*
 * VMR basic ops checker
 *
 * The basic OP commands functionality for Identify OP and
 * Flash OP is restricted to be strictly unmodified to
 * ensure backward compatibility with older shell versions.
 */
static bool vmr_xgq_basic_op(struct vmr_cmd *cmd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(opcode); i++) {
		if (cmd->xgq_cmd_entry.hdr.opcode == opcode[i])
			return true;
	}

	return false;
}

static int vmr_submit_cmd(struct vmr_drvdata *vmr, struct vmr_cmd *cmd)
{
	u64 slot_addr = 0;
	int rval = 0;

	mutex_lock(&vmr->xgq_lock);
	if (vmr->xgq_halted && !vmr_xgq_basic_op(cmd)) {
		VMR_ERR(vmr, "vmr service is halted");
		rval = -EIO;
		goto done;
	}

	rval = xgq_produce(&vmr->xgq_queue, &slot_addr);
	if (rval) {
		VMR_ERR(vmr, "xgq_produce failed: %d", rval);
		goto done;
	}

	vmr_memcpy_toio32((void __iomem *)slot_addr, &cmd->xgq_cmd_entry,
			  sizeof(cmd->xgq_cmd_entry));

	xgq_notify_peer_produced(&vmr->xgq_queue);

	list_add_tail(&cmd->xgq_cmd_list, &vmr->xgq_submitted_cmds);

done:
	mutex_unlock(&vmr->xgq_lock);
	return rval;
}

static int vmr_create_cmd(struct vmr_drvdata *vmr, int opcode,
			  struct vmr_cmd **cmd_ptr, int *id, u64 timeout)
{
	struct vmr_cmd *cmd = NULL;
	struct xgq_cmd_sq_hdr *hdr = NULL;
	int ret;

	/* set id to invalid, 0 is a valid value */
	*id = -1;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		VMR_ERR(vmr, "no memory");
		return -ENOMEM;
	}

	cmd->xgq_cmd_arg = cmd;
	cmd->xgq_vmr = vmr;

	hdr = &cmd->xgq_cmd_entry.hdr;
	hdr->opcode = opcode;
	hdr->state = XGQ_SQ_CMD_NEW;
	hdr->count = 0; //temporary set to 0, create_payload will update it later
	mutex_lock(&vmr->xgq_lock);
	*id = idr_alloc_cyclic(&vmr->xgq_vmr_cid_idr, vmr, 0, 0, GFP_KERNEL);
	mutex_unlock(&vmr->xgq_lock);
	if (*id < 0) {
		VMR_ERR(vmr, "alloc id failed: %d", *id);
		ret = -ENOMEM;
		goto error;
	}
	hdr->cid = *id;

	init_completion(&cmd->xgq_cmd_complete);
	cmd->xgq_cmd_timeout_jiffies = jiffies + timeout;

	*cmd_ptr = cmd;
	return 0;
error:
	kfree(cmd);
	return ret;
}

static void vmr_remove_cmd(struct vmr_drvdata *vmr, struct vmr_cmd *cmd, int id)
{
	if (id >= 0) {
		mutex_lock(&vmr->xgq_lock);
		idr_remove(&vmr->xgq_vmr_cid_idr, id);
		mutex_unlock(&vmr->xgq_lock);
	}

	kfree(cmd);
}

static inline u32 vmr_shared_mem_size(struct vmr_drvdata *vmr)
{
	return vmr->xgq_vmr_shared_mem.vmr_data_end -
		vmr->xgq_vmr_shared_mem.vmr_data_start + 1;
}

static inline u32 shm_size_log_page(struct vmr_drvdata *vmr)
{
	return (VMR_LOG_PAGE_SIZE * VMR_LOG_PAGE_NUM);
}

static inline u32 shm_addr_data(struct vmr_drvdata *vmr)
{
	return vmr->xgq_vmr_shared_mem.vmr_data_start + VMR_DATA_ADDR_OFF;
}

static inline u32 shm_size_data(struct vmr_drvdata *vmr)
{
	return vmr_shared_mem_size(vmr) - shm_size_log_page(vmr);
}

static int shm_acquire_data(struct vmr_drvdata *vmr, u32 *addr, u32 *len)
{
	if (down_interruptible(&vmr->xgq_data_sema)) {
		VMR_ERR(vmr, "cancelled");
		return -EIO;
	}

	*addr = shm_addr_data(vmr);
	*len = shm_size_data(vmr);
	return 0;
}

static void shm_release_data(struct vmr_drvdata *vmr)
{
	up(&vmr->xgq_data_sema);
}

static inline u32 shm_addr_log_page(struct vmr_drvdata *vmr)
{
	return vmr->xgq_vmr_shared_mem.vmr_data_start + VMR_LOG_ADDR_OFF;
}

static int shm_acquire_log_page(struct vmr_drvdata *vmr, u32 *addr, u32 *len)
{
	if (down_interruptible(&vmr->xgq_log_page_sema)) {
		VMR_ERR(vmr, "cancelled");
		return -EIO;
	}

	/*TODO: memset shared memory to all zero */
	*addr = shm_addr_log_page(vmr);
	*len = VMR_LOG_PAGE_SIZE;
	return 0;
}

static void shm_release_log_page(struct vmr_drvdata *vmr)
{
	up(&vmr->xgq_log_page_sema);
}

static void memcpy_to_device(struct vmr_drvdata *vmr, u32 offset, const void *data, size_t len)
{
	void __iomem *dst = vmr->xgq_payload_base + offset;

	memcpy_toio(dst, data, len);
}

static void memcpy_from_device(struct vmr_drvdata *vmr, u32 offset, void *dst, size_t len)
{
	void __iomem *src = vmr->xgq_payload_base + offset;

	memcpy_fromio(dst, src, len);
}

static int vmr_data_payload_init(struct vmr_drvdata *vmr, struct vmr_cmd *cmd, int opcode,
				 const void *buf, u32 req_len, u64 priv)
{
	struct xgq_cmd_data_payload *payload = NULL;
	struct xgq_cmd_sq_hdr *hdr = NULL;
	u32 address = 0;
	u32 length = 0;

	if (shm_acquire_data(vmr, &address, &length))
		return -EIO;

	if (length < req_len) {
		VMR_ERR(vmr, "request %d is larger than available %d", req_len, length);
		shm_release_data(vmr);
		return -EINVAL;
	}

	/* update payload content */
	payload = (opcode == XGQ_CMD_OP_LOAD_XCLBIN) ?
		&cmd->xgq_cmd_entry.pdi_payload :
		&cmd->xgq_cmd_entry.xclbin_payload;

	if (req_len > 0)
		memcpy_to_device(vmr, address, buf, req_len);

	payload->address = address;
	payload->size = req_len;
	/* Clear Bits of given mask */
	payload->flash_type &= ~XGQ_MASK_FLASH_TYPE;
	payload->flash_type |= FIELD_PREP(XGQ_MASK_FLASH_TYPE,XGQ_CMD_FLASH_DEFAULT);
	payload->priv = priv;

	/* update payload size in hdr */
	hdr = &cmd->xgq_cmd_entry.hdr;
	hdr->count = sizeof(*payload);

	return 0;
}

static void vmr_data_payload_fini(struct vmr_drvdata *vmr)
{
	shm_release_data(vmr);
}

static int vmr_log_payload_init(struct vmr_drvdata *vmr, struct vmr_cmd *cmd,
				enum xgq_cmd_log_page_type req_pid, loff_t off, u32 req_len,
				u32 *addr, u32 *len)
{
	struct xgq_cmd_log_payload *payload = NULL;
	struct xgq_cmd_sq_hdr *hdr = NULL;
	u32 address = 0;
	u32 length = 0;

	if (shm_acquire_log_page(vmr, &address, &length))
		return -EIO;

	if (length < req_len) {
		VMR_ERR(vmr, "request %d is larger than available %d", req_len, length);
		shm_release_log_page(vmr);
		return -EINVAL;
	}

	/* update payload content */
	payload = &cmd->xgq_cmd_entry.log_payload;

	payload->address = address;
	payload->size = req_len ? req_len : length; // if req_len is 0, use entire length
	payload->offset = off;
	/* Clear Bits of given mask */
	payload->pid &= ~XGQ_MASK_PID;
	payload->pid |= FIELD_PREP(XGQ_MASK_PID,req_pid);

	/* update payload size in hdr */
	hdr = &cmd->xgq_cmd_entry.hdr;
	hdr->count = sizeof(*payload);

	/* pass log buffer address and length back */
	*addr = address;
	*len = length;

	return 0;
}

static void vmr_log_payload_fini(struct vmr_drvdata *vmr)
{
	shm_release_log_page(vmr);
}

static void vmr_submitted_cmd_remove(struct vmr_drvdata *vmr, struct vmr_cmd *cmd)
{
	struct vmr_cmd *cmd_iter;
	struct list_head *pos = NULL, *next = NULL;

	mutex_lock(&vmr->xgq_lock);
	list_for_each_safe(pos, next, &vmr->xgq_submitted_cmds) {
		cmd_iter = list_entry(pos, struct vmr_cmd, xgq_cmd_list);

		/* Find the aborted cmd */
		if (cmd_iter == cmd) {
			list_del(pos);

			cmd->xgq_cmd_rcode = -EIO;
			VMR_ERR(vmr, "cmd id: %d op: 0x%x removed.",
				cmd->xgq_cmd_entry.hdr.cid,
				cmd->xgq_cmd_entry.hdr.opcode);
		}
	}
	mutex_unlock(&vmr->xgq_lock);
}

static void vmr_submitted_cmds_drain(struct vmr_drvdata *vmr)
{
	struct vmr_cmd *xgq_cmd = NULL;
	struct list_head *pos = NULL, *next = NULL;

	mutex_lock(&vmr->xgq_lock);
	list_for_each_safe(pos, next, &vmr->xgq_submitted_cmds) {
		xgq_cmd = list_entry(pos, struct vmr_cmd, xgq_cmd_list);

		/* Only timed out cmds can be drained */
		if (time_after(jiffies, xgq_cmd->xgq_cmd_timeout_jiffies)) {
			list_del(pos);

			xgq_cmd->xgq_cmd_rcode = -ETIME;
			complete(&xgq_cmd->xgq_cmd_complete);
			VMR_ERR(vmr, "cmd id: %d op: 0x%x timed out, hot reset is required!",
				xgq_cmd->xgq_cmd_entry.hdr.cid,
				xgq_cmd->xgq_cmd_entry.hdr.opcode);
		}
	}
	mutex_unlock(&vmr->xgq_lock);
}

static bool vmr_submitted_cmds_empty(struct vmr_drvdata *vmr)
{
	mutex_lock(&vmr->xgq_lock);
	if (list_empty(&vmr->xgq_submitted_cmds)) {
		mutex_unlock(&vmr->xgq_lock);
		return true;
	}
	mutex_unlock(&vmr->xgq_lock);

	return false;
}

static int vmr_supported_version(u16 major, u16 minor)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(supported_vers); i++) {
		if (supported_vers[i].major == major &&
		    supported_vers[i].minor == minor)
			return 0;
	}

	return -ENOTSUPP;
}

static int vmr_identify_op(struct vmr_drvdata *vmr)
{
	struct vmr_cmd *cmd = NULL;
	int id = -1;
	int ret = 0;

	ret = vmr_create_cmd(vmr, XGQ_CMD_OP_IDENTIFY, &cmd, &id, XGQ_CONFIG_TIME);
	if (ret)
		return ret;

	ret = vmr_submit_cmd(vmr, cmd);
	if (ret)
		goto done;

	if (wait_for_completion_killable(&cmd->xgq_cmd_complete)) {
		VMR_ERR(vmr, "submitted cmd killed");
		vmr_submitted_cmd_remove(vmr, cmd);
	}

	ret = cmd->xgq_cmd_rcode;

	if (ret) {
		VMR_ERR(vmr, "ret: %d", ret);
	} else {
		struct xgq_cmd_cq_vmr_identify_payload *payload = NULL;
		u16 major, minor;

		payload = (struct xgq_cmd_cq_vmr_identify_payload *)&cmd->xgq_cmd_cq_payload;
		major = payload->ver_major;
		minor = payload->ver_minor;

		ret = vmr_supported_version(major, minor);
		VMR_INFO(vmr, "version: %d:%d ret:%d", major, minor, ret);
	}
done:
	vmr_remove_cmd(vmr, cmd, id);
	return ret;
}

static inline int valid_data_opcode(int opcode)
{
	int data_opcodes[] = { XGQ_CMD_OP_LOAD_XCLBIN,
			       XGQ_CMD_OP_DOWNLOAD_PDI,
			       XGQ_CMD_OP_LOAD_APUBIN,
			       XGQ_CMD_OP_PROGRAM_SCFW,
			     };

	for (int i = 0; i < ARRAY_SIZE(data_opcodes); i++) {
		if (data_opcodes[i] == opcode)
			return 0;
	}

	return -EINVAL;
}

static int vmr_wait_not_killable(struct vmr_cmd *cmd)
{
	/*
	 * For pdi/xclbin data transfer, we block any cancellation and
	 * wait till command completed and then release resources safely.
	 * We call cond_resched after every timeout to avoid linux kernel
	 * warning for thread hanging too long.
	 *
	 * The health thread will check if any command jiffies are due and
	 * clean the pending command.
	 */
	while (!wait_for_completion_timeout(&cmd->xgq_cmd_complete, XGQ_WAIT_TIMEOUT))
		cond_resched();

	/* rcode 0 means succeeded, otherwise an error */
	return cmd->xgq_cmd_rcode;
}

static int vmr_transfer_data(struct vmr_drvdata *vmr, const void *buf, u32 len, u64 priv,
			     enum xgq_cmd_opcode opcode, u32 timer)
{
	struct vmr_cmd *cmd = NULL;
	int id = 0;
	int ret = 0;

	if (valid_data_opcode(opcode)) {
		VMR_WARN(vmr, "unsupported opcode %d", opcode);
		return -EINVAL;
	}

	ret = vmr_create_cmd(vmr, opcode, &cmd, &id, timer);
	if (ret)
		return ret;

	ret = vmr_data_payload_init(vmr, cmd, opcode, buf, len, priv);
	if (ret) {
		vmr_remove_cmd(vmr, cmd, id);
		return ret;
	}

	ret = vmr_submit_cmd(vmr, cmd);
	if (ret) {
		VMR_ERR(vmr, "submit cmd failed, cid %d", id);
		goto done;
	}

	vmr_wait_not_killable(cmd);

	/* If return is 0, we set length as return value */
	if (cmd->xgq_cmd_rcode)
		ret = cmd->xgq_cmd_rcode;
	else
		ret = len;

done:
	vmr_data_payload_fini(vmr);
	vmr_remove_cmd(vmr, cmd, id);
	return ret;
}

static int vmr_transfer_data_impl(struct vmr_drvdata *vmr, char *buf, size_t len,
				  enum xgq_cmd_opcode opcode)
{
	int ret;

	ret = vmr_transfer_data(vmr, buf, (u32)len, 0, opcode, XGQ_DOWNLOAD_TIME);
	if (ret != len) {
		VMR_ERR(vmr, "ret: %d, buf request: %ld", ret, len);
		return -EIO;
	}

	VMR_INFO(vmr, "successfully download len %ld", len);
	return 0;
}

static int xgq_log_page_af(struct vmr_drvdata *vmr)
{
	struct vmr_cmd *cmd = NULL;
	struct xgq_cmd_cq_log_page_payload *log = NULL;
	int ret = 0;
	int id = 0;
	u32 address = 0;
	u32 len = 0;
	u32 log_size = 0;

	ret = vmr_create_cmd(vmr, XGQ_CMD_OP_GET_LOG_PAGE, &cmd, &id, XGQ_CONFIG_TIME);
	if (ret)
		return ret;

	ret = vmr_log_payload_init(vmr, cmd, XGQ_CMD_LOG_AF_CHECK, 0, 0, &address, &len);
	if (ret) {
		vmr_remove_cmd(vmr, cmd, id);
		return ret;
	}

	ret = vmr_submit_cmd(vmr, cmd);
	if (ret) {
		VMR_ERR(vmr, "submit cmd failed, cid %d", id);
		goto done;
	}

	/* wait for command completion */
	if (wait_for_completion_killable(&cmd->xgq_cmd_complete)) {
		VMR_ERR(vmr, "submitted cmd killed");
		vmr_submitted_cmd_remove(vmr, cmd);
		/* this is not a firewall trip */
		ret = 0;
		goto done;
	}

	ret = cmd->xgq_cmd_rcode;

	if (ret == -ETIME || ret == -EINVAL)
		ret = 0;

	/*
	 * No matter ret is 0 or not, the device might return error messages.
	 */
	log = (struct xgq_cmd_cq_log_page_payload *)&cmd->xgq_cmd_cq_payload;
	log_size = log->count;
	if (log_size > len) {
		VMR_WARN(vmr, "return log size %d is greater than request %d",
			 log->count, len);
		log_size = len;
	}

	if (log_size > 0 && log_size < VMR_LOG_MAXLEN) {
		char *log_msg = vmalloc(log_size + 1);
		if (!log_msg) {
			VMR_ERR(vmr, "vmalloc failed to find %d memory", log_size + 1);
			goto done;
		}
		memcpy_from_device(vmr, address, log_msg, log_size);
		log_msg[log_size] = '\0';

		VMR_ERR(vmr, "%s", log_msg);
		vfree(log_msg);
	}

done:
	vmr_log_payload_fini(vmr);
	vmr_remove_cmd(vmr, cmd, id);

	return ret;
}

static int xgq_log_page_fw(struct vmr_drvdata *vmr, char **fw, size_t *fw_size,
			   enum xgq_cmd_log_page_type req_pid, loff_t off, size_t req_size)
{
	struct vmr_cmd *cmd = NULL;
	int ret = 0;
	int id = 0;
	u32 address = 0;
	u32 len = 0;

	ret = vmr_create_cmd(vmr, XGQ_CMD_OP_GET_LOG_PAGE, &cmd, &id, XGQ_CONFIG_TIME);
	if (ret)
		return ret;

	ret = vmr_log_payload_init(vmr, cmd, req_pid, off, req_size, &address, &len);
	if (ret) {
		vmr_remove_cmd(vmr, cmd, id);
		return ret;
	}

	ret = vmr_submit_cmd(vmr, cmd);
	if (ret) {
		VMR_ERR(vmr, "submit cmd failed, cid %d", id);
		goto done;
	}

	/* wait for command completion */
	if (wait_for_completion_killable(&cmd->xgq_cmd_complete)) {
		VMR_ERR(vmr, "submitted cmd killed");
		vmr_submitted_cmd_remove(vmr, cmd);
	}

	ret = cmd->xgq_cmd_rcode;

	if (ret) {
		VMR_ERR(vmr, "failed ret %d", ret);
	} else {
		struct xgq_cmd_cq_log_page_payload *fw_result = NULL;

		fw_result = (struct xgq_cmd_cq_log_page_payload *)&cmd->xgq_cmd_cq_payload;

		if (fw_result->count > len) {
			VMR_ERR(vmr, "need to alloc %d for device data",
				fw_result->count);
			ret = -ENOSPC;
		} else if (fw_result->count == 0) {
			VMR_WARN(vmr, "fw size is zero");
			ret = -EINVAL;
		} else {
			*fw_size = fw_result->count;
			*fw = vmalloc(*fw_size);
			if (!*fw) {
				VMR_ERR(vmr, "vmalloc failed");
				ret = -ENOMEM;
				goto done;
			}
			memcpy_from_device(vmr, address, *fw, *fw_size);
			ret = 0;
			VMR_INFO(vmr, "loading fw from vmr size %ld", *fw_size);
		}
	}

done:
	vmr_log_payload_fini(vmr);
	vmr_remove_cmd(vmr, cmd, id);

	return ret;
}

static int vmr_get_intf_uuid(struct vmr_drvdata *vmr)
{
	int ret = 0;
	char *buf = NULL;
	size_t size = 0;
	char str[UUID_STRING_LEN];
	u8 i, j;

	ret = xgq_log_page_fw(vmr, &buf, &size,
			      XGQ_CMD_LOG_SHELL_INTERFACE_UUID, 0, 0);
	if (ret) {
		VMR_INFO(vmr, "Failed to get intf uuid from vmr: %d", ret);
		return ret;
	}

	VMR_INFO(vmr, "cast fw to string %s", buf);

	/* parse uuid into a valid uuid string format */
	for (i  = 0, j = 0; i < size; i++) {
		str[j++] = buf[i];
		if (j == 8 || j == 13 || j == 18 || j == 23)
			str[j++] = '-';
	}

	VMR_INFO(vmr, "Interface uuid %s", str);

	uuid_parse(str, &vmr->intf_uuid);

	return ret;
}

static int vmr_download_apu_bin(struct vmr_drvdata *vmr, char *buf, size_t len)
{
	return vmr_transfer_data_impl(vmr, buf, len, XGQ_CMD_OP_LOAD_APUBIN);
}

static void vmr_cq_result_copy(struct vmr_drvdata *vmr, struct vmr_cmd *cmd)
{
	struct xgq_cmd_cq_default_payload *payload =
		(struct xgq_cmd_cq_default_payload *)&cmd->xgq_cmd_cq_payload;

	mutex_lock(&vmr->xgq_lock);
	memcpy(&vmr->xgq_cq_payload, payload, sizeof(*payload));
	mutex_unlock(&vmr->xgq_lock);
}

static int vmr_control_payload_update(struct vmr_drvdata *vmr, struct vmr_cmd *cmd,
				      enum xgq_cmd_vmr_control_type req_type)
{
	struct xgq_cmd_vmr_control_payload *payload = NULL;
	struct xgq_cmd_sq_hdr *hdr = NULL;

	/* update payload content */
	payload = &cmd->xgq_cmd_entry.vmr_control_payload;
	payload->req_type = req_type;
	payload->debug_level = vmr->xgq_vmr_debug_level;

	/* update payload size in hdr */
	hdr = &cmd->xgq_cmd_entry.hdr;
	hdr->count = sizeof(*payload);

	return 0;
}

static int vmr_control_op(struct vmr_drvdata *vmr, enum xgq_cmd_vmr_control_type req_type)
{
	struct vmr_cmd *cmd = NULL;
	int id = -1;
	int ret = 0;

	ret = vmr_create_cmd(vmr, XGQ_CMD_OP_VMR_CONTROL, &cmd, &id, XGQ_CONFIG_TIME);
	if (ret)
		return ret;

	vmr_control_payload_update(vmr, cmd, req_type);

	ret = vmr_submit_cmd(vmr, cmd);
	if (ret) {
		VMR_ERR(vmr, "submit cmd failed, cid %d", id);
		goto done;
	}

	/* wait for command completion */
	if (wait_for_completion_killable(&cmd->xgq_cmd_complete)) {
		VMR_ERR(vmr, "submitted cmd killed");
		vmr_submitted_cmd_remove(vmr, cmd);
	}

	ret = cmd->xgq_cmd_rcode;

	if (ret)
		VMR_ERR(vmr, "Multiboot or reset might not work. ret %d", ret);
	else if (req_type == XGQ_CMD_VMR_QUERY)
		vmr_cq_result_copy(vmr, cmd);

done:
	vmr_remove_cmd(vmr, cmd, id);
	return ret;
}

static int vmr_status_query(struct vmr_drvdata *vmr)
{
	return vmr_control_op(vmr, XGQ_CMD_VMR_QUERY);
}

static int vmgmt_vmr_debug_level_buf_get(struct vmr_drvdata *vmr, char **buf, u32 *len)
{
	*len = 10;
	*buf = vmalloc(*len);
	if (!(*buf))
		return -ENOMEM;

	snprintf(*buf, *len, "%d\n", vmr->xgq_vmr_debug_level);

	return 0;
}

static int vmgmt_vmr_log_buf_get(struct vmr_drvdata *vmr, char **buf, u32 *len)
{
	return -EINVAL;
}

int vmgmt_log_buf_get(struct vmr_drvdata *vmr, enum log_type lt, char **buf, u32 *len)
{
	if (lt == LT_VMR_DBG_LEVEL)
		return vmgmt_vmr_debug_level_buf_get(vmr, buf, len);
	else if (lt == LT_VMR_LOG)
		return vmgmt_vmr_log_buf_get(vmr, buf, len);
	else
		return -EINVAL;
}

int vmgmt_log_val_set(struct vmr_drvdata *vmr, enum log_type lt, u32 val)
{
	if (lt != LT_VMR_DBG_LEVEL)
		return -EINVAL;

	mutex_lock(&vmr->xgq_lock);
	vmr->xgq_vmr_debug_level = val;
	mutex_unlock(&vmr->xgq_lock);

	return vmr_status_query(vmr);
}

static bool vmr_check_apu_is_ready(struct vmr_drvdata *vmr)
{
	struct xgq_cmd_cq_vmr_payload *vmr_status =
		(struct xgq_cmd_cq_vmr_payload *)&vmr->xgq_cq_payload;

	if (vmr_status_query(vmr))
		return false;

	return vmr_status->ps_is_ready ? true : false;
}

static int vmr_wait_apu_is_ready(struct vmr_drvdata *vmr)
{
	bool is_ready = false;
	int i;

	for (i = 0; i < MAX_WAIT; i++) {
		is_ready = vmr_check_apu_is_ready(vmr);
		if (is_ready)
			break;

		msleep(XGQ_MSLEEP_1S);
	}

	VMR_INFO(vmr, "wait %d seconds for PS ready", i);
	return is_ready ? 0 : -ETIME;
}

static int vmr_download_apu_firmware(struct vmr_drvdata *vmr)
{
	const struct firmware *fw = NULL;
	char *apu_bin = "xilinx/xrt-versal-apu.xsabin";
	char *buf;
	size_t buf_len;
	int ret = 0;

	/*TODO: check apu is ready */
	if (vmr_check_apu_is_ready(vmr)) {
		VMR_INFO(vmr, "apu is ready, skip download");
		return ret;
	}
	ret = request_firmware(&fw, apu_bin, &vmr->pdev->dev);
	if (ret) {
		VMR_WARN(vmr, "request fw %s failed %d", apu_bin, ret);
		return ret;
	}

	buf = vmalloc(fw->size);
	if (!buf) {
		VMR_ERR(vmr, "no memory");
		release_firmware(fw);
		return -ENOMEM;
	}
	memcpy(buf, fw->data, fw->size);
	buf_len = fw->size;
	release_firmware(fw);

	ret = vmr_download_apu_bin(vmr, buf, buf_len);
	vfree(buf);
	if (ret)
		return ret;

	VMR_INFO(vmr, "start waiting for APU becomes ready");
	return vmr_wait_apu_is_ready(vmr);
}

static inline bool vmr_xgq_device_is_ready(struct vmr_drvdata *vmr)
{
	u32 rval;
	int i, retry = 100, interval = 100;

	for (i = 0; i < retry; i++) {
		msleep(interval);

		memcpy_fromio(&vmr->xgq_vmr_shared_mem, vmr->xgq_payload_base,
			      sizeof(vmr->xgq_vmr_shared_mem));
		if (vmr->xgq_vmr_shared_mem.vmr_magic_no == VMR_MAGIC_NO) {
			rval = ioread32(vmr->xgq_payload_base +
					vmr->xgq_vmr_shared_mem.vmr_status_off);
			if (rval) {
				VMR_INFO(vmr, "ready rval %u", rval);
				return true;
			}
		}
	}

	VMR_ERR(vmr, "not ready after %d ms", interval * retry);
	return false;
}

static int vmr_start_services(struct vmr_drvdata *vmr)
{
	u64 flags = 0;
	int ret;

	if (!vmr_xgq_device_is_ready(vmr))
		return -ENODEV;

	vmr->xgq_ring_base = vmr->xgq_payload_base +
				vmr->xgq_vmr_shared_mem.ring_buffer_off;

	ret = xgq_attach(&vmr->xgq_queue, flags, 0, (u64)vmr->xgq_ring_base,
			 (u64)vmr->xgq_sq_base, (u64)vmr->xgq_cq_base);
	if (ret) {
		VMR_ERR(vmr, "xgq_attach failed: %d, reset device please", ret);
		return -ENODEV;
	}

	mutex_lock(&vmr->xgq_lock);
	vmr->xgq_halted = false;
	mutex_unlock(&vmr->xgq_lock);

	VMR_INFO(vmr, "succeeded");
	return ret;
}

static void vmr_stop_services(struct vmr_drvdata *vmr)
{
	VMR_INFO(vmr, "stopping vmr services");

	mutex_lock(&vmr->xgq_lock);
	vmr->xgq_halted = true;
	mutex_unlock(&vmr->xgq_lock);

	while (vmr_submitted_cmds_empty(vmr) != true) {
		msleep(XGQ_MSLEEP_1S);
		vmr_submitted_cmds_drain(vmr);
	}

	VMR_INFO(vmr, "vmr services are stopped");
}

static void vmr_offline_services(struct vmr_drvdata *vmr)
{
	VMR_INFO(vmr, "vmr service are going offline...");

	/*
	 *	if (!vmr->xgq_halted)
	 *		vmr_log_dump_all(vmr);
	 */
	vmr_stop_services(vmr);

	VMR_INFO(vmr, "vmr services are offline");
}

static int vmr_services_probe(struct vmr_drvdata *vmr)
{
	int ret;

	/*
	 * First check vmr firmware version is compatible.
	 */
	ret = vmr_identify_op(vmr);
	if (ret) {
		VMR_WARN(vmr, "Unsupported firmware version, only basic operations allowed");
		vmr_stop_services(vmr);
		return 0;
	}

	ret = vmr_get_intf_uuid(vmr);
	if (ret)
		VMR_ERR(vmr, "Failed to get interface uuid");

	/* try to download APU firmware, user can check APU status later */
	ret = vmr_download_apu_firmware(vmr);
	if (ret)
		VMR_WARN(vmr, "unable to download APU, ret:%d", ret);

	return 0;
}

u32 comms_chan_get_xclbin_uuid(struct vmr_drvdata *vmr, void *payload)
{
	struct comms_srv_uuid_resp *resp = (struct comms_srv_uuid_resp *)payload;

	uuid_copy(&resp->uuid, &vmr->xclbin_uuid);

	return sizeof(*resp);
}

u32 comms_chan_get_protocol_version(void *payload)
{
	struct comms_srv_ver_resp *resp = (struct comms_srv_ver_resp *)payload;

	resp->version = COMMS_CHAN_PROTOCOL_VERSION;

	return sizeof(*resp);
}

#define PL_TO_PMC_ERROR_SIGNAL_PATH_MASK        BIT(0)

static int enable_vmr_boot(struct vmr_drvdata *vmr)
{
	u32 val;

	/* refer to xocl_enable_vmr_boot */
	/* TODO: skip set default boot for now, need to add new opcode */

	/* set reset signal */
	val = ioread32(vmr->xgq_pmc_mux_base);
	val |= PL_TO_PMC_ERROR_SIGNAL_PATH_MASK;
	iowrite32(val, vmr->xgq_pmc_mux_base);

	VMR_INFO(vmr, "mux control is 0x%x", ioread32(vmr->xgq_pmc_mux_base));

	return 0;
}

static void vmgmt_hot_reset(struct vmr_drvdata *vmr)
{
	VMR_WARN(vmr, "start hot_reset");
	enable_vmr_boot(vmr);
	vmr_stop_services(vmr);
	vmgmt_reset_pci(vmr->pdev);
	vmr_start_services(vmr);
	VMR_WARN(vmr, "done hot_reset");
}

void comms_chan_send_response(struct comms_chan *comms, struct comms_msg *msg)
{
	struct pci_dev *pdev = comms->vmr->pdev;
	struct comms_srv_req *req = (struct comms_srv_req *)msg->data;
	struct comms_hw_msg response = {0};
	u32 size;
	u8 i;

	switch (req->opcode) {
	case COMMS_REQ_OPS_GET_PROTOCOL_VERSION:
		size = comms_chan_get_protocol_version(response.body.payload);
		break;
	case COMMS_REQ_OPS_GET_XCLBIN_UUID:
		size = comms_chan_get_xclbin_uuid(comms->vmr, response.body.payload);
		break;
	case COMMS_REQ_OPS_HOT_RESET:
		// enable_vmr_boot
		// offline vmr_services
		// xclmgmt_reset_pci
		VMR_WARN(comms->vmr, "Trying to reset card in slot %s:%02x:%x",
			 pdev->bus->name, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

		vmgmt_hot_reset(comms->vmr);

		*response.body.payload = 0;
		size = sizeof(int);
		break;
	default:
		VMR_ERR(comms->vmr, "Unsupported request opcode: %d",
			req->opcode);
		*response.body.payload = -1;
		size = sizeof(int);
	}

	VMR_INFO(comms->vmr, "response opcode:%d", req->opcode);

	response.header.type = COMMS_MSG_START | COMMS_MSG_END;
	response.header.payload_size = size;

	response.body.id = msg->id;
	response.body.flags = COMMS_MSG_SRV_RESPONSE;
	response.body.payload_size = size;

	for (i = 0; i < COMMS_DATA_LEN; i++) {
		iowrite32(((u32 *)&response)[i], comms->vmr->comms_chan_base +
			  COMMS_REG_WRDATA_OFF);
	}
}

void comms_chan_check_request(struct work_struct *w)
{
	struct comms_chan *comms = container_of(w, struct comms_chan, work);
	u32 status = 0, request[COMMS_DATA_LEN] = {0};
	struct comms_hw_msg *hw_msg;
	struct comms_msg msg;
	u8 i, type, eom;

	mutex_lock(&comms->lock);

	status = ioread32(comms->vmr->comms_chan_base + COMMS_REG_IS_OFF);
	if (!(status & BIT(1)))
		goto exit;

	/* ACK status */
	iowrite32(status, comms->vmr->comms_chan_base + COMMS_REG_IS_OFF);

	for (i = 0; i < COMMS_DATA_LEN; i++) {
		request[i] = ioread32(comms->vmr->comms_chan_base +
				      COMMS_REG_RDDATA_OFF);
	}

	hw_msg = (struct comms_hw_msg *)request;
	type = FIELD_GET(COMMS_DATA_TYPE_MASK, hw_msg->header.type);
	eom = FIELD_GET(COMMS_DATA_EOM_MASK, hw_msg->header.type);

	/* Only support fixed size 64B messages */
	if (!eom || type != COMMS_MSG_START) {
		VMR_ERR(comms->vmr, "Unsupported message format or length");
		goto exit;
	}

	msg.flags = hw_msg->body.flags;
	msg.len = hw_msg->body.payload_size;
	msg.id = hw_msg->body.id;

	if (msg.flags != COMMS_MSG_SRV_REQUEST) {
		VMR_ERR(comms->vmr, "Unsupported service request");
		goto exit;
	}

	memcpy(msg.data, hw_msg->body.payload, hw_msg->body.payload_size);

	/* Now decode and respond appropriately */
	comms_chan_send_response(comms, &msg);

exit:
	mutex_unlock(&comms->lock);
}

void comms_chan_sched_work(struct timer_list *t)
{
	struct comms_chan *comms = container_of(t, struct comms_chan, timer);

	/* schedule a work in the general workqueue */
	schedule_work(&comms->work);

	/* Periodic timer */
	mod_timer(&comms->timer, jiffies + COMMS_CHAN_TIMER);
}

static void comms_chan_finish(struct vmr_drvdata *vmr)
{
	struct comms_chan *comms = &vmr->comms;

	/* First stop scheduling new work then cancel work */
	del_timer_sync(&comms->timer);
	cancel_work_sync(&comms->work);
	mutex_destroy(&comms->lock);
}

static int comms_chan_init(struct vmr_drvdata *vmr)
{
	struct comms_chan *comms = &vmr->comms;

	mutex_init(&comms->lock);

	mutex_lock(&comms->lock);

	/* Clear request and response FIFOs */
	iowrite32(0x3, vmr->comms_chan_base + COMMS_REG_CTRL_OFF);

	/* Disable interrupts */
	iowrite32(0, vmr->comms_chan_base + COMMS_REG_IE_OFF);

	/* Clear interrupts */
	iowrite32(7, vmr->comms_chan_base + COMMS_REG_IS_OFF);

	/* Setup RIT reg */
	iowrite32(15, vmr->comms_chan_base + COMMS_REG_RIT_OFF);

	/* Enable RIT interrupt */
	iowrite32(2, vmr->comms_chan_base + COMMS_REG_IE_OFF);

	mutex_unlock(&comms->lock);

	/* Create and schedule timer to do recurring work */
	timer_setup(&comms->timer, comms_chan_sched_work, 0);

	mod_timer(&comms->timer, jiffies + COMMS_CHAN_TIMER);

	INIT_WORK(&comms->work, comms_chan_check_request);

	return 0;
}

static int vmr_char_open(struct inode *inode, struct file *filep)
{
	struct vmr_char *vmr_char = container_of(inode->i_cdev,
						 struct vmr_char, cdev);
	struct vmr_drvdata *vmr = vmr_char->vmr;

	if (!vmr) {
		pr_err("vmr device not found\n");
		return -ENXIO;
	}
	VMR_DBG(vmr, "vmr char device found");
	filep->private_data = vmr;

	return 0;
}

static int vmr_char_close(struct inode *inode, struct file *filep)
{
	filep->private_data = NULL;
	return 0;
}

struct vmr_region_match_arg {
	struct vmr_drvdata *vmr;
	uuid_t *uuid;
	bool skip;
};

static int vmr_region_match(struct device *dev, const void *data)
{
	const struct vmr_region_match_arg *arg = data;
	const struct fpga_region *match_region;
	struct vmr_drvdata *vmr = arg->vmr;
	uuid_t compat_uuid;

	if (dev->parent != &arg->vmr->pdev->dev)
		return false;

	match_region = to_fpga_region(dev);

	import_uuid(&compat_uuid, (const char *)match_region->compat_id);
	if (arg->skip || uuid_equal(&compat_uuid, arg->uuid)) {
		VMR_INFO(vmr, "Region match found");
		return true;
	}

	VMR_INFO(vmr, "Region match failed");
	return false;
}

static int vmr_region_program(struct fpga_region *region, const void *xclbin)
{
	const struct axlf *xclbin_obj = xclbin;
	struct vmr_drvdata *vmr = region->priv;
	struct fpga_image_info *info;
	int ret;

	info = fpga_image_info_alloc(&vmr->pdev->dev);
	if (!info) {
		VMR_ERR(vmr, "Failed to alloc fpga image info: %d", ret);
		return -ENOMEM;
	}

	info->buf = xclbin;
	info->count = xclbin_obj->header.length;
	info->flags |= FPGA_MGR_PARTIAL_RECONFIG;
	region->info = info;
	ret = fpga_region_program_fpga(region);
	if (ret) {
		VMR_ERR(vmr, "Programming xclbin failed: %d", ret);
		goto exit;
	}

	/* free bridges to allow reprogram */
	if (region->get_bridges)
		fpga_bridges_put(&region->bridge_list);

exit:
	fpga_image_info_free(info);
	return ret;
}

static long vmr_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct vmr_drvdata *vmr = (struct vmr_drvdata *)filep->private_data;
	struct versal_mgmt_ioc_xclbin ioc_obj = { 0 };
	struct axlf xclbin = { 0 };
	void *copy_buffer = NULL;
	size_t copy_buffer_size = 0;
	struct fpga_region *region = NULL;
	struct vmr_region_match_arg reg = { 0 };
	int ret = 0;

	ret = copy_from_user((void *)&ioc_obj, (void *)arg, sizeof(ioc_obj));
	if (ret) {
		VMR_ERR(vmr, "copy ioc_obj failed: %d\n", ret);
		return ret;
	}

	ret = copy_from_user((void *)&xclbin, ioc_obj.xclbin, sizeof(xclbin));
	if (ret) {
		VMR_ERR(vmr, "copy xclbin failed: %d\n", ret);
		return ret;
	}
	if (memcmp(xclbin.magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2)))
		return -EINVAL;

	copy_buffer_size = (size_t)xclbin.header.length;

	/* xclbin should never be over 1G and less than size of struct axlf */
	if (copy_buffer_size < sizeof(xclbin) || copy_buffer_size > 1024 * 1024 * 1024)
		return -EINVAL;

	copy_buffer = vmalloc(copy_buffer_size);
	if (!copy_buffer)
		return -ENOMEM;
	ret = copy_from_user((void *)copy_buffer, ioc_obj.xclbin, copy_buffer_size);
	if (ret) {
		vfree(copy_buffer);
		return -EFAULT;
	}

	switch (cmd) {
	case VERSAL_MGMT_LOAD_XCLBIN_IOCTL:
		vmr->fw_tnx.opcode = XGQ_CMD_OP_LOAD_XCLBIN;
		reg.skip = false;
		break;
	case VERSAL_MGMT_PROGRAM_SHELL_IOCTL:
		vmr->fw_tnx.opcode = XGQ_CMD_OP_DOWNLOAD_PDI;
		reg.skip = true;
		break;
	default:
		VMR_ERR(vmr, "Invalid IOCTL command: %d", cmd);
		return -EINVAL;
	}

	reg.uuid = &xclbin.header.rom_uuid;
	reg.vmr = vmr;

	region = fpga_region_class_find(NULL, &reg, vmr_region_match);
	if (!region) {
		VMR_ERR(vmr, "Failed to find compatible region");
		ret = -ENOENT;
		goto exit;
	}

	ret = vmr_region_program(region, copy_buffer);
	if (ret) {
		VMR_ERR(vmr, "Failed to program region");
		goto exit;
	}

	VMR_INFO(vmr, "Downloaded firmware %pUb of size %zu bytes",
		 &xclbin.header.uuid, copy_buffer_size);
	uuid_copy(&vmr->xclbin_uuid, &xclbin.header.uuid);
exit:
	vfree(copy_buffer);
	return ret;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = vmr_char_open,
	.release = vmr_char_close,
	.unlocked_ioctl = vmr_ioctl,
};

static void vmr_char_destroy(struct vmr_drvdata *vmr)
{
	struct vmr_char *vmr_char = &vmr->char_dev;

	device_destroy(vmgmt_class, vmr_char->cdev.dev);
	cdev_del(&vmr_char->cdev);
	ida_free(&vmgmt_dev_minor_ida, vmr_char->minor);
}

static int vmr_char_create(struct vmr_drvdata *vmr)
{
	struct vmr_char *vmr_char = &vmr->char_dev;
	u32 devid;
	int ret;

	vmr_char->minor = ida_alloc_max(&vmgmt_dev_minor_ida, MAX_DEVICES,
					GFP_KERNEL);
	if (vmr_char->minor < 0) {
		VMR_ERR(vmr, "Failed to allocate device minor ID");
		return vmr_char->minor;
	}

	cdev_init(&vmr_char->cdev, &fops);
	vmr_char->cdev.owner = THIS_MODULE;
	vmr_char->cdev.dev = MKDEV(MAJOR(vmgmt_devnode), vmr_char->minor);

	ret = cdev_add(&vmr_char->cdev, vmr_char->cdev.dev, 1);
	if (ret) {
		VMR_ERR(vmr, "Failed to add char device: %d\n", ret);
		return -ENODEV;
	}

	devid = PCI_DEVID(vmr->pdev->bus->number, vmr->pdev->devfn);
	vmr_char->sys_device = device_create(vmgmt_class, &vmr->pdev->dev,
					     vmr_char->cdev.dev, NULL, "%s%x",
					     DRV_NAME, devid);
	if (IS_ERR(vmr_char->sys_device)) {
		VMR_ERR(vmr, "Failed to create char device: %ld\n",
			PTR_ERR(vmr_char->sys_device));
		cdev_del(&vmr_char->cdev);
		return PTR_ERR(vmr_char->sys_device);
	}

	vmr_char->vmr = vmr;

	return ret;
}

static int versal_fpga_write_init(struct fpga_manager *mgr,
				  struct fpga_image_info *info, const char *buf,
				  size_t count)
{
	struct vmr_drvdata *vmr = mgr->priv;
	struct vmr_fw_tnx *tnx = &vmr->fw_tnx;
	int ret;

	ret = vmr_create_cmd(vmr, tnx->opcode, &tnx->cmd, &tnx->id,
			     XGQ_DOWNLOAD_TIME);
	if (ret) {
		vmr->state = FPGA_MGR_STATE_WRITE_INIT_ERR;
		return ret;
	}

	vmr->state = FPGA_MGR_STATE_WRITE_INIT;
	return ret;
}

static int versal_fpga_write(struct fpga_manager *mgr, const char *buf,
			     size_t count)
{
	struct vmr_drvdata *vmr = mgr->priv;
	u64 priv = 0;
	int ret;

	ret = vmr_data_payload_init(vmr, vmr->fw_tnx.cmd, vmr->fw_tnx.opcode,
				    buf, count, priv);
	if (ret) {
		vmr->state = FPGA_MGR_STATE_WRITE_ERR;
		vmr_remove_cmd(vmr, vmr->fw_tnx.cmd, vmr->fw_tnx.id);
		return ret;
	}

	vmr->state = FPGA_MGR_STATE_WRITE;
	return 0;
}

static int versal_fpga_write_complete(struct fpga_manager *mgr,
				      struct fpga_image_info *info)
{
	struct vmr_drvdata *vmr = mgr->priv;
	int ret;

	ret = vmr_submit_cmd(vmr, vmr->fw_tnx.cmd);
	if (ret) {
		vmr->state = FPGA_MGR_STATE_WRITE_COMPLETE_ERR;
		VMR_ERR(vmr, "submit cmd failed, cid %d", vmr->fw_tnx.id);
		goto done;
	}

	ret = vmr_wait_not_killable(vmr->fw_tnx.cmd);
	if (!ret) {
		VMR_ERR(vmr, "Image download timed out");
		ret = -ETIMEDOUT;
		vmr->state = FPGA_MGR_STATE_WRITE_COMPLETE_ERR;
		goto done;
	} else {
		ret = 0;
	}

	vmr->state = FPGA_MGR_STATE_WRITE_COMPLETE;
done:
	vmr_data_payload_fini(vmr);
	vmr_remove_cmd(vmr, vmr->fw_tnx.cmd, vmr->fw_tnx.id);
	memset(&vmr->fw_tnx, 0, sizeof(vmr->fw_tnx));
	return ret;
}

static enum fpga_mgr_states versal_fpga_state(struct fpga_manager *mgr)
{
	struct vmr_drvdata *vmr = mgr->priv;

	return vmr->state;
}

static const struct fpga_manager_ops versal_fpga_ops = {
	.write_init = versal_fpga_write_init,
	.write = versal_fpga_write,
	.write_complete = versal_fpga_write_complete,
	.state = versal_fpga_state,
};

static void versal_mgmt_remove(struct pci_dev *pdev)
{
	struct vmr_drvdata *vmr = pci_get_drvdata(pdev);

	vmgmt_debugfs_fini(vmr->debugfs_root);

	if (vmr->bridge)
		fpga_bridge_unregister(vmr->bridge);
	if (vmr->region)
		fpga_region_unregister(vmr->region);

	comms_chan_finish(vmr);
	vmr_char_destroy(vmr);
	vmr_stop_services(vmr);
	fini_worker(&vmr->xgq_complete_worker);
	fini_worker(&vmr->xgq_health_worker);
	idr_destroy(&vmr->xgq_vmr_cid_idr);

	/* TODO: iounmap bars? */

	mutex_destroy(&vmr->xgq_lock);

	dev_info(&pdev->dev, "%s removed.\n", __func__);
}

static struct fpga_bridge_ops vmr_br_ops;

static struct fpga_bridge *vmr_create_bridge(struct vmr_drvdata *vmr)
{
	return fpga_bridge_register(&vmr->pdev->dev, "vmgmt_base_br",
				    &vmr_br_ops, vmr);
}

static int vmr_get_bridges(struct fpga_region *region)
{
	struct vmr_drvdata *vmr = region->priv;
	struct device *dev = &vmr->pdev->dev;

	return fpga_bridge_get_to_list(dev, region->info, &region->bridge_list);
}

static int versal_mgmt_probe(struct pci_dev *pdev,
			     const struct pci_device_id *pdev_id)
{
	struct vmr_drvdata *vmr;
	struct fpga_region_info region;
	void __iomem * const *tbl;
	int bar_mask;
	int ret;

	vmr = devm_kzalloc(&pdev->dev, sizeof(*vmr), GFP_KERNEL);
	if (!vmr)
		return -ENOMEM;

	vmr->pdev = pdev;
	vmr->xgq_halted = true;
	vmr->xgq_vmr_debug_level = 2;
	mutex_init(&vmr->xgq_lock);
	sema_init(&vmr->xgq_data_sema, 1);
	sema_init(&vmr->xgq_log_page_sema, 1);

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable device %d.", ret);
		return ret;
	}

	/*TODO: cleanup iomap bars, using regular ioremap and ioremap_wc for
	 * shared memory buffer to get better performance
	 */
	bar_mask = pci_select_bars(pdev, IORESOURCE_MEM);
	ret = pcim_iomap_regions(pdev, bar_mask, "versal-mgmt");
	if (ret) {
		VMR_ERR(vmr, "map regions failed: %d", ret);
		return ret;
	}

	tbl = pcim_iomap_table(pdev);
	if (!tbl) {
		VMR_ERR(vmr, "create iomap table failed.");
		return -ENOMEM;
	}

	vmr->comms_chan_base = tbl[COMMS_CHAN_BAR] + COMMS_CHAN_BAR_OFF;
	vmr->xgq_pmc_mux_base = tbl[XGQ_VMR_PMC_BAR] + XGQ_VMR_PMC_BAR_OFF;
	vmr->xgq_payload_base = tbl[XGQ_VMR_PAYLOAD_BAR] + XGQ_VMR_PAYLOAD_OFF;

	vmr->xgq_sq_base = tbl[XGQ_VMR_SQ_BAR] + XGQ_VMR_SQ_BAR_OFF;
	vmr->xgq_sq_base = vmr->xgq_sq_base + XGQ_SQ_TAIL_POINTER;
	vmr->xgq_cq_base = vmr->xgq_sq_base + XGQ_CQ_TAIL_POINTER;

	ret = vmr_start_services(vmr);
	if (ret)
		return ret;

	idr_init(&vmr->xgq_vmr_cid_idr);
	INIT_LIST_HEAD(&vmr->xgq_submitted_cmds);

	vmr->xgq_complete_worker.xgq_vmr = vmr;
	vmr->xgq_health_worker.xgq_vmr = vmr;
	init_complete_worker(&vmr->xgq_complete_worker);
	init_health_worker(&vmr->xgq_health_worker);

	(void)vmr_services_probe(vmr);
	pci_set_drvdata(pdev, vmr);

	ret = vmr_char_create(vmr);
	if (ret) {
		VMR_ERR(vmr, "char create failed: %d", ret);
		goto char_create_failed;
	}

	vmr->comms.vmr = vmr;
	ret = comms_chan_init(vmr);
	if (ret) {
		VMR_ERR(vmr, "comms chan create failed: %d", ret);
		goto comms_chan_failed;
	}

	/* register fpga manager */
	vmr->mgr = devm_fpga_mgr_register(&pdev->dev, "AMD Versal FPGA Manager",
					  &versal_fpga_ops, vmr);
	if (IS_ERR(vmr->mgr)) {
		ret = PTR_ERR(vmr->mgr);
		goto fpga_mgr_failed;
	}

	/* create fgpa bridge, region for the base shell */
	vmr->bridge = vmr_create_bridge(vmr);
	if (IS_ERR(vmr->bridge)) {
		VMR_ERR(vmr, "Failed to register FPGA bridge for base shell: %ld",
			PTR_ERR(vmr->bridge));
		ret = PTR_ERR(vmr->bridge);
		vmr->bridge = NULL;
		goto fpga_mgr_failed;
	}

	region.mgr = vmr->mgr;
	region.compat_id = (struct fpga_compat_id *)&vmr->intf_uuid;
	region.get_bridges = vmr_get_bridges;
	region.priv = vmr;

	vmr->region = fpga_region_register_full(&pdev->dev, &region);
	if (IS_ERR(vmr->region)) {
		VMR_ERR(vmr, "Failed to register FPGA region for base shell: %ld",
			PTR_ERR(vmr->region));
		ret = PTR_ERR(vmr->region);
		vmr->region = NULL;
		goto fpga_region_failed;
	}

	vmr->debugfs_root =
		vmgmt_debugfs_init(vmr, dev_name(vmr->char_dev.sys_device));

	VMR_INFO(vmr, "succeeded");
	return 0;

fpga_region_failed:
	fpga_bridge_unregister(vmr->bridge);

fpga_mgr_failed:
	comms_chan_finish(vmr);

comms_chan_failed:
	vmr_char_destroy(vmr);

char_create_failed:
	vmr_stop_services(vmr);
	fini_worker(&vmr->xgq_complete_worker);
	idr_destroy(&vmr->xgq_vmr_cid_idr);
	mutex_destroy(&vmr->xgq_lock);

	return ret;
}

static struct pci_driver versal_mgmt_driver = {
	.name = DRV_NAME,
	.id_table = versal_mgmt_id_tbl,
	.probe = versal_mgmt_probe,
	.remove = versal_mgmt_remove,
};

static int __init versal_mgmt_init(void)
{
	int ret;

	pr_info(" init()\n");

	vmgmt_class = class_create(CLASS_NAME);
	if (IS_ERR(vmgmt_class))
		return PTR_ERR(vmgmt_class);

	ret = alloc_chrdev_region(&vmgmt_devnode, 0, MAX_DEVICES, DRV_NAME);
	if (ret)
		goto alloc_err;

	ret = pci_register_driver(&versal_mgmt_driver);
	if (ret)
		goto reg_err;

	return 0;

reg_err:
	unregister_chrdev_region(vmgmt_devnode, MAX_DEVICES);
alloc_err:
	pr_info(DRV_NAME " init() err\n");
	class_destroy(vmgmt_class);
	return ret;
}

static void versal_mgmt_exit(void)
{
	pr_info(DRV_NAME " exit()\n");
	pci_unregister_driver(&versal_mgmt_driver);
	unregister_chrdev_region(vmgmt_devnode, MAX_DEVICES);
	class_destroy(vmgmt_class);
}

module_init(versal_mgmt_init);
module_exit(versal_mgmt_exit);

MODULE_DESCRIPTION("Versal Management PCIe Device Driver");
MODULE_AUTHOR("AMD Corporation");
MODULE_LICENSE("GPL v2");
