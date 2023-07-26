// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Versal PCIe device
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 *
 * Authors:
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/miscdevice.h>

#include "xgq_cmd_vmr.h"
#include "xgq_xocl_plat.h"
#include "xclbin.h"

#define DRV_VERSION		"0.1"
#define DRV_NAME		"versal-mgmt"
#define PCIE_DEVICE_ID_PF_V70	0x5094

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
#define VMR_LOG_PAGE_SIZE	(1024 * 1024)
#define VMR_LOG_PAGE_NUM	1
#define VMR_LOG_ADDR_OFF	0x0
#define VMR_DATA_ADDR_OFF	(VMR_LOG_PAGE_SIZE * VMR_LOG_PAGE_NUM)

#define VMR_INFO(vmr, fmt, args...)  dev_info(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_WARN(vmr, fmt, args...)  dev_warn(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_ERR(vmr, fmt, args...)   dev_err(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)
#define VMR_DBG(vmr, fmt, args...)   dev_dbg(&(vmr)->pdev->dev, "%s: "fmt, __func__, ##args)

#define ICAP_XCLBIN_V2          "xclbin2"

struct versal_mgmt_ioc_xclbin {
	char *xclbin;
};

#define VERSAL_MGMT_XCLBIN_IOCTL _IOW('k', 0, struct versl_mgmt_ioc_xclbin)

struct vmr_drvdata;

static dev_t devt_major;
struct class *dev_class;

struct vmr_char {
	struct vmr_drvdata *vmr;
	struct cdev cdev;
	struct device *cdev_device;
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
	struct mutex		lock;
	struct timer_list	timer;
	struct work_struct	work;
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
	struct mutex		xgq_lock; /* for exclusive reference to xgq command data */
	struct idr		xgq_vmr_cid_idr;
	struct vmr_shared_mem	xgq_vmr_shared_mem;
	struct list_head	xgq_submitted_cmds;
	struct xgq_worker	xgq_complete_worker;
	bool			xgq_halted;
	struct semaphore	xgq_data_sema;
	struct semaphore	xgq_log_page_sema;
	struct xgq_cmd_cq_default_payload xgq_cq_payload;
	bool			xgq_vmr_program;
	void __iomem		*comms_chan_base;
	struct comms_chan	comms;
};

static const struct pci_device_id versal_mgmt_id_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, PCIE_DEVICE_ID_PF_V70),},
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

static int init_complete_worker(struct xgq_worker *xw)
{
	xw->complete_thread =
		kthread_run(complete_worker, (void *)xw, "complete worker");

	if (IS_ERR(xw->complete_thread))
		return PTR_ERR(xw->complete_thread);

	return 0;
}

static int fini_worker(struct xgq_worker *xw)
{
	return kthread_stop(xw->complete_thread);
};

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
	payload->flash_type = XGQ_CMD_FLASH_DEFAULT;
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

	/*
	 * For pdi/xclbin data transfer, we block any cancellation and
	 * wait till command completed and then release resources safely.
	 * We call cond_resched after every timeout to avoid linux kernel
	 * warning for thread hanging too long.
	 */
	while (!wait_for_completion_timeout(&cmd->xgq_cmd_complete, XGQ_WAIT_TIMEOUT))
		cond_resched();

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

static int vmr_download_xclbin(struct vmr_drvdata *vmr, char *buf, size_t len)
{
	return vmr_transfer_data_impl(vmr, buf, len, XGQ_CMD_OP_LOAD_XCLBIN);
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

static int vmr_control_op(struct vmr_drvdata *vmr, enum xgq_cmd_vmr_control_type req_type)
{
	struct vmr_cmd *cmd = NULL;
	int id = -1;
	int ret = 0;

	ret = vmr_create_cmd(vmr, XGQ_CMD_OP_VMR_CONTROL, &cmd, &id, XGQ_CONFIG_TIME);
	if (ret)
		return ret;

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
			if (rval)
				return true;
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

	/* try to download APU firmware, user can check APU status later */
	ret = vmr_download_apu_firmware(vmr);
	if (ret)
		VMR_WARN(vmr, "unable to download APU, ret:%d", ret);

	return 0;
}

u32 comms_chan_get_xclbin_uuid(void *payload)
{
	struct comms_srv_uuid_resp *resp = (struct comms_srv_uuid_resp *)payload;

	/* UUID of verify.xclbin */
	resp->uuid = UUID_INIT(0xe35795bd, 0x5b08, 0x78d4, 0x4d, 0xc4, 0xdb,
			       0x18, 0x81, 0x15, 0x9e, 0xc2);

	return sizeof(*resp);
}


u32 comms_chan_get_protocol_version(void *payload)
{
	struct comms_srv_ver_resp *resp = (struct comms_srv_ver_resp *)payload;

	resp->version = COMMS_CHAN_PROTOCOL_VERSION;

	return sizeof(*resp);
}

void comms_chan_send_response(struct comms_chan *comms, struct comms_msg *msg)
{
	struct comms_srv_req *req = (struct comms_srv_req *)msg->data;
	struct comms_hw_msg response = {0};
	u32 size;
	u8 i;

	switch (req->opcode) {
	case COMMS_REQ_OPS_GET_PROTOCOL_VERSION:
		size = comms_chan_get_protocol_version(response.body.payload);
		break;
	case COMMS_REQ_OPS_GET_XCLBIN_UUID:
		size = comms_chan_get_xclbin_uuid(response.body.payload);
		break;
	default:
		VMR_ERR(comms->vmr, "Unsupported request opcode: %d",
			req->opcode);
		*response.body.payload = -1;
		size = sizeof(int);
	}

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
	return;
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

	/* Disble interrupts */
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
	struct cdev *icdev = inode->i_cdev;
	struct vmr_char *vmr_char = container_of(icdev, struct vmr_char, cdev);
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

static long vmr_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct vmr_drvdata *vmr = (struct vmr_drvdata *)filep->private_data;
	struct versal_mgmt_ioc_xclbin ioc_obj = { 0 };
	struct axlf xclbin = { 0 };
	void *copy_buffer = NULL;
	size_t copy_buffer_size = 0;
	int ret = 0;

	if (!vmr) {
		pr_err("vmr device not found\n");
		return -ENXIO;
	}

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
	if (memcmp(xclbin.m_magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2)))
		return -EINVAL;

	copy_buffer_size = (size_t)xclbin.m_header.m_length;
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

	ret = vmr_download_xclbin(vmr, (char *)copy_buffer, copy_buffer_size);

	vfree(copy_buffer);

	VMR_DBG(vmr, "received ioctl data ");

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

	device_destroy(dev_class, devt_major);
	class_destroy(dev_class);
	unregister_chrdev_region(devt_major, 1);

	cdev_del(&vmr_char->cdev);
}

static int vmr_char_create(struct vmr_drvdata *vmr)
{
	struct vmr_char *vmr_char = &vmr->char_dev;
	int ret;

	if (alloc_chrdev_region(&devt_major, 0, 1, DRV_NAME) < 0)
		return -EIO;

	cdev_init(&vmr_char->cdev, &fops);
	vmr_char->cdev.owner = THIS_MODULE;

	ret = cdev_add(&vmr_char->cdev, devt_major, 1);
	if (ret) {
		pr_info("cdev_add %d\n", ret);
		goto free_devt_major;
	}

	dev_class = class_create("versal mgmt char driver class");
	if (IS_ERR(dev_class)) {
		pr_info("create class %ld\n", PTR_ERR(dev_class));
		goto free_cdev;
	}

	vmr_char->cdev_device = device_create(dev_class, NULL, MKDEV(MAJOR(devt_major), 0),
					      NULL, "%s", DRV_NAME);
	if (IS_ERR(vmr_char->cdev_device)) {
		pr_info("device create %ld\n", PTR_ERR(vmr_char->cdev_device));
		goto free_class;
	}

	vmr_char->vmr = vmr;

	VMR_INFO(vmr, "succeeded");

	return 0;
free_class:
	class_destroy(dev_class);

free_cdev:
	kobject_put(&vmr_char->cdev.kobj);

free_devt_major:
	unregister_chrdev_region(devt_major, 1);

	return -EIO;
}

static void versal_mgmt_remove(struct pci_dev *pdev)
{
	struct vmr_drvdata *vmr = pci_get_drvdata(pdev);

	comms_chan_finish(vmr);
	vmr_char_destroy(vmr);
	vmr_stop_services(vmr);
	fini_worker(&vmr->xgq_complete_worker);
	idr_destroy(&vmr->xgq_vmr_cid_idr);

	/* TODO: iounmap bars? */

	mutex_destroy(&vmr->xgq_lock);

	dev_info(&pdev->dev, "%s removed.\n", __func__);
}

static int versal_mgmt_probe(struct pci_dev *pdev,
			     const struct pci_device_id *pdev_id)
{
	struct vmr_drvdata *vmr;
	void __iomem * const *tbl;
	int bar_mask;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to enable device %d.", ret);
		return ret;
	}

	vmr = devm_kzalloc(&pdev->dev, sizeof(*vmr), GFP_KERNEL);
	if (!vmr)
		return -ENOMEM;

	vmr->pdev = pdev;
	vmr->xgq_halted = true;
	mutex_init(&vmr->xgq_lock);
	sema_init(&vmr->xgq_data_sema, 1);
	sema_init(&vmr->xgq_log_page_sema, 1);

	bar_mask = pci_select_bars(pdev, IORESOURCE_MEM);
	ret = pcim_iomap_regions(pdev, bar_mask, "versal-mgmt");
	if (ret) {
		VMR_ERR(vmr, "map regions failed: %d", ret);
		return -ENOMEM;
	}

	tbl = pcim_iomap_table(pdev);
	if (!tbl) {
		VMR_ERR(vmr, "create iomap table failed.");
		return -ENOMEM;
	}
	vmr->xgq_sq_base = tbl[XGQ_VMR_SQ_BAR] + XGQ_VMR_SQ_BAR_OFF;
	vmr->comms_chan_base = tbl[COMMS_CHAN_BAR] + COMMS_CHAN_BAR_OFF;
	vmr->xgq_payload_base = tbl[XGQ_VMR_PAYLOAD_BAR] + XGQ_VMR_PAYLOAD_OFF;
	vmr->xgq_sq_base = vmr->xgq_sq_base + XGQ_SQ_TAIL_POINTER;
	vmr->xgq_cq_base = vmr->xgq_sq_base + XGQ_CQ_TAIL_POINTER;

	ret = vmr_start_services(vmr);
	if (ret)
		return -ENODEV;

	idr_init(&vmr->xgq_vmr_cid_idr);
	INIT_LIST_HEAD(&vmr->xgq_submitted_cmds);

	vmr->xgq_complete_worker.xgq_vmr = vmr;
	init_complete_worker(&vmr->xgq_complete_worker);

	(void)vmr_services_probe(vmr);

	vmr->comms.vmr = vmr;
	ret = comms_chan_init(vmr);
	if (ret) {
		versal_mgmt_remove(pdev);
		return -ENODEV;
	}

	pci_set_drvdata(pdev, vmr);

	ret = vmr_char_create(vmr);
	if (ret) {
		VMR_ERR(vmr, "char create failed");
		return ret;
	}

	VMR_INFO(vmr, "succeeded");

	return 0;
}

static struct pci_driver versal_mgmt_driver = {
	.name = DRV_NAME,
	.id_table = versal_mgmt_id_tbl,
	.probe = versal_mgmt_probe,
	.remove = versal_mgmt_remove,
};

module_pci_driver(versal_mgmt_driver);

MODULE_DESCRIPTION("Versal Management PCIe Device Driver");
MODULE_AUTHOR("AMD Corporation");
MODULE_LICENSE("GPL v2");
