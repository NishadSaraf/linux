// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Versal PCIe device
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 *
 * Authors:
 */

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/firmware.h>

#include "xgq_cmd_vmr.h"
#include "xgq_xocl_plat.h"

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

struct vmr_drvdata;

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

struct vmr_drvdata {
	struct pci_dev		*pdev;
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
	int ret;

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

static int vmr_download_apu_bin(struct vmr_drvdata *vmr, char *buf, size_t len)
{
	int ret;

	ret = vmr_transfer_data(vmr, buf, (u32)len, 0, XGQ_CMD_OP_LOAD_APUBIN,
				XGQ_DOWNLOAD_TIME);
	if (ret != len) {
		VMR_ERR(vmr, "ret: %d, buf request: %ld", ret, len);
		return -EIO;
	}

	VMR_INFO(vmr, "successfully download len %ld", len);
	return 0;
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

static void versal_mgmt_remove(struct pci_dev *pdev)
{
	struct vmr_drvdata *vmr = pci_get_drvdata(pdev);

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

	pci_set_drvdata(pdev, vmr);

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
