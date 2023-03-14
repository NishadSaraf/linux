// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DMA driver for AMD Queue-based DMA Subsystem
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/platform_data/amd_qdma.h>

#include "qdma.h"
#include "qdma-cpm5.h"

/* MMIO regmap config for all QDMA registers */
static const struct regmap_config qdma_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.max_register = QDMA_PF_ADDR_SPACE_LEN,
};

static inline struct qdma_queue *to_qdma_queue(struct dma_chan *chan)
{
	return container_of(chan, struct qdma_queue, vchan.chan);
}

static inline u64 qdma_get_field(struct qdma_device *qdev, u32 *data,
				 enum qdma_reg_fields field)
{
	const struct qdma_reg_field *f = &qdev->rfields[field];
	u16 index = QDMA_U32_OFF(f->lsb);
	u64 value = 0, mask;

	if (f->width == QDMA_REGF_WIDTH_64) {
		mask = QDMA_REGF_MASK_ULL(f->msb, f->lsb);
		value = (data[index] & mask);
		value |= (data[++index] & (mask >> BITS_PER_TYPE(u32))) <<
			 BITS_PER_TYPE(u32);
		value >>= __bf_shf(mask);
	} else {
		mask = QDMA_REGF_MASK(f->msb, f->lsb);
		value = (data[index] & mask) >> __bf_shf(mask);
	}
	return value;
}

static inline void qdma_set_field(struct qdma_device *qdev, u32 *data,
				  enum qdma_reg_fields field, u64 value)
{
	const struct qdma_reg_field *f = &qdev->rfields[field];
	u16 index = QDMA_U32_OFF(f->lsb);
	u64 mask;

	if (f->width == QDMA_REGF_WIDTH_64) {
		mask = QDMA_REGF_MASK_ULL(f->msb, f->lsb);
		value = mask & (value << __bf_shf(mask));
		data[index] |= value;
		data[index + 1] |= value >> BITS_PER_TYPE(u32);
	} else {
		mask = QDMA_REGF_MASK(f->msb, f->lsb);
		data[index] |= mask & (value << __bf_shf(mask));
	}
}

static inline int qdma_reg_write(struct qdma_device *qdev, u32 *data,
				 enum qdma_reg_offs off)
{
	const struct qdma_reg_off *o = &qdev->roffs[off];

	if (!data)
		return -EINVAL;

	return regmap_write(qdev->regmap, o->offset, *data);
}

static inline int qdma_reg_bulk_write(struct qdma_device *qdev, u32 *data,
				      enum qdma_reg_offs off, u32 index)
{
	const struct qdma_reg_off *o = &qdev->roffs[off];

	if (!data || index >= o->len)
		return -EINVAL;

	return regmap_bulk_write(qdev->regmap, o->offset + index * sizeof(u32),
				 data, o->len - index);
}

static inline int qdma_reg_read(struct qdma_device *qdev, u32 *data,
				enum qdma_reg_offs off)
{
	const struct qdma_reg_off *o = &qdev->roffs[off];

	if (!data)
		return -EINVAL;

	return regmap_read(qdev->regmap, o->offset, data);
}

static inline int qdma_reg_bulk_read(struct qdma_device *qdev, u32 *data,
				     enum qdma_reg_offs off, u32 index)
{
	const struct qdma_reg_off *o = &qdev->roffs[off];

	if (!data || index >= o->len)
		return -EINVAL;

	return regmap_bulk_read(qdev->regmap, o->offset + index * sizeof(u32),
				data, o->len - index);
}

static inline int qdma_reg_read_poll(struct qdma_device *qdev,
				     enum qdma_reg_fields field)
{
	const struct qdma_reg_field *f = &qdev->rfields[field];
	const struct qdma_reg_off *o = &qdev->roffs[f->regoff];
	u32 value = 0, mask = QDMA_REGF_MASK(f->msb, f->lsb);

	return regmap_read_poll_timeout(qdev->regmap, o->offset, value,
					!(value & mask), QDMA_PF_POLL_INTRVL_US,
					QDMA_PF_POLL_TIMEOUT_US);
}

/**
 * qdma_context_cmd_execute() - Executes command of a given context type
 * @qdev: DMA driver handle
 * @type: context type
 * @cmd: command opcode
 * @index: for queue context, this serves as queue index
 */
static int qdma_context_cmd_execute(struct qdma_device *qdev,
				    enum qdma_ctxt_type type,
				    enum qdma_ctxt_cmd cmd, u16 index)
{
	u32 value = 0;
	int ret;

	qdma_set_field(qdev, &value, QDMA_REGF_CMD_INDX, index);
	qdma_set_field(qdev, &value, QDMA_REGF_CMD_CMD, cmd);
	qdma_set_field(qdev, &value, QDMA_REGF_CMD_TYPE, type);

	ret = qdma_reg_write(qdev, &value, QDMA_REGO_CTXT_CMD);
	if (ret)
		return ret;

	ret = qdma_reg_read_poll(qdev, QDMA_REGF_CMD_BUSY);
	if (ret) {
		qdma_err(qdev, "Context command execution timed out");
		return ret;
	}

	return 0;
}

/**
 * qdma_context_write_data() - Write context data
 * @qdev: DMA driver handle
 * @data: write buffer
 */
static int qdma_context_write_data(struct qdma_device *qdev, u32 *data)
{
	u32 mask[QDMA_CTXT_REGMAP_LEN];
	int ret;

	if (!data)
		return -EINVAL;

	memset(mask, 0xFF, QDMA_CTXT_REGMAP_LEN * sizeof(u32));

	ret = qdma_reg_bulk_write(qdev, mask, QDMA_REGO_CTXT_MASK, 0U);
	if (ret)
		goto exit;

	ret = qdma_reg_bulk_write(qdev, data, QDMA_REGO_CTXT_DATA, 0U);
	if (ret)
		goto exit;
exit:
	return ret;
}

/**
 * qdma_prep_sw_desc_context() - Prepares write buffer of software descriptor
 *				 context
 * @qdev: DMA driver handle
 * @ctxt: software descriptor context config
 * @data: write buffer
 */
static void qdma_prep_sw_desc_context(struct qdma_device *qdev,
				      struct qdma_ctxt_sw_dec *ctxt,
				      u32 *data)
{
	qdma_set_field(qdev, data, QDMA_REGF_DESC_BASE, ctxt->desc_base);
	qdma_set_field(qdev, data, QDMA_REGF_DESC_SIZE, ctxt->desc_sz);
	qdma_set_field(qdev, data, QDMA_REGF_RING_ID, ctxt->rid);
	qdma_set_field(qdev, data, QDMA_REGF_QUEUE_MODE, ctxt->mode);
	qdma_set_field(qdev, data, QDMA_REGF_IRQ_ENABLE, ctxt->irq_en);
	qdma_set_field(qdev, data, QDMA_REGF_WBK_ENABLE, ctxt->wbk_en);
	qdma_set_field(qdev, data, QDMA_REGF_WBI_INTVL_ENABLE,
		       ctxt->wbi_intvl_en);
	qdma_set_field(qdev, data, QDMA_REGF_QUEUE_ENABLE, ctxt->qen);
}

/**
 * qdma_context_config() - Configures a queue context
 * @qdev: DMA driver handle
 * @type: context type
 * @cmd: command opcode
 * @ctxt: context config
 * @data: read or write buffer
 * @index: for queue context this servers as queue index
 */
static int qdma_context_config(struct qdma_device *qdev,
			       enum qdma_ctxt_type type,
			       enum qdma_ctxt_cmd cmd,
			       union qdma_ctxt_data *ctxt, u32 *data, u16 index)
{
	u32 temp[QDMA_CTXT_REGMAP_LEN] = {0};
	void *cdata;
	int ret;

	if (type == QDMA_CTXT_DESC_SW_C2H || type == QDMA_CTXT_DESC_SW_H2C)
		cdata = (struct qdma_ctxt_sw_dec *)ctxt;

	switch (cmd) {
	case QDMA_CTXT_READ:
		ret = qdma_context_cmd_execute(qdev, type, cmd, index);
		if (ret)
			return ret;

		ret = qdma_reg_bulk_read(qdev, data, QDMA_REGO_CTXT_DATA, 0U);
		break;
	case QDMA_CTXT_WRITE:
		if (type == QDMA_CTXT_DESC_SW_C2H ||
		    type == QDMA_CTXT_DESC_SW_H2C) {
			qdma_prep_sw_desc_context(qdev, cdata, temp);
		} else {
			qdma_err(qdev,
				 "Unsupported command for the context type %d",
				 type);
			return -EINVAL;
		}

		ret = qdma_context_write_data(qdev, temp);
		if (ret)
			return ret;

		ret = qdma_context_cmd_execute(qdev, type, cmd, index);
		break;
	case QDMA_CTXT_CLEAR:
		ret = qdma_context_cmd_execute(qdev, type, cmd, index);
		break;
	default:
		qdma_err(qdev, "Invalid context command %d", cmd);
		ret = -EINVAL;
	}

	return ret;
}

/**
 * qdma_get_queue_status() - Returns the status of queue
 * @qdev: DMA driver handle
 * @dir: queue direction
 * @qid: queue index
 * @status: returns 1 if queue is enabled, or 0 if disabled
 */
static int qdma_get_queue_status(struct qdma_device *qdev,
				 enum dma_transfer_direction dir, u16 qid,
				 bool *status)
{
	u32 data[QDMA_CTXT_REGMAP_LEN] = {0};
	enum qdma_ctxt_type sw;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		sw = QDMA_CTXT_DESC_SW_H2C;
	} else if (dir == DMA_DEV_TO_MEM) {
		sw = QDMA_CTXT_DESC_SW_C2H;
	} else {
		qdma_err(qdev, "Invalid DMA direction");
		return -EINVAL;
	}

	ret = qdma_context_config(qdev, sw, QDMA_CTXT_READ, NULL, data, qid);
	if (ret)
		goto exit;

	*status = qdma_get_field(qdev, data, QDMA_REGF_QUEUE_ENABLE);
exit:
	return ret;
}

/**
 * qdma_init_queue_context() - Initializes a queue context to clean state
 * @qdev: DMA driver handle
 * @dir: queue direction
 * @qid: queue index
 */
static int qdma_init_queue_context(struct qdma_device *qdev,
				   enum dma_transfer_direction dir, u16 qid)
{
	enum qdma_ctxt_type sw, hw;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		sw = QDMA_CTXT_DESC_SW_H2C;
		hw = QDMA_CTXT_DESC_HW_H2C;
	} else if (dir == DMA_DEV_TO_MEM) {
		sw = QDMA_CTXT_DESC_SW_C2H;
		hw = QDMA_CTXT_DESC_HW_C2H;
	} else {
		qdma_err(qdev, "Invalid DMA direction");
		return -EINVAL;
	}

	/* Clear SW descriptor context */
	ret = qdma_context_config(qdev, sw, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev, "Failed clearing H2C SW descriptor context");
		return ret;
	}

	/* Clear HW descriptor context */
	ret = qdma_context_config(qdev, hw, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev, "Failed clearing H2C HW descriptor context");
		return ret;
	}

	return 0;
}

/**
 * qdma_setup_queue_context() - Sets up the queue context
 * @qdev: DMA driver handle
 * @ctxt: context config
 * @dir: queue direction
 * @qid: queue index
 */
static int qdma_setup_queue_context(struct qdma_device *qdev,
				    union qdma_ctxt_data *ctxt,
				    enum dma_transfer_direction dir, u16 qid)
{
	enum qdma_ctxt_type type;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		type = QDMA_CTXT_DESC_SW_H2C;
	} else if (dir == DMA_DEV_TO_MEM) {
		type = QDMA_CTXT_DESC_SW_C2H;
	} else {
		qdma_err(qdev, "Invalid DMA direction");
		return -EINVAL;
	}

	/* Setup SW descriptor context */
	ret = qdma_context_config(qdev, type, QDMA_CTXT_WRITE, ctxt, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed setup SW descriptor %s context for %d queue",
			 (dir == DMA_MEM_TO_DEV) ? "H2C" : "C2H", qid);
		return ret;
	}

	return 0;
}

/**
 * qdma_queue_teardown() - Cleanup context of a queue
 * @qdev: DMA driver handle
 * @dir: queue direction
 * @qid: queue index
 */
static int qdma_queue_teardown(struct qdma_device *qdev,
			       enum dma_transfer_direction dir, u16 qid)
{
	enum qdma_ctxt_type type;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		type = QDMA_CTXT_DESC_SW_H2C;
	} else if (dir == DMA_DEV_TO_MEM) {
		type = QDMA_CTXT_DESC_SW_C2H;
	} else {
		qdma_err(qdev, "Invalid DMA direction");
		return -EINVAL;
	}

	/* Clear SW descriptor context */
	ret = qdma_context_config(qdev, type, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed setup SW descriptor %s context for %d queue",
			 (dir == DMA_MEM_TO_DEV) ? "H2C" : "C2H", qid);
		return ret;
	}

	return 0;
}

/**
 * qdma_sgdma_control() - Enable or disable memory-mapped DMA engines
 * @qdev: DMA driver handle
 * @dir: queue direction
 * @ctrl: 1 of enable, 0 for disable
 */
static int qdma_sgdma_control(struct qdma_device *qdev,
			      enum dma_transfer_direction dir, u8 ctrl)
{
	u32 value = 0;

	if (dir == DMA_MEM_TO_DEV) {
		qdma_set_field(qdev, &value, QDMA_REGF_MM_H2C_CTRL, ctrl);
		return qdma_reg_write(qdev, &value, QDMA_REGO_MM_H2C_CTRL);
	} else if (dir == DMA_DEV_TO_MEM) {
		qdma_set_field(qdev, &value, QDMA_REGF_MM_C2H_CTRL, ctrl);
		return qdma_reg_write(qdev, &value, QDMA_REGO_MM_C2H_CTRL);
	}

	qdma_err(qdev, "Invalid DMA direction");
	return -EINVAL;
}

/**
 * qdma_get_hw_queue_count() - Returns per DMA direction count of queues as
 *			       supported by the hardware
 * @qdev: DMA driver handle
 * @qcount: queue count
 */
static int qdma_get_hw_queue_count(struct qdma_device *qdev, u16 *qcount)
{
	u32 value = 0;
	int ret;

	ret = qdma_reg_read(qdev, &value, QDMA_REGO_QUEUE_COUNT);
	if (ret) {
		qdma_err(qdev,
			 "Failed to read queue count register with error %d",
			 ret);
		return ret;
	}

	value = qdma_get_field(qdev, &value, QDMA_REGF_QUEUE_COUNT) + 1U;
	*qcount = value / 2;

	return 0;
}

/**
 * qdma_alloc_queues() - Allocates requested queues and initialize virtual DMA
 *			 channels
 * @qdev: DMA driver handle
 * @dir: queue direction
 */
static int qdma_alloc_queues(struct qdma_device *qdev,
			     enum dma_transfer_direction dir)
{
	struct qdma_platdata *pdata = dev_get_platdata(&qdev->pdev->dev);
	struct qdma_queue *q, **queues;
	u32 i, *qnum;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		queues = &qdev->h2c_queues;
		qnum = &qdev->h2c_qnum;
	} else if (dir == DMA_DEV_TO_MEM) {
		queues = &qdev->c2h_queues;
		qnum = &qdev->c2h_qnum;
	} else {
		qdma_err(qdev, "Invalid DMA direction");
		return -EINVAL;
	}

	for (i = 0; i < pdata->max_mm_channels; i++) {
		bool status;

		ret = qdma_get_queue_status(qdev, dir, i, &status);
		if (ret)
			return ret;

		if (status) {
			qdma_err(qdev, "Queue already in use");
			return -EBUSY;
		}
	}

	*qnum = i;

	*queues = devm_kzalloc(&qdev->pdev->dev, sizeof(**queues) * (*qnum),
			       GFP_KERNEL);
	if (!*queues)
		return -ENOMEM;

	for (i = 0; i < *qnum; i++) {
		q = &(*queues)[i];
		q->ring_size = QDMA_PF_DEFAULT_RING_SIZE;
		q->qdev = qdev;
		q->dir = dir;
		q->qid = i;

		vchan_init(&q->vchan, &qdev->dma_dev);
	}

	qdma_info(qdev, "Configured %d %s-MM queue(s)", *qnum,
		  (dir == DMA_MEM_TO_DEV) ? "H2C" : "C2H");

	return 0;
}

/**
 * qdma_reg_init()- Initializes the register backend based on the QDMA hardware
 *		    instance type
 * @qdev: DMA driver handle
 */
static int qdma_reg_init(struct qdma_device *qdev)
{
	u32 value;
	int ret;

	ret = regmap_read(qdev->regmap, QDMA_PF_INST_TYPE_REGOFF, &value);
	if (ret) {
		qdma_err(qdev, "Failed to read DMA config instance type");
		return -EIO;
	}

	value = FIELD_GET(QDMA_PF_INST_TYPE_MASK, value);

	switch (value) {
	case QDMA_SOFT_IP:
	case QDMA_HARD_IP:
		qdev->rfields = qdma_regfs_cpm5;
		qdev->roffs = qdma_regos_cpm5;
		break;
	default:
		qdma_err(qdev, "Invalid instance type %d", value);
		ret = -EINVAL;
	}

	return 0;
}

/**
 * qdma_device_verify()- Verifies if the DMA config space belong to a CPM5 QDMA
 *			 subsystem
 * @qdev: DMA driver handle
 */
static int qdma_device_verify(struct qdma_device *qdev)
{
	u32 value;

	if (regmap_read(qdev->regmap, QDMA_PF_IDENTIFIER_REGOFF, &value)) {
		qdma_err(qdev, "Failed to read DMA identifier register");
		return -EIO;
	}

	value = FIELD_GET(QDMA_PF_IDENTIFIER_MASK, value);
	return (value == QDMA_IDENTIFIER) ? 0 : -ENODEV;
}

/**
 * qdma_device_setup() - Initial hardware and software setup
 * @qdev: DMA driver handle
 */
static int qdma_device_setup(struct qdma_device *qdev)
{
	u32 ring = 0;
	int ret = 0;

	/* Setup global ring buffer size at QDMA_PF_DEFAULT_RING_ID index */
	qdma_set_field(qdev, &ring, QDMA_REGF_RING_SIZE,
		       QDMA_PF_DEFAULT_RING_SIZE);

	ret = qdma_reg_write(qdev, &ring, QDMA_REGO_RING_SIZE);
	if (ret) {
		qdma_err(qdev, "Failed to setup ring %d of size %d",
			 QDMA_PF_DEFAULT_RING_ID, QDMA_PF_DEFAULT_RING_SIZE);
		return ret;
	}

	/* Enable memory-mapped DMA engine in both directions */
	ret = qdma_sgdma_control(qdev, DMA_MEM_TO_DEV, ENABLE);
	if (ret) {
		qdma_err(qdev, "Failed to enable H2C SGDMA with error %d", ret);
		return ret;
	}
	qdev->mm_h2c_enable = 1;

	ret = qdma_sgdma_control(qdev, DMA_DEV_TO_MEM, ENABLE);
	if (ret) {
		qdma_err(qdev, "Failed to enable C2H SGDMA with error %d", ret);
		return ret;
	}
	qdev->mm_c2h_enable = 1;

	ret = qdma_alloc_queues(qdev, DMA_MEM_TO_DEV);
	if (ret) {
		qdma_err(qdev, "Failed to configure H2C queues with error %d",
			 ret);
		return ret;
	}

	ret = qdma_alloc_queues(qdev, DMA_DEV_TO_MEM);
	if (ret) {
		qdma_err(qdev, "Failed to configure C2H queues with error %d",
			 ret);
	}

	return ret;
}

/**
 * qdma_device_teardown() - Device teardown
 * @qdev: DMA driver handle
 */
static int qdma_device_teardown(struct qdma_device *qdev)
{
	int ret = 0;

	if (qdev->mm_h2c_enable) {
		ret = qdma_sgdma_control(qdev, DMA_MEM_TO_DEV, DISABLE);
		if (ret) {
			qdma_err(qdev,
				 "Failed to disable H2C SGDMA with error %d",
				 ret);
			return ret;
		}
	}

	if (qdev->mm_c2h_enable) {
		ret = qdma_sgdma_control(qdev, DMA_DEV_TO_MEM, DISABLE);
		if (ret) {
			qdma_err(qdev,
				 "Failed to disable C2H SGDMA with error %d",
				 ret);
		}
	}

	return ret;
}

/**
 * qdma_device_config() - Configure the DMA channel
 * @chan: DMA channel
 * @cfg: channel configuration
 */
static int qdma_device_config(struct dma_chan *chan,
			      struct dma_slave_config *cfg)
{
	struct qdma_queue *queue = to_qdma_queue(chan);

	memcpy(&queue->cfg, cfg, sizeof(*cfg));

	return 0;
}

/**
 * qdma_free_queue_resources() - Free queue resources
 * @chan: DMA channel
 */
static void qdma_free_queue_resources(struct dma_chan *chan)
{
	struct qdma_queue *queue = to_qdma_queue(chan);
	struct qdma_device *qdev = queue->qdev;
	struct device *dev = qdev->dma_dev.dev;

	qdma_queue_teardown(qdev, queue->dir, queue->qid);
	dma_free_coherent(dev, queue->ring_size * QDMA_MM_DESC_SIZE,
			  queue->desc_base, queue->dma_desc_base);
	vchan_free_chan_resources(&queue->vchan);
}

/**
 * qdma_alloc_queue_resources() - Allocate queue resources
 * @chan: DMA channel
 */
static int qdma_alloc_queue_resources(struct dma_chan *chan)
{
	struct qdma_queue *queue = to_qdma_queue(chan);
	struct qdma_device *qdev = queue->qdev;
	struct device *dev = qdev->dma_dev.dev;
	struct qdma_ctxt_sw_dec desc;
	size_t size;
	int ret;

	if (dev && !dev_is_pci(dev))
		dev = dev->parent;

	if (!dev) {
		qdma_err(qdev, "PCIe device not found");
		return -EINVAL;
	}

	ret = qdma_init_queue_context(qdev, queue->dir, queue->qid);
	if (ret)
		return ret;

	/**
	 * Descriptor ring size value must be at least 4k to support
	 * dma_alloc_coherent() type allocation.
	 */
	size = queue->ring_size * QDMA_MM_DESC_SIZE;
	if (size < QDMA_MIN_DMA_ALLOC_SIZE) {
		qdma_err(qdev, "Invalid ring size");
		return -EINVAL;
	}

	queue->desc_base = dma_alloc_coherent(dev, size,
					      &queue->dma_desc_base,
					      GFP_KERNEL);
	if (!queue->desc_base) {
		qdma_err(qdev, "Failed to allocate descriptor ring");
		return -ENOMEM;
	}

	/* Setup SW descriptor queue context */
	desc.desc_base = queue->dma_desc_base;
	desc.rid = QDMA_PF_DEFAULT_RING_ID;
	desc.desc_sz = QDMA_DESC_SIZE_32B;
	desc.mode = QDMA_QUEUE_OP_MM;
	desc.wbi_intvl_en = true;
	desc.irq_en = true;
	desc.wbk_en = true;
	desc.qen = true;

	ret = qdma_setup_queue_context(qdev, (union qdma_ctxt_data *)&desc,
				       queue->dir, queue->qid);
	if (ret) {
		qdma_err(qdev, "Failed to setup SW descriptor context for %s",
			 chan->name);
		dma_free_coherent(dev, size, queue->desc_base,
				  queue->dma_desc_base);
		return ret;
	}

	return 0;
}

/**
 * qdma_filter_fn() - Queue filter function
 * @chan: DMA channel
 * @param: queue info pointer
 */
static bool qdma_filter_fn(struct dma_chan *chan, void *param)
{
	struct qdma_queue *queue = to_qdma_queue(chan);
	struct qdma_queue_info *info = param;

	return info->dir == queue->dir;
}

/**
 * qdma_xfer_start() - Start DMA transfer
 * @xdma_chan: DMA channel pointer
 */
static int qdma_xfer_start(struct qdma_queue *queue)
{
	/* Placeholder for successfully registering dmaengine */
	return 0;
}

/**
 * qdma_issue_pending() - Issue pending transactions
 * @chan: DMA channel pointer
 */
static void qdma_issue_pending(struct dma_chan *chan)
{
	struct qdma_queue *queue = to_qdma_queue(chan);
	unsigned long flags;

	/* Placeholder for successfully registering dmaengine */
	spin_lock_irqsave(&queue->vchan.lock, flags);
	if (vchan_issue_pending(&queue->vchan))
		qdma_xfer_start(queue);
	spin_unlock_irqrestore(&queue->vchan.lock, flags);
}

static int amd_qdma_remove(struct platform_device *pdev)
{
	struct qdma_device *qdev = platform_get_drvdata(pdev);

	if (qdev->mm_h2c_enable || qdev->mm_c2h_enable)
		qdma_device_teardown(qdev);

	if (qdev->status & QDMA_DEV_STATUS_REG_DMA)
		dma_async_device_unregister(&qdev->dma_dev);

	return 0;
}

static int amd_qdma_probe(struct platform_device *pdev)
{
	struct qdma_platdata *pdata = dev_get_platdata(&pdev->dev);
	struct qdma_device *qdev;
	void __iomem *regs;
	u16 qcount;
	int ret;

	qdev = devm_kzalloc(&pdev->dev, sizeof(*qdev), GFP_KERNEL);
	if (!qdev)
		return -ENOMEM;

	platform_set_drvdata(pdev, qdev);
	qdev->pdev = pdev;

	regs = devm_platform_get_and_ioremap_resource(pdev, 0, NULL);
	if (IS_ERR(regs)) {
		ret = PTR_ERR(regs);
		qdma_err(qdev, "Failed to remap IO resource with error %d",
			 ret);
		goto failed;
	}

	qdev->regmap = devm_regmap_init_mmio(&pdev->dev, regs,
					     &qdma_regmap_config);
	if (IS_ERR(qdev->regmap)) {
		ret = PTR_ERR(qdev->regmap);
		qdma_err(qdev, "Regmap init failed with error %d", ret);
		goto failed;
	}

	ret = qdma_device_verify(qdev);
	if (ret)
		goto failed;

	ret = qdma_reg_init(qdev);
	if (ret)
		goto failed;

	ret = qdma_get_hw_queue_count(qdev, &qcount);
	if (ret)
		goto failed;

	if (pdata->max_mm_channels > qcount) {
		qdma_err(qdev,
			 "Max DMA channel count exceeds HW supported limit");
		goto failed;
	}

	qdev->h2c_qnum = pdata->max_mm_channels;
	qdev->c2h_qnum = pdata->max_mm_channels;

	INIT_LIST_HEAD(&qdev->dma_dev.channels);

	ret = qdma_device_setup(qdev);
	if (ret)
		goto failed;

	dma_cap_set(DMA_SLAVE, qdev->dma_dev.cap_mask);
	dma_cap_set(DMA_PRIVATE, qdev->dma_dev.cap_mask);

	qdev->dma_dev.dev = &pdev->dev;
	qdev->dma_dev.filter.map = pdata->device_map;
	qdev->dma_dev.filter.mapcnt = pdata->device_map_cnt;
	qdev->dma_dev.filter.fn = qdma_filter_fn;
	qdev->dma_dev.device_config = qdma_device_config;
	qdev->dma_dev.device_alloc_chan_resources = qdma_alloc_queue_resources;
	qdev->dma_dev.device_free_chan_resources = qdma_free_queue_resources;
	qdev->dma_dev.device_tx_status = dma_cookie_status;
	qdev->dma_dev.device_issue_pending = qdma_issue_pending;

	ret = dma_async_device_register(&qdev->dma_dev);
	if (ret) {
		qdma_err(qdev, "Failed to register AMD QDMA: %d", ret);
		goto dev_tear;
	}
	qdev->status |= QDMA_DEV_STATUS_REG_DMA;

	qdma_info(qdev, "AMD QDMA driver probed");

	return 0;

dev_tear:
	qdma_device_teardown(qdev);
failed:
	qdma_err(qdev, "Failed to probe AMD QDMA driver");
	amd_qdma_remove(pdev);
	return ret;
}

static const struct platform_device_id amd_qdma_id_table[] = {
	{ "amd-qdma", 0},
	{/* sentinel */},
};

static struct platform_driver amd_qdma_driver = {
	.driver		= {
		.name = "amd-qdma",
	},
	.id_table	= amd_qdma_id_table,
	.probe		= amd_qdma_probe,
	.remove		= amd_qdma_remove,
};

module_platform_driver(amd_qdma_driver);

MODULE_DESCRIPTION("AMD QDMA driver");
MODULE_AUTHOR("Nishad Saraf <nishads@amd.com>");
MODULE_LICENSE("GPL");
