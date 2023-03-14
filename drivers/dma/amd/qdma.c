// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DMA driver for AMD Queue-based DMA Subsystem
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/platform_data/amd_qdma.h>

#include "qdma.h"

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

/**
 * bitmap_cpy_from_value() - Copies nbits from value at start in map
 * @map: destination bitmap
 * @value: source bitmap
 * @maplen: length of destination bitmap in bits
 * @start: bit position to in map
 * @nbits: numbers of bits to be copied from value
 */
static inline int bitmap_cpy_from_value(unsigned long *map,
					unsigned long *value, u32 maplen,
					u32 start, u32 nbits)
{
	unsigned long *mask;

	mask = bitmap_zalloc(maplen, GFP_KERNEL);
	if (!mask)
		return -ENOMEM;

	bitmap_copy(mask, value, nbits);
	bitmap_shift_left(mask, mask, start, maplen);
	bitmap_or(map, map, mask, maplen);

	bitmap_free(mask);
	return 0;
}

/**
 * qdma_context_cmd_execute() - Executes command of a given context type
 * @qdev: DMA driver handle
 * @type: context type
 * @cmd: command opcode
 * @index: for queue context this servers as queue index
 */
static int qdma_context_cmd_execute(struct qdma_device *qdev,
				    enum qdma_ctxt_type type,
				    enum qdma_ctxt_cmd cmd, u16 index)
{
	u32 value = 0;
	int ret;

	value = FIELD_PREP(QDMA_PF_CTXT_CMD_INDX_MASK, index) |
		FIELD_PREP(QDMA_PF_CTXT_CMD_CMD_MASK, cmd) |
		FIELD_PREP(QDMA_PF_CTXT_CMD_TYPE_MASK, type);

	ret = regmap_write(qdev->regmap, QDMA_PF_CTXT_CMD_REGOFF, value);
	if (ret)
		return ret;

	ret = regmap_read_poll_timeout(qdev->regmap, QDMA_PF_CTXT_CMD_REGOFF,
				       value, QDMA_PF_CTXT_CMD_POLL_COND(value),
				       QDMA_PF_CTXT_CMD_POLL_INTRVL_US,
				       QDMA_PF_CTXT_CMD_POLL_TIMEOUT_US);
	if (ret) {
		qdma_err(qdev, "Context command exection timed out\n");
		return ret;
	}

	return 0;
}

/**
 * qdma_context_read_data() - read context data
 * @qdev: DMA driver handle
 * @data: read buffer
 */
static int qdma_context_read_data(struct qdma_device *qdev,
				  unsigned long *data)
{
	if (!data)
		return -EINVAL;

	return regmap_bulk_read(qdev->regmap, QDMA_PF_CTXT_DATA_REGOFF,
				data, QDMA_CTXT_REGMAP_LEN);
}

/**
 * qdma_context_write_data() - write context data
 * @qdev: DMA driver handle
 * @data: write buffer
 */
static int qdma_context_write_data(struct qdma_device *qdev,
				   unsigned long *data)
{
	int ret;
	unsigned long *mask;

	if (!data)
		return -EINVAL;

	mask = bitmap_alloc(QDMA_CTXT_BIT_LEN, GFP_KERNEL);
	if (!mask)
		return -ENOMEM;

	bitmap_set(mask, 0, QDMA_CTXT_BIT_LEN);

	ret = regmap_bulk_write(qdev->regmap, QDMA_PF_CTXT_MASK_REGOFF, mask,
				QDMA_CTXT_REGMAP_LEN);
	if (ret)
		goto exit;

	ret = regmap_bulk_write(qdev->regmap, QDMA_PF_CTXT_DATA_REGOFF, data,
				QDMA_CTXT_REGMAP_LEN);
	if (ret)
		goto exit;
exit:
	bitmap_free(mask);
	return ret;
}

/**
 * qdm_prep_sw_desc_context() - prepares write buffer of software descriptor
 *				context
 * @qdev: DMA driver handle
 * @ctxt: software descriptor context config
 * @data: write buffer
 */
static int qdm_prep_sw_desc_context(struct qdma_device *qdev,
				    struct qdma_ctxt_sw_dec *ctxt,
				    unsigned long *data)
{
	int ret;

	ret = bitmap_cpy_from_value(data, (unsigned long *)&ctxt->desc_base,
				    QDMA_CTXT_BIT_LEN,
				    QDMA_CTXT_SW_DESC_DESC_BASE_LSB,
				    QDMA_CTXT_SW_DESC_DESC_BASE_WIDTH);
	if (ret)
		return ret;

	ret = bitmap_cpy_from_value(data, (unsigned long *)&ctxt->desc_sz,
				    QDMA_CTXT_BIT_LEN,
				    QDMA_CTXT_SW_DESC_DESC_SIZE_LSB,
				    QDMA_CTXT_SW_DESC_DESC_SIZE_WIDTH);
	if (ret)
		return ret;

	ret = bitmap_cpy_from_value(data, (unsigned long *)&ctxt->rid,
				    QDMA_CTXT_BIT_LEN,
				    QDMA_CTXT_SW_DESC_DESC_RID_LSB,
				    QDMA_CTXT_SW_DESC_DESC_RID_WIDTH);
	if (ret)
		return ret;

	if (ctxt->mode)
		set_bit(QDMA_CTXT_SW_DESC_MODE_LSB, data);

	if (ctxt->irq_en)
		set_bit(QDMA_CTXT_SW_DESC_IRQ_EN_LSB, data);

	if (ctxt->wbk_en)
		set_bit(QDMA_CTXT_SW_DESC_WBK_EN_LSB, data);

	if (ctxt->wbi_intvl_en)
		set_bit(QDMA_CTXT_SW_DESC_WBI_INTVL_EN_LSB, data);

	if (ctxt->qen)
		set_bit(QDMA_CTXT_SW_DESC_WBK_EN_LSB, data);
	return 0;
}

/**
 * qdma_context_config() - configure a queue context
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
			       union qdma_ctxt_data *ctxt,
			       unsigned long *data, u16 index)
{
	unsigned long *temp;
	void *cdata;
	int ret;

	if (type == QDMA_CTXT_DESC_SW_C2H || type == QDMA_CTXT_DESC_SW_H2C)
		cdata = (struct qdma_ctxt_sw_dec *)ctxt;

	switch (cmd) {
	case QDMA_CTXT_READ:
		ret = qdma_context_cmd_execute(qdev, type, cmd, index);
		if (ret)
			return ret;

		ret = qdma_context_read_data(qdev, data);
		break;
	case QDMA_CTXT_WRITE:
		temp = bitmap_zalloc(QDMA_CTXT_BIT_LEN, GFP_KERNEL);
		if (!temp)
			return -ENOMEM;

		if (type == QDMA_CTXT_DESC_SW_C2H ||
		    type == QDMA_CTXT_DESC_SW_H2C) {
			ret = qdm_prep_sw_desc_context(qdev, cdata, temp);
			if (ret) {
				bitmap_free(temp);
				return ret;
			}
		} else {
			qdma_err(qdev,
				 "Unsupported command for the context type %d\n",
				 type);
			bitmap_free(temp);
			return -EINVAL;
		}

		ret = qdma_context_write_data(qdev, temp);
		if (ret) {
			bitmap_free(temp);
			return ret;
		}

		ret = qdma_context_cmd_execute(qdev, type, cmd, index);

		bitmap_free(temp);
		break;
	case QDMA_CTXT_CLEAR:
		ret = qdma_context_cmd_execute(qdev, type, cmd, index);
		break;
	default:
		qdma_err(qdev, "Invalid context command %d\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

/**
 * qdma_get_queue_status() - returns the status of queue
 * @qdev: DMA driver handle
 * @dir: queue direction
 * @qid: queue index
 * @status: return 1 if queue is enabled or 0 if disabled
 */
static int qdma_get_queue_status(struct qdma_device *qdev,
				 enum dma_transfer_direction dir, u16 qid,
				 bool *status)
{
	enum qdma_ctxt_type sw;
	unsigned long *data;
	int ret;

	if (dir == DMA_MEM_TO_DEV) {
		sw = QDMA_CTXT_DESC_SW_H2C;
	} else if (dir == DMA_DEV_TO_MEM) {
		sw = QDMA_CTXT_DESC_SW_C2H;
	} else {
		qdma_err(qdev, "Invalid DMA direction\n");
		return -EINVAL;
	}

	data = bitmap_zalloc(QDMA_CTXT_BIT_LEN, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = qdma_context_config(qdev, sw, QDMA_CTXT_READ, NULL, data, qid);
	if (ret)
		goto exit;

	*status = test_bit(QDMA_CTXT_SW_DESC_QEN_LSB, data);
exit:
	bitmap_free(data);
	return ret;
}

/**
 * qdma_init_queue_context() - initialize a queu context to clean state
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
		qdma_err(qdev, "Invalid DMA direction\n");
		return -EINVAL;
	}

	/* Clear SW descriptor context */
	ret = qdma_context_config(qdev, sw, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed clearing H2C software descriptor context");
		return ret;
	}

	/* Clear HW descriptor context */
	ret = qdma_context_config(qdev, hw, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed clearing H2C HW descriptor context");
		return ret;
	}

	return 0;
}

/**
 * qdma_setup_queue_context() - configure a queue context
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
		qdma_err(qdev, "Invalid DMA direction\n");
		return -EINVAL;
	}

	/* Setup SW descriptor context */
	ret = qdma_context_config(qdev, type, QDMA_CTXT_WRITE, ctxt, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed setup H2C SW descriptor context");
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
		qdma_err(qdev, "Invalid DMA direction\n");
		return -EINVAL;
	}

	/* Clear SW descriptor context */
	ret = qdma_context_config(qdev, type, QDMA_CTXT_CLEAR, NULL, NULL,
				  qid);
	if (ret) {
		qdma_err(qdev,
			 "Failed clearing H2C software descriptor context");
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
	u32 regoff, value;

	if (dir == DMA_MEM_TO_DEV) {
		regoff = QDMA_PF_H2C_MM_CTRL_REGOFF;
		value = FIELD_PREP(QDMA_PF_H2C_MM_CTRL_MASK, ctrl);
	} else if (dir == DMA_DEV_TO_MEM) {
		regoff = QDMA_PF_C2H_MM_CTRL_REGOFF;
		value = FIELD_PREP(QDMA_PF_C2H_MM_CTRL_MASK, ctrl);
	} else {
		qdma_err(qdev, "invalid direction specified");
		return -EINVAL;
	}

	return regmap_write(qdev->regmap, regoff, value);
}

/**
 * qdma_get_hw_queue_count() - Returns per DMA direction count of queues as
 *			       supported by the hardware
 * @qdev: DMA driver handle
 * @qcount: queue count
 */
static int qdma_get_hw_queue_count(struct qdma_device *qdev, u16 *qcount)
{
	u32 value;
	int ret;

	ret = regmap_read(qdev->regmap, QDMA_PF_MAX_QUEUE_COUNT_REGOFF,
			  &value);
	if (ret) {
		qdma_err(qdev, "Failed to read DMA register with error %d\n",
			 ret);
		return ret;
	}

	value = FIELD_GET(QDMA_PF_MAX_QUEUE_COUNT_MASK, value) + 1U;
	*qcount = value / 2;

	return 0;
}

/**
 * qdma_set_ring_sizes() - Defines size(s) for ring(s)
 * @qdev: DMA driver handle
 * @start: start index of ring index
 * @count: number of rings indices to be configured
 * @size: array of size values
 */
static int qdma_set_ring_sizes(struct qdma_device *qdev, u8 start, u8 count,
			       u16 *size)
{
	if (!size || !count || (start + count) > QDMA_PF_GLB_RING_COUNT)
		return -EINVAL;

	return regmap_bulk_write(qdev->regmap,
				 QDMA_PF_GLB_RING_SIZE_BASE_REGOFF, size,
				 count);
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
		qdma_err(qdev, "invalid direction specified");
		return -EINVAL;
	}

	for (i = 0; i < pdata->max_dma_queues; i++) {
		bool status;

		ret = qdma_get_queue_status(qdev, dir, i, &status);
		if (ret)
			return ret;

		if (status) {
			qdma_err(qdev, "Queue already in use\n");
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

	dev_info(&qdev->pdev->dev, "Configured %d %s-MM queue(s)", *qnum,
		 (dir == DMA_MEM_TO_DEV) ? "H2C" : "C2H");

	return 0;
}

/**
 * qdma_device_verify()- verifies if the DMA config space belong to a CPM5 QDMA
 *			 subsystem
 * @qdev: DMA driver handle
 */
static int qdma_device_verify(struct qdma_device *qdev)
{
	u32 value;

	if (regmap_read(qdev->regmap, QDMA_PF_IDENTIFIER_REGOFF, &value)) {
		qdma_err(qdev, "Failed to read DMA config register\n");
		return -EIO;
	}

	value = FIELD_GET(QDMA_PF_IDENTIFIER_MASK, value);
	return (value == QDMA_IDENTIFIER) ? 0 : -ENODEV;
}

/**
 * qdma_device_setup() - early hardware and software setup
 * @qdev: DMA driver handle
 */
static int qdma_device_setup(struct qdma_device *qdev)
{
	u16 ring[1] = {QDMA_PF_DEFAULT_RING_SIZE};
	u8 rid = QDMA_PF_DEFAULT_RING_OFF;
	int ret = 0;

	/* Setup global ring buffer size */
	ret = qdma_set_ring_sizes(qdev, rid, 1, ring);
	if (ret) {
		qdma_err(qdev, "Failed to setup ring size %d of size %d\n",
			 rid, QDMA_PF_DEFAULT_RING_SIZE);
		return ret;
	}

	/* Enable memory-mapped DMA engine in both directions */
	ret = qdma_sgdma_control(qdev, DMA_MEM_TO_DEV, ENABLE);
	if (ret) {
		qdma_err(qdev, "Failed to read DMA register with error %d\n",
			 ret);
		return ret;
	}
	qdev->mm_h2c_enable = 1;

	ret = qdma_sgdma_control(qdev, DMA_DEV_TO_MEM, ENABLE);
	if (ret) {
		qdma_err(qdev, "Failed to read DMA register with error %d\n",
			 ret);
	}
	qdev->mm_c2h_enable = 1;

	ret = qdma_alloc_queues(qdev, DMA_MEM_TO_DEV);
	if (ret) {
		qdma_err(qdev, "Failed to configure H2C queues with error %d\n",
			 ret);
		return ret;
	}

	ret = qdma_alloc_queues(qdev, DMA_DEV_TO_MEM);
	if (ret) {
		qdma_err(qdev, "Failed to configure C2H queues with error %d\n",
			 ret);
	}

	return ret;
}

/**
 * qdma_device_teardown() - device teardown
 * @qdev: DMA driver handle
 */
static int qdma_device_teardown(struct qdma_device *qdev)
{
	int ret = 0;

	if (qdev->mm_h2c_enable) {
		ret = qdma_sgdma_control(qdev, DMA_MEM_TO_DEV, DISABLE);
		if (ret) {
			qdma_err(qdev, "Failed to read DMA register with error %d\n",
				 ret);
			return ret;
		}
	}

	if (qdev->mm_c2h_enable) {
		ret = qdma_sgdma_control(qdev, DMA_DEV_TO_MEM, DISABLE);
		if (ret) {
			qdma_err(qdev, "Failed to read DMA register with error %d\n",
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
	dma_free_coherent(dev, queue->ring_size * QDMA_MM_SW_DESC_SIZE,
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

	while (dev && !dev_is_pci(dev))
		dev = dev->parent;
	if (!dev) {
		qdma_err(qdev, "PCIe device not found\n");
		return -EINVAL;
	}

	ret = qdma_init_queue_context(qdev, queue->dir, queue->qid);
	if (ret)
		return ret;

	/**
	 * Descriptor ring size value must be at least 4k to support
	 * dma_alloc_coherent() type allocation.
	 */
	size = queue->ring_size * QDMA_MM_SW_DESC_SIZE;
	if (size < QDMA_MIN_DMA_ALLOC_SIZE) {
		qdma_err(qdev, "Invalid ring size\n");
		return -EINVAL;
	}

	queue->desc_base = dma_alloc_coherent(dev, size,
					      &queue->dma_desc_base,
					      GFP_KERNEL);
	if (!queue->desc_base) {
		qdma_err(qdev, "Failed to allocate descriptor ring\n");
		return -ENOMEM;
	}

	/* Setup SW descriptor queue context */
	desc.desc_base = queue->dma_desc_base;
	desc.mode = QDMA_QUEUE_OP_MM;
	desc.irq_en = ENABLE;
	desc.wbk_en = ENABLE;
	desc.desc_sz = QDMA_DESC_SIZE_32B;
	desc.rid = QDMA_PF_DEFAULT_RING_OFF;
	desc.wbi_intvl_en = ENABLE;
	desc.qen = ENABLE;

	ret = qdma_setup_queue_context(qdev, (union qdma_ctxt_data *)&desc,
				       queue->dir, queue->qid);
	if (ret) {
		qdma_err(qdev, "Failed to setup SW descriptor context for %s\n",
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
		qdma_err(qdev,
			 "Failed to get IO resource and remap it with error %d\n",
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

	ret = qdma_get_hw_queue_count(qdev, &qcount);
	if (ret)
		goto failed;

	if (pdata->max_dma_queues > qcount) {
		qdma_err(qdev,
			 "Max DMA queue count exceeds hardware supported limit\n");
		goto failed;
	}

	qdev->h2c_qnum = pdata->max_dma_queues;
	qdev->c2h_qnum = pdata->max_dma_queues;

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

	qdma_info(qdev, "AMD QDMA driver probed\n");

	return 0;

dev_tear:
	qdma_device_teardown(qdev);
failed:
	qdma_err(qdev, "Failed to probe AMD QDMA driver\n");
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
