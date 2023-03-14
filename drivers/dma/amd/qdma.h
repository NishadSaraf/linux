/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * DMA header for AMD Queue-based DMA Subsystem
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef __QDMA_H
#define __QDMA_H

#include <linux/bitfield.h>
#include <linux/dmaengine.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include "../virt-dma.h"

#define ENABLE					1
#define DISABLE					0

#define QDMA_DEV_STATUS_REG_DMA			BIT(0)

#define QDMA_IDENTIFIER				0x1FD3

#define QDMA_PF_ADDR_SPACE_LEN			77824
#define QDMA_PF_DEFAULT_RING_SIZE		2048
#define QDMA_PF_DEFAULT_RING_OFF		0
#define QDMA_MIN_DMA_ALLOC_SIZE			4096

#define QDMA_PF_IDENTIFIER_MASK			GENMASK(31, 16)
#define QDMA_PF_IDENTIFIER_REGOFF		0x0

#define QDMA_PF_MAX_QUEUE_COUNT_REGOFF		0x120
#define QDMA_PF_MAX_QUEUE_COUNT_MASK		GENMASK(11, 0)

#define QDMA_PF_GLB_RING_COUNT			16
#define QDMA_PF_GLB_RING_SIZE_BASE_REGOFF	0x204
#define QDMA_PF_GLB_RING_SIZE_MASK		GENMASK(15, 0)

#define QDMA_PF_H2C_MM_CTRL_REGOFF		0x1204
#define QDMA_PF_C2H_MM_CTRL_REGOFF		0x1004
#define QDMA_PF_H2C_MM_CTRL_MASK		BIT(0)
#define QDMA_PF_C2H_MM_CTRL_MASK		BIT(0)

#define QDMA_MM_SW_DESC_SIZE			32		/* Bytes */
#define QDMA_MM_DESC_BLOCK_ALIGN		4096

#define QDMA_CTXT_BIT_LEN			256
#define QDMA_CTXT_REGMAP_LEN			8		/* 8, 32-bit regs*/
#define QDMA_CTXT_SW_DESC_QEN_LSB		32
#define QDMA_CTXT_SW_DESC_WBI_INTVL_EN_LSB	35
#define QDMA_CTXT_SW_DESC_DESC_RID_LSB		44
#define QDMA_CTXT_SW_DESC_DESC_SIZE_LSB		48
#define QDMA_CTXT_SW_DESC_WBK_EN_LSB		52
#define QDMA_CTXT_SW_DESC_IRQ_EN_LSB		53
#define QDMA_CTXT_SW_DESC_MODE_LSB		63
#define QDMA_CTXT_SW_DESC_DESC_BASE_LSB		64
#define QDMA_CTXT_SW_DESC_DESC_BASE_WIDTH	64
#define QDMA_CTXT_SW_DESC_DESC_SIZE_WIDTH	2
#define QDMA_CTXT_SW_DESC_DESC_RID_WIDTH	4

#define QDMA_PF_CTXT_DATA_REGOFF		0x804
#define QDMA_PF_CTXT_MASK_REGOFF		0x824
#define QDMA_PF_CTXT_CMD_REGOFF			0x844
#define QDMA_PF_CTXT_CMD_INDX_MASK		GENMASK(19, 7)
#define QDMA_PF_CTXT_CMD_CMD_MASK		GENMASK(6, 5)
#define QDMA_PF_CTXT_CMD_TYPE_MASK		GENMASK(4, 1)
#define QDMA_PF_CTXT_CMD_BUSY_MASK		BIT(0)
#define QDMA_PF_CTXT_CMD_POLL_INTRVL_US		10		/* 10us */
#define QDMA_PF_CTXT_CMD_POLL_TIMEOUT_US	(500 * 1000)	/* 500ms */
#define QDMA_PF_CTXT_CMD_POLL_COND(value)	(!((value) & QDMA_PF_CTXT_CMD_BUSY_MASK))

#define qdma_err(qdev, fmt, args...)					\
	dev_err(&(qdev)->pdev->dev, fmt, ##args)

#define qdma_info(qdev, fmt, args...)					\
	dev_info(&(qdev)->pdev->dev, fmt, ##args)

enum qdma_desc_size {
	QDMA_DESC_SIZE_8B,
	QDMA_DESC_SIZE_16B,
	QDMA_DESC_SIZE_32B,
	QDMA_DESC_SIZE_64B,
};

enum qdma_queue_op_mode {
	QDMA_QUEUE_OP_STREAM,
	QDMA_QUEUE_OP_MM,
};

enum qdma_ctxt_type {
	QDMA_CTXT_DESC_SW_C2H,
	QDMA_CTXT_DESC_SW_H2C,
	QDMA_CTXT_DESC_HW_C2H,
	QDMA_CTXT_DESC_HW_H2C,
	QDMA_CTXT_DESC_CR_C2H,
	QDMA_CTXT_DESC_CR_H2C,
};

enum qdma_ctxt_cmd {
	QDMA_CTXT_READ,
	QDMA_CTXT_WRITE,
	QDMA_CTXT_CLEAR,
	QDMA_CTXT_INVALIDATE,
	QDMA_CTXT_MAX
};

/**
 * qdma_ctxt_sw_dec - QDMA software descriptor context structure
 * @desc_base: descriptor rung base address
 * @mode: operating mode. 1: Memory Mapped 0: Stream
 * @irq_en: interrupt enable
 * @wbk_en: writeback enable
 * @desc_sz: descriptor fetch size
 * @rid: ring index
 * @wbi_intvl_en: write back/Interrupt interval.
 * @qen: queue enable
 */
struct qdma_ctxt_sw_dec {
	u64 desc_base;
	enum qdma_queue_op_mode mode;
	bool irq_en;
	bool wbk_en;
	enum qdma_desc_size desc_sz;
	u32 rid;
	bool wbi_intvl_en;
	bool qen;
};

/**
 * qdma_ctxt_data - QDMA context data union
 * @sw_desc: software descriptor context
 */
union qdma_ctxt_data {
	struct qdma_ctxt_sw_dec sw_desc;
};

/**
 * qdma_mm_sw_dec - software descriptor format structure
 * @src_addr - source address
 * @lenlo: lower 16-bits of length in bytes
 * @lenhi: higher 16-bits of length in bytes
 * @reserved1: reserved
 * @len: length in bytes
 * @dst_addr: destination address
 * @reserved2: reserved
 */
struct qdma_mm_sw_dec {
	__le64 src_addr;
	union {
		struct {
			__le16 lenlo;
			__le16 lenhi;
			__le32 reserved1;
		} __packed;
		__le64 len;
	};
	__le64 dst_addr;
	__le64 reserved2;
} __packed;

/**
 * struct qdma_queue - Driver specific DMA queue structure
 * @vchan: Virtual channel
 * @qdev: Pointer to DMA device structure
 * @dir: Transferring direction of the channel
 * @cfg: Transferring config of the channel
 * @desc_base: cpu descriptor ring base address
 * @dma_desc_base: dma descriptor ring base address
 * @ring_size: size of ring
 * @qid: queue index
 */
struct qdma_queue {
	struct virt_dma_chan		vchan;
	void				*qdev;
	enum dma_transfer_direction	dir;
	struct dma_slave_config		cfg;
	struct qdma_mm_sw_dec		*desc_base;
	dma_addr_t			dma_desc_base;
	u32				ring_size;
	u16				qid;
};

/**
 * struct qdma_device - DMA device structure
 * @pdev: Platform device pointer
 * @dma_dev: DMA device structure
 * @regmap: MMIO regmap for DMA registers
 * @h2c_queues: Host to Card queues
 * @c2h_queues: Card to Host queues
 * @h2c_qnum: Number of H2C queues
 * @c2h_qnum: Number of C2H queues
 * @mm_h2c_enable: MM H2C engine enable
 * @mm_c2h_enable: MM C2H engine enable
 * @status: Initialization status
 */
struct qdma_device {
	struct platform_device	*pdev;
	struct dma_device	dma_dev;
	struct regmap		*regmap;
	struct qdma_queue	*h2c_queues;
	struct qdma_queue	*c2h_queues;
	u32			h2c_qnum;
	u32			c2h_qnum;
	bool			mm_h2c_enable;
	bool			mm_c2h_enable;
	u32			status;
};

#endif	/* __QDMA_H */
