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
#define QDMA_PF_DEFAULT_RING_SIZE		1025
#define QDMA_PF_DEFAULT_RING_ID			0
#define QDMA_PF_POLL_INTRVL_US			10		/* 10us */
#define QDMA_PF_POLL_TIMEOUT_US			(500 * 1000)	/* 500ms */
#define QDMA_CTXT_REGMAP_LEN			8		/* 8, 32-bit regs */
#define QDMA_MM_DESC_SIZE			32		/* Bytes */
#define QDMA_MIN_DMA_ALLOC_SIZE			4096

#define QDMA_PF_IDENTIFIER_REGOFF		0x0
#define QDMA_PF_INST_TYPE_REGOFF		0x10
#define QDMA_PF_IDENTIFIER_MASK			GENMASK(31, 16)
#define QDMA_PF_INST_TYPE_MASK			BIT(16)

#define qdma_err(qdev, fmt, args...)					\
	dev_err(&(qdev)->pdev->dev, fmt, ##args)

#define qdma_info(qdev, fmt, args...)					\
	dev_info(&(qdev)->pdev->dev, fmt, ##args)

enum qdma_field_width {
	QDMA_REGF_WIDTH_32,
	QDMA_REGF_WIDTH_64
};

enum qdma_reg_fields {
	QDMA_REGF_IRQ_ENABLE,
	QDMA_REGF_WBK_ENABLE,
	QDMA_REGF_WBI_INTVL_ENABLE,
	QDMA_REGF_QUEUE_ENABLE,
	QDMA_REGF_QUEUE_MODE,
	QDMA_REGF_DESC_BASE,
	QDMA_REGF_DESC_SIZE,
	QDMA_REGF_RING_ID,
	QDMA_REGF_CMD_INDX,
	QDMA_REGF_CMD_CMD,
	QDMA_REGF_CMD_TYPE,
	QDMA_REGF_CMD_BUSY,
	QDMA_REGF_MM_H2C_CTRL,
	QDMA_REGF_MM_C2H_CTRL,
	QDMA_REGF_QUEUE_COUNT,
	QDMA_REGF_RING_SIZE,
	QDMA_REGF_MAX
};

enum qdma_reg_offs {
	QDMA_REGO_CTXT_DATA,
	QDMA_REGO_CTXT_CMD,
	QDMA_REGO_CTXT_MASK,
	QDMA_REGO_MM_H2C_CTRL,
	QDMA_REGO_MM_C2H_CTRL,
	QDMA_REGO_QUEUE_COUNT,
	QDMA_REGO_RING_SIZE,
	QDMA_REGO_MAX
};

/**
 * struct qdma_reg_field - QDMA register field
 * @lsb: least significant bit of field
 * @msb: most significant bit of field
 * @width: addressing field width
 * @regoff: register offset index
 */
struct qdma_reg_field {
	u16 lsb;
	u16 msb;
	enum qdma_field_width width;
	enum qdma_reg_offs regoff;
};

/**
 * struct qdma_reg_off - QDMA reigster offset
 * @offset: register offset into MMIO space
 * @len: length of the register
 */
struct qdma_reg_off {
	u32 offset;
	u32 len;
};

#define QDMA_U32_OFF(_value)			((_value) / BITS_PER_TYPE(u32))
#define QDMA_U32_BIT_OFF(_value)		((_value) % BITS_PER_TYPE(u32))
#define QDMA_U64_BIT_OFF(_value)		((_value) % BITS_PER_TYPE(u64))

#define QDMA_REGF_MASK(_msb, _lsb)					\
		GENMASK(QDMA_U32_BIT_OFF(_msb), QDMA_U32_BIT_OFF(_lsb)) \

#define QDMA_REGF_MASK_ULL(_msb, _lsb)					\
		GENMASK_ULL(QDMA_U64_BIT_OFF(_msb), QDMA_U64_BIT_OFF(_lsb))

#define QDMA_REGF(_regoff, _msb, _lsb) {				\
	.regoff = (_regoff),						\
	.lsb = (_lsb),							\
	.msb = (_msb),							\
	.width = QDMA_REGF_WIDTH_32,					\
}

#define QDMA_REGF_ULL(_regoff, _msb, _lsb) {				\
	.regoff = (_regoff),						\
	.lsb = (_lsb),							\
	.msb = (_msb),							\
	.width = QDMA_REGF_WIDTH_64,					\
}

#define QDMA_REGO(_off, _len) {						\
	.offset = (_off),						\
	.len = (_len),							\
}

enum qdma_inst_type {
	QDMA_SOFT_IP,
	QDMA_HARD_IP,
};

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
 * struct qdma_ctxt_sw_dec - QDMA software descriptor context
 * @rid: ring index
 * @desc_base: descriptor rung base address
 * @desc_sz: descriptor fetch size
 * @mode: operating mode. 1: Memory Mapped 0: Stream
 * @qen: queue enable
 * @irq_en: interrupt enable
 * @wbk_en: writeback enable
 * @wbi_intvl_en: write back/interrupt interval.
 */
struct qdma_ctxt_sw_dec {
	u32				rid;
	u64				desc_base;
	enum qdma_desc_size		desc_sz;
	enum qdma_queue_op_mode		mode;
	bool				qen;
	bool				irq_en;
	bool				wbk_en;
	bool				wbi_intvl_en;
};

/**
 * union qdma_ctxt_data - QDMA context data union
 * @sw_desc: software descriptor context
 */
union qdma_ctxt_data {
	struct qdma_ctxt_sw_dec sw_desc;
};

struct qdma_device;

/**
 * struct qdma_mm_desc - MM DMA descriptor format
 * @src_addr: source address
 * @len: length in bytes
 * @data: placeholder for hardware compatible struct packing
 * @reserved1: reserved
 * @len: length in bytes
 * @dst_addr: destination address
 * @reserved2: reserved
 */
struct qdma_mm_desc {
	__le64			src_addr;
	union {
		struct {
			__le32	len;
			__le32	reserved1;
		} __packed;
		__le64		data;
	};
	__le64			dst_addr;
	__le64			reserved2;
} __packed;

/**
 * struct qdma_queue - Driver specific DMA queue structure
 * @vchan: virtual channel
 * @qdev: pointer to DMA device structure
 * @dir: transferring direction of the queue
 * @cfg: transferring config of the queue
 * @desc_base: cpu descriptor ring base address
 * @dma_desc_base: dma descriptor ring base address
 * @ring_size: size of ring
 * @qid: queue index
 */
struct qdma_queue {
	struct virt_dma_chan		vchan;
	struct qdma_device		*qdev;
	enum dma_transfer_direction	dir;
	struct dma_slave_config		cfg;
	struct qdma_mm_desc		*desc_base;
	dma_addr_t			dma_desc_base;
	u32				ring_size;
	u16				qid;
};

/**
 * struct qdma_device - DMA device structure
 * @pdev: platform device pointer
 * @dma_dev: DMA device structure
 * @regmap: MMIO regmap for DMA registers
 * @rfields: pointer to an array of register fields
 * @roffs: pointer to an array of register offsets
 * @h2c_queues: host to Card queues
 * @c2h_queues: card to Host queues
 * @h2c_qnum: number of H2C queues
 * @c2h_qnum: number of C2H queues
 * @mm_h2c_enable: MM H2C engine enable
 * @mm_c2h_enable: MM C2H engine enable
 * @status: initialization status
 */
struct qdma_device {
	struct platform_device		*pdev;
	struct dma_device		dma_dev;
	struct regmap			*regmap;
	const struct qdma_reg_field	*rfields;
	const struct qdma_reg_off	*roffs;
	struct qdma_queue		*h2c_queues;
	struct qdma_queue		*c2h_queues;
	u32				h2c_qnum;
	u32				c2h_qnum;
	bool				mm_h2c_enable;
	bool				mm_c2h_enable;
	u32				status;
};

#endif	/* __QDMA_H */
