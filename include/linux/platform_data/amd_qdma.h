/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef _PLATDATA_AMD_QDMA_H
#define _PLATDATA_AMD_QDMA_H

#include <linux/dmaengine.h>

/**
 * struct qdma_queue_info - DMA queue information
 *	This information is used to match queue when request dma channel
 * @dir: Channel transfer direction
 */
struct qdma_queue_info {
	enum dma_transfer_direction dir;
};

#define QDMA_FILTER_PARAM(qinfo)	((void *)(qinfo))

struct dma_slave_map;

/**
 * struct qdma_platdata - platform specific data for QDMA engine
 * @max_dma_queues: Maximum dma queues in each direction
 */
struct qdma_platdata {
	u32 max_dma_queues;
	u32 device_map_cnt;
	struct dma_slave_map *device_map;
};

#endif /* _PLATDATA_AMD_QDMA_H */
