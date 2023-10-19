/*
 * Copyright (C) 2023, Xilinx Inc
 *
 * Licensed under Apache License 2.0 or General Public License 2.0
 *
 * Header file for Accelerated FPGA Versal Boards
 */

#ifndef __VMGMT_COMMON_H
#define __VMGMT_COMMON_H

struct pci_dev;
struct vmr_drvdata;

enum log_type {
	LT_VMR_BASIC = 0,
	LT_VMR_VERBOSE,
	LT_VMR_LOG,
	LT_PLM_LOG,
	LT_APU_LOG,
	LT_VMR_DBG_LEVEL,
};

void vmgmt_reset_pci(struct pci_dev *pdev);

int vmgmt_log_buf_get(struct vmr_drvdata *vmr, enum log_type, char **buf, u32 *len);
int vmgmt_log_val_set(struct vmr_drvdata *vmr, enum log_type, u32 val);

/*
 * vmgmt internal functions in vmgmt_internal.c.
 * these code will not be opensourced, skip checkpatch
 */
void* vmgmt_debugfs_init(struct vmr_drvdata *vmr, const char *root_name);
void vmgmt_debugfs_fini(void *debugfs_root);

#endif

