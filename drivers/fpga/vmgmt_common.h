/*
 * Copyright (C) 2023, Xilinx Inc
 *
 * Licensed under Apache License 2.0 or General Public License 2.0
 *
 * Header file for Accelerated FPGA Versal Boards
 */

#ifndef __VMGMT_RESET_H
#define __VMGMT_RESET_H

struct pci_dev;

void vmgmt_reset_pci(struct pci_dev *pdev);

#endif

