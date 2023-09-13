/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Header file for Versal PCIe device user API
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 */

#ifndef _UAPI_LINUX_VMGMT_H
#define _UAPI_LINUX_VMGMT_H

#include <linux/ioctl.h>
#include <linux/xclbin.h>

#define VERSAL_MGMT_MAGIC	0xB7
#define VERSAL_MGMT_BASE	0

struct versal_mgmt_ioc_xclbin {
	struct axlf *xclbin;
};

#define VERSAL_MGMT_LOAD_XCLBIN_IOCTL	_IOW(VERSAL_MGMT_MAGIC,		\
					     VERSAL_MGMT_BASE + 0,	\
					     struct versal_mgmt_ioc_xclbin)

#define VERSAL_MGMT_PROGRAM_SHELL_IOCTL	_IOW(VERSAL_MGMT_MAGIC,		\
					     VERSAL_MGMT_BASE + 1,	\
					     struct versal_mgmt_ioc_xclbin)

#endif /* _UAPI_LINUX_VMGMT_H */
