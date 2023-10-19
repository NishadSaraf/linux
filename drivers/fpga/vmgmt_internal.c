// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Versal PCIe device
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 */
#include <linux/debugfs.h>
#include <linux/vmalloc.h>

#include "vmgmt_common.h"

#define _DBGFS_FOPS_RW(_open, _write)	\
{ 					\
	.owner = THIS_MODULE,		\
	.open = _open,			\
	.read = seq_read,		\
	.llseek = seq_lseek,		\
	.release = single_release,	\
	.write = _write,		\
}

#define DBGFS_FOPS_RW(_name, _show, _write) \
static int dbgfs_##_name##_open(struct inode *inode, struct file *file) \
{ 									\
	return single_open(file, _show, inode->i_private); 		\
} 									\
const struct file_operations fops_##_name = 				\
	_DBGFS_FOPS_RW(dbgfs_##_name##_open, _write)

#define DBGFS_FILE(_name, _mode) { #_name, &fops_##_name, _mode }

#define file_to_vmr(file) \
	(((struct seq_file *)(file)->private_data)->private)

#define seq_file_to_vmr(m) \
	((m)->private)

static ssize_t vmr_debug_level_write(struct file *file, const char __user *ptr,
				     size_t len, loff_t *off)
{
	struct vmr_drvdata *vmr = file_to_vmr(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		pr_err("Invalid input ret: %d", ret);
		return ret;
	}

	pr_info("debug level: %d", val);

	if (val > 3) {
		pr_err("debug level should be 0 - 3");
		return -EINVAL;
	}

	vmgmt_log_val_set(vmr, LT_VMR_DBG_LEVEL, val);

	return len;
}

static int vmr_debug_level_show(struct seq_file *m, void *unused)
{
	struct vmr_drvdata *vmr = seq_file_to_vmr(m);
	char *buf;
	u32 len;
	int ret;

	ret = vmgmt_log_buf_get(vmr, LT_VMR_DBG_LEVEL, &buf, &len);
	if (ret) {
		pr_err("ret: %d", ret);
		return ret;
	}
	seq_printf(m, "%s", buf);
	vfree(buf);

	return 0;
}
DBGFS_FOPS_RW(vmr_debug_level, vmr_debug_level_show, vmr_debug_level_write);

static ssize_t vmr_log_write(struct file *file, const char __user *ptr,
				     size_t len, loff_t *off)
{
	pr_err("do not support write to vmr_log.");
	return -EINVAL;
}

static int vmr_log_show(struct seq_file *m, void *unused)
{
	struct vmr_drvdata *vmr = seq_file_to_vmr(m);
	char *buf;
	u32 len;
	int ret;

	ret = vmgmt_log_buf_get(vmr, LT_VMR_LOG, &buf, &len);
	if (ret) {
		pr_err("ret: %d", ret);
		return ret;
	}
	seq_write(m, buf, len);
	vfree(buf);

	return 0;
}
DBGFS_FOPS_RW(vmr_log, vmr_log_show, vmr_log_write);

static const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} dbgfs_list[] = {
	DBGFS_FILE(vmr_log, 0400),
	/*
	DBGFS_FILE(plm_log, 0400),
	DBGFS_FILE(apu_log, 0400),
	DBGFS_FILE(vmr_verbose_info, 0400),
	DBGFS_FILE(vmr_status, 0400),
	*/
	DBGFS_FILE(vmr_debug_level, 0400),
};

void* vmgmt_debugfs_init(struct vmr_drvdata *vmr, const char *root_name)
{
	struct dentry *debugfs_root;

	debugfs_root = debugfs_create_dir(root_name, NULL);
	if (IS_ERR(debugfs_root) || !debugfs_root) {
		pr_warn("failed to create debugfs directory %s\n", root_name);
		return NULL;
	}

	for (int i = 0; i < ARRAY_SIZE(dbgfs_list); i++) {
		debugfs_create_file(dbgfs_list[i].name,
				    dbgfs_list[i].mode,
				    debugfs_root, vmr,
				    dbgfs_list[i].fops);
	}

	return (void *)debugfs_root;
}

void vmgmt_debugfs_fini(void *debugfs_root)
{
	if (debugfs_root)
		debugfs_remove_recursive((struct dentry *)debugfs_root);
}
