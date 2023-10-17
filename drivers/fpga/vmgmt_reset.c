// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Versal PCIe device
 *
 * Copyright (C) 2023 AMD Corporation, Inc.
 */
#include <linux/pci.h>
#include <linux/delay.h>

#include "vmgmt_common.h"

struct saved_data {
	u32	saved_config[8][16]; /* save config for pci reset */
};

static int xocl_wait_pci_status(struct pci_dev *pdev, u16 mask, u16 val, int timeout)
{
	u16     pci_cmd;
	int     i;

	if (!timeout)
		timeout = 5000;
	else
		timeout *= 1000;

	for (i = 0; i < timeout; i++) {
		pci_read_config_word(pdev, PCI_COMMAND, &pci_cmd);
		if (pci_cmd != 0xffff && (pci_cmd & mask) == val)
			break;
		usleep_range(1000, 1001);
	}

	pr_info("waiting for %d ms\n", i);
	if (i == timeout)
		return -ETIME;

	return 0;
}

static void xocl_save_config_space(struct pci_dev *pdev, u32 *saved_config)
{
	int i;

	for (i = 0; i < 16; i++)
		pci_read_config_dword(pdev, i * 4, &saved_config[i]);
}

#define XOCL_DEV_ID(pdev)                       \
	((pci_domain_nr(pdev->bus) << 16) |     \
	PCI_DEVID(pdev->bus->number, pdev->devfn))

static int xocl_match_slot_and_save(struct device *dev, void *data)
{
	struct saved_data *sdata = data;
	struct pci_dev *pdev;

	pdev = to_pci_dev(dev);

	pci_cfg_access_lock(pdev);
	pci_save_state(pdev);
	xocl_save_config_space(pdev, sdata->saved_config[PCI_FUNC(pdev->devfn)]);

	return 0;
}

static void xocl_restore_config_space(struct pci_dev *pdev, u32 *config_saved)
{
	int i;
	u32 val;

	for (i = 0; i < 16; i++) {
		pci_read_config_dword(pdev, i * 4, &val);
		if (val == config_saved[i])
			continue;

		pci_write_config_dword(pdev, i * 4, config_saved[i]);
		pci_read_config_dword(pdev, i * 4, &val);
		if (val != config_saved[i])
			pr_info("restore config at %d failed\n", i * 4);
	}
}

static int xocl_match_slot_and_restore(struct device *dev, void *data)
{
	struct saved_data *sdata = data;
	struct pci_dev *pdev;

	pdev = to_pci_dev(dev);

	xocl_restore_config_space(pdev, sdata->saved_config[PCI_FUNC(pdev->devfn)]);
	pci_restore_state(pdev);
	pci_cfg_access_unlock(pdev);

	return 0;
}

void vmgmt_reset_pci(struct pci_dev *pdev)
{
	struct pci_bus *bus;
	u16 slot_ctrl_orig = 0, slot_ctrl;
	u8 pci_bctl;
	u16 pci_cmd, devctl;
	struct saved_data sdata = { 0 };

	/*TODO: pci_save_config_all */
	bus_for_each_dev(&pci_bus_type, NULL, &sdata, xocl_match_slot_and_save);

	pci_disable_device(pdev);
	bus = pdev->bus;

	pcie_capability_read_word(bus->self, PCI_EXP_SLTCTL, &slot_ctrl);
	if (slot_ctrl != (u16)~0) {
		slot_ctrl_orig = slot_ctrl;
		slot_ctrl &= ~(PCI_EXP_SLTCTL_HPIE);
		pcie_capability_write_word(bus->self, PCI_EXP_SLTCTL, slot_ctrl);
	}
	/*
	 * When flipping the SBR bit, device can fall off the bus. This is usually
	 * no problem at all so long as drivers are working properly after SBR.
	 * However, some systems complain bitterly when the device falls off the bus.
	 * Such as a Dell Servers, The iDRAC is totally independent from the
	 * operating system; it will still reboot the machine even if the operating
	 * system ignores the error.
	 * The quick solution is to temporarily disable the SERR reporting of
	 * switch port during SBR.
	 */
	pci_read_config_word(bus->self, PCI_COMMAND, &pci_cmd);
	pci_write_config_word(bus->self, PCI_COMMAND, (pci_cmd & ~PCI_COMMAND_SERR));
	pcie_capability_read_word(bus->self, PCI_EXP_DEVCTL, &devctl);
	pcie_capability_write_word(bus->self, PCI_EXP_DEVCTL, (devctl & ~PCI_EXP_DEVCTL_FERE));

	pci_read_config_byte(bus->self, PCI_BRIDGE_CONTROL, &pci_bctl);
	pci_bctl |= PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_byte(bus->self, PCI_BRIDGE_CONTROL, pci_bctl);

	if (!slot_ctrl_orig)
		pcie_capability_write_word(bus->self, PCI_EXP_SLTCTL, slot_ctrl_orig);

	msleep(100);
	pci_bctl &= ~PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_byte(bus->self, PCI_BRIDGE_CONTROL, pci_bctl);
	ssleep(1);

	pcie_capability_write_word(bus->self, PCI_EXP_DEVCTL, devctl);
	pci_write_config_word(bus->self, PCI_COMMAND, pci_cmd);

	if (pci_enable_device(pdev))
		pr_warn("failed to enable pci device\n");

	xocl_wait_pci_status(pdev, 0, 0, 0);

	bus_for_each_dev(&pci_bus_type, NULL, &sdata, xocl_match_slot_and_restore);

	/*TODO: config pci */
}
