/******************************************************************************
 * platform-pci.c
 *
 * Xen platform PCI device driver
 * Copyright (c) 2005, Intel Corporation.
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2010, Citrix
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <asm/io.h>

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>

#include <xen/grant_table.h>
#include <xen/platform_pci.h>
#include <xen/interface/platform_pci.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/hvm.h>
#include <xen/xen-ops.h>

#define DRV_NAME    "xen-platform-pci"

MODULE_AUTHOR("ssmith@xensource.com and stefano.stabellini@eu.citrix.com");
MODULE_DESCRIPTION("Xen platform PCI device");
MODULE_LICENSE("GPL");

static unsigned long platform_mmio;
static unsigned long platform_mmio_alloc;
static unsigned long platform_mmiolen;
static uint64_t callback_via;
struct pci_dev *xen_platform_pdev;

unsigned long alloc_xen_mmio(unsigned long len)
{
	unsigned long addr;

	addr = platform_mmio + platform_mmio_alloc;
	platform_mmio_alloc += len;
	BUG_ON(platform_mmio_alloc > platform_mmiolen);

	return addr;
}

static uint64_t get_callback_via(struct pci_dev *pdev)
{
	u8 pin;
	int irq;

	irq = pdev->irq;
	if (irq < 16)
		return irq; /* ISA IRQ */

	pin = pdev->pin;

	/* We don't know the GSI. Specify the PCI INTx line instead. */
	return ((uint64_t)0x01 << 56) | /* PCI INTx identifier */
		((uint64_t)pci_domain_nr(pdev->bus) << 32) |
		((uint64_t)pdev->bus->number << 16) |
		((uint64_t)(pdev->devfn & 0xff) << 8) |
		((uint64_t)(pin - 1) & 3);
}

static irqreturn_t do_hvm_evtchn_intr(int irq, void *dev_id)
{
	xen_hvm_evtchn_do_upcall(get_irq_regs());
	return IRQ_HANDLED;
}

static int xen_allocate_irq(struct pci_dev *pdev)
{
	__set_irq_handler(pdev->irq, handle_edge_irq, 0, NULL);
	return request_irq(pdev->irq, do_hvm_evtchn_intr,
			IRQF_DISABLED | IRQF_NOBALANCING | IRQF_TRIGGER_RISING,
			"xen-platform-pci", pdev);
}

void platform_pci_disable_irq(void)
{
	printk(KERN_DEBUG "platform_pci_disable_irq\n");
	disable_irq(xen_platform_pdev->irq);
}

void platform_pci_enable_irq(void)
{
	printk(KERN_DEBUG "platform_pci_enable_irq\n");
	enable_irq(xen_platform_pdev->irq);
}

void platform_pci_resume(void)
{
	if (xen_set_callback_via(callback_via)) {
		printk("platform_pci_resume failure!\n");
		return;
	}
}

static int __devinit platform_pci_init(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int i, ret;
	long ioaddr, iolen;
	long mmio_addr, mmio_len;
	xen_platform_pdev = pdev;

	i = pci_enable_device(pdev);
	if (i)
		return i;

	ioaddr = pci_resource_start(pdev, 0);
	iolen = pci_resource_len(pdev, 0);

	mmio_addr = pci_resource_start(pdev, 1);
	mmio_len = pci_resource_len(pdev, 1);

	if (mmio_addr == 0 || ioaddr == 0) {
		dev_err(&pdev->dev, "no resources found\n");
		ret = -ENOENT;
	}

	if (request_mem_region(mmio_addr, mmio_len, DRV_NAME) == NULL) {
		dev_err(&pdev->dev, "MEM I/O resource 0x%lx @ 0x%lx busy\n",
		       mmio_addr, mmio_len);
		ret = -EBUSY;
	}

	if (request_region(ioaddr, iolen, DRV_NAME) == NULL) {
		dev_err(&pdev->dev, "I/O resource 0x%lx @ 0x%lx busy\n",
		       iolen, ioaddr);
		ret = -EBUSY;
		goto out;
	}

	platform_mmio = mmio_addr;
	platform_mmiolen = mmio_len;

	if (!xen_have_vector_callback) {
		ret = xen_allocate_irq(pdev);
		if (ret) {
			printk(KERN_WARNING "request_irq failed err=%d\n", ret);
			goto out;
		}
		callback_via = get_callback_via(pdev);
		ret = xen_set_callback_via(callback_via);
		if (ret) {
			printk(KERN_WARNING
					"Unable to set the evtchn callback err=%d\n", ret);
			goto out;
		}
	}
	ret = gnttab_init();
	if (ret)
		goto out;
	ret = xenbus_probe_init();
	if (ret)
		goto out;
	ret = xen_setup_shutdown_event();
	if (ret)
		goto out;


out:
	if (ret) {
		release_mem_region(mmio_addr, mmio_len);
		release_region(ioaddr, iolen);
		pci_disable_device(pdev);
	}

	return ret;
}

#define XEN_PLATFORM_VENDOR_ID 0x5853
#define XEN_PLATFORM_DEVICE_ID 0x0001
static struct pci_device_id platform_pci_tbl[] __devinitdata = {
	{XEN_PLATFORM_VENDOR_ID, XEN_PLATFORM_DEVICE_ID,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, platform_pci_tbl);

static struct pci_driver platform_driver = {
	name:     DRV_NAME,
	probe :    platform_pci_init,
	id_table : platform_pci_tbl,
};

static int check_platform_magic(void)
{
	short magic;
	char protocol, *err;

	magic = inw(XEN_IOPORT_MAGIC);

	if (magic != XEN_IOPORT_MAGIC_VAL) {
		err = "unrecognised magic value";
		goto no_dev;
	}

	protocol = inb(XEN_IOPORT_PROTOVER);

	printk(KERN_DEBUG DRV_NAME "I/O protocol version %d\n", protocol);

	switch (protocol) {
	case 1:
		outw(XEN_IOPORT_LINUX_PRODNUM, XEN_IOPORT_PRODNUM);
		outl(XEN_IOPORT_LINUX_DRVVER, XEN_IOPORT_DRVVER);
		if (inw(XEN_IOPORT_MAGIC) != XEN_IOPORT_MAGIC_VAL) {
			printk(KERN_ERR DRV_NAME "blacklisted by host\n");
			return -ENODEV;
		}
		break;
	default:
		err = "unknown I/O protocol version";
		goto no_dev;
	}

	return 0;

 no_dev:
	printk(KERN_WARNING DRV_NAME  "failed backend handshake: %s\n", err);
	return -ENODEV;
}

static int __init platform_pci_module_init(void)
{
	int rc;

	rc = check_platform_magic();
	if (rc < 0)
		return rc;

	rc = pci_register_driver(&platform_driver);
	if (rc) {
		printk(KERN_INFO DRV_NAME
		       ": No platform pci device model found\n");
		return rc;
	}

	return 0;
}

module_init(platform_pci_module_init);
