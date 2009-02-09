#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/pci.h>

#include <asm/pci_x86.h>

#include <asm/xen/hypervisor.h>

#include <xen/interface/xen.h>
#include <xen/events.h>

#include "xen-ops.h"

int xen_register_gsi(u32 gsi, int triggering, int polarity)
{
	int irq;

	if (!xen_domain())
		return -1;

	printk(KERN_DEBUG "xen: registering gsi %u triggering %d polarity %d\n",
	       gsi, triggering, polarity);

	irq = xen_allocate_pirq(gsi);

	printk(KERN_DEBUG "xen: --> irq=%d\n", irq);

	return irq;
}

void __init xen_setup_pirqs(void)
{
#ifdef CONFIG_ACPI
	int irq;

	/*
	 * Set up acpi interrupt in acpi_gbl_FADT.sci_interrupt.
	 */
	irq = xen_allocate_pirq(acpi_gbl_FADT.sci_interrupt);

	printk(KERN_INFO "xen: allocated irq %d for acpi %d\n",
	       irq, acpi_gbl_FADT.sci_interrupt);

	/* Blerk. */
	acpi_gbl_FADT.sci_interrupt = irq;
#endif
}
