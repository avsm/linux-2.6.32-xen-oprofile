#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/pci.h>

#include <asm/mpspec.h>
#include <asm/io_apic.h>
#include <asm/pci_x86.h>

#include <asm/xen/hypervisor.h>

#include <xen/interface/xen.h>
#include <xen/events.h>

#include "xen-ops.h"

static void xen_set_io_apic_routing(int irq, int trigger, int polarity)
{
	int ioapic, ioapic_pin;
	int vector, gsi;
	struct IO_APIC_route_entry entry;

	gsi = xen_gsi_from_irq(irq);
	vector = xen_vector_from_irq(irq);

	ioapic = mp_find_ioapic(gsi);
	if (ioapic == -1) {
		printk(KERN_WARNING "xen_set_ioapic_routing: irq %d gsi %d ioapic %d\n",
			irq, gsi, ioapic);
		return;
	}

	ioapic_pin = mp_find_ioapic_pin(ioapic, gsi);

	printk(KERN_INFO "xen_set_ioapic_routing: irq %d gsi %d vector %d ioapic %d pin %d triggering %d polarity %d\n",
		irq, gsi, vector, ioapic, ioapic_pin, trigger, polarity);

	setup_ioapic_entry(ioapic, -1, &entry, ~0, trigger, polarity, vector,
			   ioapic_pin);
	ioapic_write_entry(ioapic, ioapic_pin, entry);
}

int xen_register_gsi(u32 gsi, int triggering, int polarity)
{
	int irq;

	if (!xen_domain())
		return -1;

	printk(KERN_DEBUG "xen: registering gsi %u triggering %d polarity %d\n",
	       gsi, triggering, polarity);

	irq = xen_allocate_pirq(gsi);

	printk(KERN_DEBUG "xen: --> irq=%d\n", irq);

	if (irq > 0)
		xen_set_io_apic_routing(irq,
					triggering == ACPI_EDGE_SENSITIVE ? 0 : 1,
					polarity == ACPI_ACTIVE_HIGH ? 0 : 1);

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
