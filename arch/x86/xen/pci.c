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

	irq = xen_allocate_pirq(gsi, (triggering == ACPI_EDGE_SENSITIVE)
				     ? "ioapic-edge" : "ioapic-level");

	printk(KERN_DEBUG "xen: --> irq=%d\n", irq);

	if (irq >= 0)
		xen_set_io_apic_routing(irq,
					triggering == ACPI_EDGE_SENSITIVE ? 0 : 1,
					polarity == ACPI_ACTIVE_HIGH ? 0 : 1);

	return irq;
}

void __init xen_setup_pirqs(void)
{
	int irq;

	/* Pre-allocate legacy irqs */
	for (irq=0; irq < NR_IRQS_LEGACY; irq++) {
		int trigger, polarity;

		if (acpi_get_override_irq(irq, &trigger, &polarity) == -1)
			continue;

		xen_register_gsi(irq,
			trigger ? ACPI_LEVEL_SENSITIVE : ACPI_EDGE_SENSITIVE,
			polarity ? ACPI_ACTIVE_LOW : ACPI_ACTIVE_HIGH);
	}
}
