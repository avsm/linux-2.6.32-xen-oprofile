#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>

#include <asm/io_apic.h>
#include <asm/acpi.h>

#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>

#include <xen/interface/xen.h>
#include <xen/interface/physdev.h>

void __init xen_io_apic_init(void)
{
}

unsigned int xen_io_apic_read(unsigned apic, unsigned reg)
{
	struct physdev_apic apic_op;
	int ret;

	apic_op.apic_physbase = mp_ioapics[apic].apicaddr;
	apic_op.reg = reg;
	ret = HYPERVISOR_physdev_op(PHYSDEVOP_apic_read, &apic_op);
	if (ret)
		BUG();
	return apic_op.value;
}


void xen_io_apic_write(unsigned int apic, unsigned int reg, unsigned int value)
{
	struct physdev_apic apic_op;

	apic_op.apic_physbase = mp_ioapics[apic].apicaddr;
	apic_op.reg = reg;
	apic_op.value = value;
	if (HYPERVISOR_physdev_op(PHYSDEVOP_apic_write, &apic_op))
		BUG();
}

void xen_init_apic(void)
{
	if (!xen_initial_domain())
		return;

#ifdef CONFIG_ACPI
	/*
	 * Pretend ACPI found our lapic even though we've disabled it,
	 * to prevent MP tables from setting up lapics.
	 */
	acpi_lapic = 1;
#endif
}
