#ifndef _XEN_ACPI_H
#define _XEN_ACPI_H

#include <linux/types.h>

#ifdef CONFIG_XEN_S3
#include <asm/xen/hypervisor.h>
#include <xen/xen.h>

static inline bool xen_pv_acpi(void)
{
	return xen_pv_domain();
}
#else
static inline bool xen_pv_acpi(void)
{
	return false;
}
#endif

int acpi_notify_hypervisor_state(u8 sleep_state,
				 u32 pm1a_cnt, u32 pm1b_cnd);

#endif	/* _XEN_ACPI_H */
