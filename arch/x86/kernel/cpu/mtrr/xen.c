#include <linux/init.h>
#include <linux/mm.h>

#include "mtrr.h"

#include <xen/interface/platform.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>

static int __init xen_num_var_ranges(void)
{
	int ranges;
	struct xen_platform_op op;

	op.cmd = XENPF_read_memtype;

	for (ranges = 0; ; ranges++) {
		op.u.read_memtype.reg = ranges;
		if (HYPERVISOR_dom0_op(&op) != 0)
			break;
	}
	return ranges;
}

/*
 * DOM0 TODO: Need to fill in the remaining mtrr methods to have full
 * working userland mtrr support.
 */
static struct mtrr_ops xen_mtrr_ops = {
	.vendor            = X86_VENDOR_UNKNOWN,
	.get_free_region   = generic_get_free_region,
	.have_wrcomb       = positive_have_wrcomb,
	.use_intel_if	   = 0,
	.num_var_ranges	   = xen_num_var_ranges,
};

void __init xen_init_mtrr(void)
{
	/* 
	 * Check that we're running under Xen, and privileged enough
	 * to play with MTRRs.
	 */
	if (!xen_initial_domain())
		return;

	/* 
	 * Check that the CPU has an MTRR implementation we can
	 * support.
	 */
	if (cpu_has_mtrr ||
	    cpu_has_k6_mtrr ||
	    cpu_has_cyrix_arr ||
	    cpu_has_centaur_mcr)
		mtrr_if = &xen_mtrr_ops;
}
