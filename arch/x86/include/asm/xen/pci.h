#ifndef _ASM_X86_XEN_PCI_H
#define _ASM_X86_XEN_PCI_H

#ifdef CONFIG_XEN_DOM0_PCI
int xen_register_gsi(u32 gsi, int triggering, int polarity);
#else
static inline int xen_register_gsi(u32 gsi, int triggering, int polarity)
{
	return -1;
}
#endif

#endif	/* _ASM_X86_XEN_PCI_H */
