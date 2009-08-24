#ifndef _ASM_X86_XEN_PCI_H
#define _ASM_X86_XEN_PCI_H

#ifdef CONFIG_XEN_DOM0_PCI
int xen_register_gsi(u32 gsi, int triggering, int polarity);
int xen_create_msi_irq(struct pci_dev *dev,
			struct msi_desc *msidesc,
			int type);
int xen_destroy_irq(int irq);
#else
static inline int xen_register_gsi(u32 gsi, int triggering, int polarity)
{
	return -1;
}

static inline int xen_create_msi_irq(struct pci_dev *dev,
				struct msi_desc *msidesc,
				int type)
{
	return -1;
}
static inline int xen_destroy_irq(int irq)
{
	return -1;
}
#endif

#if defined(CONFIG_PCI_MSI) && defined(CONFIG_XEN_DOM0_PCI)
int xen_setup_msi_irqs(struct pci_dev *dev, int nvec, int type);
#else
static inline int xen_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	return -1;
}
#endif

#endif	/* _ASM_X86_XEN_PCI_H */
