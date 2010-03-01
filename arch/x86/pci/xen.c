/*
 * Xen PCI Frontend Stub - puts some "dummy" functions in to the Linux
 * 			   x86 PCI core to support the Xen PCI Frontend
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/acpi.h>

#include <asm/io.h>
#include <asm/pci_x86.h>

#include <asm/xen/hypervisor.h>

#include <xen/events.h>
#include <asm/xen/pci.h>

#if defined(CONFIG_PCI_MSI)
struct xen_pci_frontend_ops *xen_pci_frontend;
EXPORT_SYMBOL_GPL(xen_pci_frontend);
#endif

static int xen_pcifront_enable_irq(struct pci_dev *dev)
{
	int rc;
	int share = 1;

	dev_info(&dev->dev, "Xen PCI enabling IRQ: %d\n", dev->irq);

	if (dev->irq < 0)
		return -EINVAL;

	if (dev->irq < NR_IRQS_LEGACY)
		share = 0;

	rc = xen_allocate_pirq(dev->irq, share, "pcifront");
	if (rc < 0) {
		dev_warn(&dev->dev, "Xen PCI IRQ: %d, failed to register:%d\n",
			 dev->irq, rc);
		return rc;
	}
	return 0;
}

int __init pci_xen_init(void)
{
	if (!xen_pv_domain() || xen_initial_domain())
		return -ENODEV;

	printk(KERN_INFO "PCI: setting up Xen PCI frontend stub\n");

	pcibios_set_cache_line_size();

	pcibios_enable_irq = xen_pcifront_enable_irq;
	pcibios_disable_irq = NULL;

#ifdef CONFIG_ACPI
	/* Keep ACPI out of the picture */
	acpi_noirq = 1;
#endif

#ifdef CONFIG_ISAPNP
	/* Stop isapnp from probing */
	isapnp_disable = 1;
#endif

	/* Ensure a device still gets scanned even if it's fn number
	 * is non-zero.
	 */
	pci_scan_all_fns = 1;

	return 0;
}

