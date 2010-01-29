/* TODO: Copyright header. */


#include <linux/dma-mapping.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/scatterlist.h>
#include <xen/interface/xen.h>
#include <xen/grant_table.h>

#include <asm/xen/page.h>
#include <xen/page.h>
#include <xen/xen-ops.h>


static dma_addr_t xen_phys_to_bus(struct device *hwdev, phys_addr_t paddr)
{
	return phys_to_machine(XPADDR(paddr)).maddr;;
}

static phys_addr_t xen_bus_to_phys(struct device *hwdev, dma_addr_t baddr)
{
	return machine_to_phys(XMADDR(baddr)).paddr;
}

static dma_addr_t xen_virt_to_bus(struct device *hwdev,
				  void *address)
{
	return xen_phys_to_bus(hwdev, virt_to_phys(address));
}

static int check_pages_physically_contiguous(unsigned long pfn,
					     unsigned int offset,
					     size_t length)
{
	unsigned long next_mfn;
	int i;
	int nr_pages;

	next_mfn = pfn_to_mfn(pfn);
	nr_pages = (offset + length + PAGE_SIZE-1) >> PAGE_SHIFT;

	for (i = 1; i < nr_pages; i++) {
		if (pfn_to_mfn(++pfn) != ++next_mfn)
			return 0;
	}
	return 1;
}

static int range_straddles_page_boundary(phys_addr_t p, size_t size)
{
	unsigned long pfn = PFN_DOWN(p);
	unsigned int offset = p & ~PAGE_MASK;

	if (offset + size <= PAGE_SIZE)
		return 0;
	if (check_pages_physically_contiguous(pfn, offset, size))
		return 0;
	return 1;
}


bool xen_dma_capable(struct device *dev, dma_addr_t dev_addr, phys_addr_t phys, size_t size)
{
	int rc = 0;

	rc =  is_buffer_dma_capable(dma_get_mask(dev), dev_addr, size) &&
		 !range_straddles_page_boundary(phys, size);
	return rc;
}

static int is_xen_swiotlb_buffer(dma_addr_t dma_addr)
{
	unsigned long mfn = PFN_DOWN(dma_addr);
	unsigned long pfn = mfn_to_local_pfn(mfn);

	/* If the address is outside our domain, it CAN
 	 * have the same virtual address as another address
 	 * in our domain. Hence only check address within our domain. */
	if (pfn_valid(pfn))
		return is_swiotlb_buffer(PFN_PHYS(pfn));

	return 0;
}
