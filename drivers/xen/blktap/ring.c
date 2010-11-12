#include <linux/device.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/poll.h>

#include <asm/xen/page.h>
#include <asm/xen/hypercall.h>

#include "blktap.h"

#ifdef CONFIG_XEN_BLKDEV_BACKEND
#include "../blkback/blkback-pagemap.h"
#else
#define blkback_pagemap_contains_page(page) 0
#endif

int blktap_ring_major;
static struct cdev blktap_ring_cdev;

static inline struct blktap *
vma_to_blktap(struct vm_area_struct *vma)
{
	struct vm_foreign_map *m = vma->vm_private_data;
	struct blktap_ring *r = container_of(m, struct blktap_ring, foreign_map);
	return container_of(r, struct blktap, ring);
}

 /* 
  * BLKTAP - immediately before the mmap area,
  * we have a bunch of pages reserved for shared memory rings.
  */
#define RING_PAGES 1

static void
blktap_ring_read_response(struct blktap *tap,
		     const struct blkif_response *rsp)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx, err;

	request = NULL;

	usr_idx = rsp->id;
	if (usr_idx < 0 || usr_idx >= MAX_PENDING_REQS) {
		err = -ERANGE;
		goto invalid;
	}

	request = tap->pending_requests[usr_idx];

	if (!request) {
		err = -ESRCH;
		goto invalid;
	}

	if (rsp->operation != request->operation) {
		err = -EINVAL;
		goto invalid;
	}

	dev_dbg(ring->dev,
		"request %d [%p] response: %d\n",
		request->usr_idx, request, rsp->status);

	err = rsp->status == BLKIF_RSP_OKAY ? 0 : -EIO;
end_request:
	blktap_device_end_request(tap, request, err);
	return;

invalid:
	dev_warn(ring->dev,
		 "invalid response, idx:%d status:%d op:%d/%d: err %d\n",
		 usr_idx, rsp->status,
		 rsp->operation, request->operation,
		 err);
	if (request)
		goto end_request;
}

static void
blktap_read_ring(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blkif_response rsp;
	RING_IDX rc, rp;

	down_read(&current->mm->mmap_sem);
	if (!ring->vma) {
		up_read(&current->mm->mmap_sem);
		return;
	}

	/* for each outstanding message on the ring  */
	rp = ring->ring.sring->rsp_prod;
	rmb();

	for (rc = ring->ring.rsp_cons; rc != rp; rc++) {
		memcpy(&rsp, RING_GET_RESPONSE(&ring->ring, rc), sizeof(rsp));
		blktap_ring_read_response(tap, &rsp);
	}

	ring->ring.rsp_cons = rc;

	up_read(&current->mm->mmap_sem);
}

static int blktap_ring_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static pte_t
blktap_ring_clear_pte(struct vm_area_struct *vma,
		      unsigned long uvaddr,
		      pte_t *ptep, int is_fullmm)
{
	pte_t copy;
	struct blktap *tap;
	unsigned long kvaddr;
	struct page **map, *page;
	struct blktap_ring *ring;
	struct blktap_request *request;
	struct grant_handle_pair *khandle;
	struct gnttab_unmap_grant_ref unmap[2];
	int offset, seg, usr_idx, count = 0;

	tap  = vma_to_blktap(vma);
	ring = &tap->ring;
	map  = ring->foreign_map.map;
	BUG_ON(!map);	/* TODO Should this be changed to if statement? */

	/*
	 * Zap entry if the address is before the start of the grant
	 * mapped region.
	 */
	if (uvaddr < ring->user_vstart)
		return ptep_get_and_clear_full(vma->vm_mm, uvaddr,
					       ptep, is_fullmm);

	offset  = (int)((uvaddr - ring->user_vstart) >> PAGE_SHIFT);
	usr_idx = offset / BLKIF_MAX_SEGMENTS_PER_REQUEST;
	seg     = offset % BLKIF_MAX_SEGMENTS_PER_REQUEST;

	offset  = (int)((uvaddr - vma->vm_start) >> PAGE_SHIFT);
	page    = map[offset];
	if (page && blkback_pagemap_contains_page(page))
		set_page_private(page, 0);
	map[offset] = NULL;

	request = tap->pending_requests[usr_idx];
	kvaddr  = request_to_kaddr(request, seg);
	khandle = request->handles + seg;

	if (khandle->kernel != INVALID_GRANT_HANDLE) {
		gnttab_set_unmap_op(&unmap[count], kvaddr, 
				    GNTMAP_host_map, khandle->kernel);
		count++;

		set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT, 
				    INVALID_P2M_ENTRY);
	}

	if (khandle->user != INVALID_GRANT_HANDLE) {
		BUG_ON(xen_feature(XENFEAT_auto_translated_physmap));

		copy = *ptep;
		gnttab_set_unmap_op(&unmap[count], virt_to_machine(ptep).maddr,
				    GNTMAP_host_map
				    | GNTMAP_application_map
				    | GNTMAP_contains_pte,
				    khandle->user);
		count++;
	} else
		copy = ptep_get_and_clear_full(vma->vm_mm, uvaddr, ptep,
					       is_fullmm);

	if (count)
		if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
					      unmap, count))
			BUG();

	khandle->kernel = INVALID_GRANT_HANDLE;
	khandle->user   = INVALID_GRANT_HANDLE;

	return copy;
}

static void
blktap_ring_fail_pending(struct blktap *tap)
{
	struct blktap_request *request;
	int usr_idx;

	for (usr_idx = 0; usr_idx < MAX_PENDING_REQS; usr_idx++) {
		request = tap->pending_requests[usr_idx];
		if (!request)
			continue;

		blktap_device_end_request(tap, request, -EIO);
	}
}

static void
blktap_ring_vm_close(struct vm_area_struct *vma)
{
	struct blktap *tap = vma_to_blktap(vma);
	struct blktap_ring *ring = &tap->ring;
	struct page *page = virt_to_page(ring->ring.sring);

	blktap_ring_fail_pending(tap);

	kfree(ring->foreign_map.map);
	ring->foreign_map.map = NULL;

	zap_page_range(vma, vma->vm_start, PAGE_SIZE, NULL);
	ClearPageReserved(page);
	__free_page(page);

	ring->vma = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);
}

static struct vm_operations_struct blktap_ring_vm_operations = {
	.close    = blktap_ring_vm_close,
	.fault    = blktap_ring_fault,
	.zap_pte  = blktap_ring_clear_pte,
};

static int
blktap_ring_open(struct inode *inode, struct file *filp)
{
	struct blktap *tap = NULL;
	int minor;

	minor = iminor(inode);

	if (minor < blktap_max_minor)
		tap = blktaps[minor];

	if (!tap)
		return -ENXIO;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		return -ENXIO;

	if (tap->ring.task)
		return -EBUSY;

	filp->private_data = tap;
	tap->ring.task = current;

	return 0;
}

static int
blktap_ring_release(struct inode *inode, struct file *filp)
{
	struct blktap *tap = filp->private_data;

	blktap_device_destroy_sync(tap);

	tap->ring.task = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);

	return 0;
}

/* Note on mmap:
 * We need to map pages to user space in a way that will allow the block
 * subsystem set up direct IO to them.  This couldn't be done before, because
 * there isn't really a sane way to translate a user virtual address down to a 
 * physical address when the page belongs to another domain.
 *
 * My first approach was to map the page in to kernel memory, add an entry
 * for it in the physical frame list (using alloc_lomem_region as in blkback)
 * and then attempt to map that page up to user space.  This is disallowed
 * by xen though, which realizes that we don't really own the machine frame
 * underlying the physical page.
 *
 * The new approach is to provide explicit support for this in xen linux.
 * The VMA now has a flag, VM_FOREIGN, to indicate that it contains pages
 * mapped from other vms.  vma->vm_private_data is set up as a mapping 
 * from pages to actual page structs.  There is a new clause in get_user_pages
 * that does the right thing for this sort of mapping.
 */
static int
blktap_ring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	struct blkif_sring *sring;
	struct page *page;
	int size, err;
	struct page **map;

	map   = NULL;
	sring = NULL;

	if (ring->vma)
		return -EBUSY;

	size = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (size != (MMAP_PAGES + RING_PAGES)) {
		BTERR("you _must_ map exactly %lu pages!\n",
		      MMAP_PAGES + RING_PAGES);
		return -EAGAIN;
	}

	/* allocate the shared ring */
	page = alloc_page(GFP_KERNEL|__GFP_ZERO);
	if (!page)
		goto fail;

	SetPageReserved(page);

	err = vm_insert_page(vma, vma->vm_start, page);
	if (err)
		goto fail;

	sring = page_address(page);
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&ring->ring, sring, PAGE_SIZE);

	ring->ring_vstart = vma->vm_start;
	ring->user_vstart = ring->ring_vstart + PAGE_SIZE;

	/* allocate the foreign map */
	map = kzalloc(size * sizeof(struct page *), GFP_KERNEL);
	if (!map)
		goto fail;

	/* Mark this VM as containing foreign pages, and set up mappings. */
	ring->foreign_map.map = map;
	vma->vm_private_data = &ring->foreign_map;
	vma->vm_flags |= VM_FOREIGN;
	vma->vm_flags |= VM_DONTCOPY;
	vma->vm_flags |= VM_RESERVED;
	vma->vm_ops = &blktap_ring_vm_operations;

#ifdef CONFIG_X86
	vma->vm_mm->context.has_foreign_mappings = 1;
#endif

	ring->vma = vma;
	return 0;

fail:
	if (page) {
		zap_page_range(vma, vma->vm_start, PAGE_SIZE, NULL);
		ClearPageReserved(page);
		__free_page(page);
	}

	if (map)
		kfree(map);

	return -ENOMEM;
}

static int
blktap_ring_ioctl(struct inode *inode, struct file *filp,
		  unsigned int cmd, unsigned long arg)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;

	BTDBG("%d: cmd: %u, arg: %lu\n", tap->minor, cmd, arg);

	if (!ring->vma || ring->vma->vm_mm != current->mm)
		return -EACCES;

	switch(cmd) {
	case BLKTAP2_IOCTL_KICK_FE:

		blktap_read_ring(tap);
		return 0;

	case BLKTAP2_IOCTL_CREATE_DEVICE: {
		struct blktap_params params;
		void __user *ptr = (void *)arg;

		if (!arg)
			return -EINVAL;

		if (copy_from_user(&params, ptr, sizeof(params)))
			return -EFAULT;

		return blktap_device_create(tap, &params);
	}

	case BLKTAP2_IOCTL_REMOVE_DEVICE:

		return blktap_device_destroy(tap);
	}

	return -ENOIOCTLCMD;
}

static unsigned int blktap_ring_poll(struct file *filp, poll_table *wait)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	int work = 0;

	poll_wait(filp, &tap->pool->wait, wait);
	poll_wait(filp, &ring->poll_wait, wait);

	down_read(&current->mm->mmap_sem);
	if (ring->vma && tap->device.gd)
		work = blktap_device_run_queue(tap);
	up_read(&current->mm->mmap_sem);

	if (work ||
	    ring->ring.sring->private.tapif_user.msg ||
	    test_and_clear_bit(BLKTAP_DEVICE_CLOSED, &tap->dev_inuse))
		return POLLIN | POLLRDNORM;

	return 0;
}

static struct file_operations blktap_ring_file_operations = {
	.owner    = THIS_MODULE,
	.open     = blktap_ring_open,
	.release  = blktap_ring_release,
	.ioctl    = blktap_ring_ioctl,
	.mmap     = blktap_ring_mmap,
	.poll     = blktap_ring_poll,
};

void
blktap_ring_kick_user(struct blktap *tap)
{
	wake_up(&tap->ring.poll_wait);
}

int
blktap_ring_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	if (ring->task || ring->vma)
		return -EBUSY;

	return 0;
}

int
blktap_ring_create(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	init_waitqueue_head(&ring->poll_wait);
	ring->devno = MKDEV(blktap_ring_major, tap->minor);

	return 0;
}

size_t
blktap_ring_debug(struct blktap *tap, char *buf, size_t size)
{
	char *s = buf, *end = buf + size;
	int usr_idx;

	s += snprintf(s, end - s,
		      "begin pending:%d\n", tap->pending_cnt);

	for (usr_idx = 0; usr_idx < MAX_PENDING_REQS; usr_idx++) {
		struct blktap_request *request;
		struct timeval *time;
		int write;

		request = tap->pending_requests[usr_idx];
		if (!request)
			continue;

		write = request->operation == BLKIF_OP_WRITE;
		time  = &request->time;

		s += snprintf(s, end - s,
			      "%02d: usr_idx:%02d "
			      "op:%c nr_pages:%02d time:%lu.%09lu\n",
			      usr_idx, request->usr_idx,
			      write ? 'W' : 'R', request->nr_pages,
			      time->tv_sec, time->tv_usec);
	}

	s += snprintf(s, end - s, "end pending\n");

	return s - buf;
}


int __init
blktap_ring_init(void)
{
	dev_t dev = 0;
	int err;

	cdev_init(&blktap_ring_cdev, &blktap_ring_file_operations);
	blktap_ring_cdev.owner = THIS_MODULE;

	err = alloc_chrdev_region(&dev, 0, MAX_BLKTAP_DEVICE, "blktap2");
	if (err < 0) {
		BTERR("error registering ring devices: %d\n", err);
		return err;
	}

	err = cdev_add(&blktap_ring_cdev, dev, MAX_BLKTAP_DEVICE);
	if (err) {
		BTERR("error adding ring device: %d\n", err);
		unregister_chrdev_region(dev, MAX_BLKTAP_DEVICE);
		return err;
	}

	blktap_ring_major = MAJOR(dev);
	BTINFO("blktap ring major: %d\n", blktap_ring_major);

	return 0;
}

void
blktap_ring_exit(void)
{
	if (!blktap_ring_major)
		return;

	cdev_del(&blktap_ring_cdev);
	unregister_chrdev_region(MKDEV(blktap_ring_major, 0),
				 MAX_BLKTAP_DEVICE);

	blktap_ring_major = 0;
}
