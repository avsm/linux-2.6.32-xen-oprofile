#include <linux/version.h> /* XXX Remove uses of VERSION instead. */
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/cdrom.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <asm/tlbflush.h>

#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>

#include <xen/xenbus.h>
#include <xen/interface/io/blkif.h>

#include <asm/xen/page.h>
#include <asm/xen/hypercall.h>

#include "blktap.h"

#include "../blkback/blkback-pagemap.h"

#if 0
#define DPRINTK_IOCTL(_f, _a...) printk(KERN_ALERT _f, ## _a)
#else
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

struct blktap_grant_table {
	int cnt;
	struct gnttab_map_grant_ref grants[BLKIF_MAX_SEGMENTS_PER_REQUEST * 2];
};

int blktap_device_major;

static inline struct blktap *
dev_to_blktap(struct blktap_device *dev)
{
	return container_of(dev, struct blktap, device);
}

static int
blktap_device_open(struct block_device * bd, fmode_t mode)
{
	struct blktap *tap;
	struct blktap_device *dev = bd->bd_disk->private_data;

	if (!dev)
		return -ENOENT;

	tap = dev_to_blktap(dev);
	if (!blktap_active(tap) ||
	    test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		return -ENOENT;

	dev->users++;

	return 0;
}

static int
blktap_device_release(struct gendisk *gd, fmode_t mode)
{
	struct blktap_device *dev = gd->private_data;
	struct blktap *tap = dev_to_blktap(dev);

	dev->users--;
	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_device(tap);

	return 0;
}

static int
blktap_device_getgeo(struct block_device *bd, struct hd_geometry *hg)
{
	/* We don't have real geometry info, but let's at least return
	   values consistent with the size of the device */
	sector_t nsect = get_capacity(bd->bd_disk);
	sector_t cylinders = nsect;

	hg->heads = 0xff;
	hg->sectors = 0x3f;
	sector_div(cylinders, hg->heads * hg->sectors);
	hg->cylinders = cylinders;
	if ((sector_t)(hg->cylinders + 1) * hg->heads * hg->sectors < nsect)
		hg->cylinders = 0xffff;
	return 0;
}

static int
blktap_device_ioctl(struct block_device *bd, fmode_t mode,
		    unsigned command, unsigned long argument)
{
	int i;

	DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
		      command, (long)argument, inode->i_rdev);

	switch (command) {
	case CDROMMULTISESSION:
		BTDBG("FIXME: support multisession CDs later\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char __user *)(argument + i)))
				return -EFAULT;
		return 0;

	case SCSI_IOCTL_GET_IDLUN:
		if (!access_ok(VERIFY_WRITE, argument, 
			sizeof(struct scsi_idlun)))
			return -EFAULT;

		/* return 0 for now. */
		__put_user(0, &((struct scsi_idlun __user *)argument)->dev_id);
		__put_user(0, 
			&((struct scsi_idlun __user *)argument)->host_unique_id);
		return 0;

	default:
		/*printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		  command);*/
		return -EINVAL; /* same return as native Linux */
	}

	return 0;
}

static struct block_device_operations blktap_device_file_operations = {
	.owner     = THIS_MODULE,
	.open      = blktap_device_open,
	.release   = blktap_device_release,
	.ioctl     = blktap_device_ioctl,
	.getgeo    = blktap_device_getgeo
};

static int
blktap_map_uaddr_fn(pte_t *ptep, struct page *pmd_page,
		    unsigned long addr, void *data)
{
	pte_t *pte = (pte_t *)data;

	BTDBG("ptep %p -> %012llx\n", ptep, pte_val(*pte));
	set_pte(ptep, *pte);
	return 0;
}

static int
blktap_map_uaddr(struct mm_struct *mm, unsigned long address, pte_t pte)
{
	return apply_to_page_range(mm, address,
				   PAGE_SIZE, blktap_map_uaddr_fn, &pte);
}

static int
blktap_umap_uaddr_fn(pte_t *ptep, struct page *pmd_page,
		     unsigned long addr, void *data)
{
	struct mm_struct *mm = (struct mm_struct *)data;

	BTDBG("ptep %p\n", ptep);
	pte_clear(mm, addr, ptep);
	return 0;
}

static int
blktap_umap_uaddr(struct mm_struct *mm, unsigned long address)
{
	return apply_to_page_range(mm, address,
				   PAGE_SIZE, blktap_umap_uaddr_fn, mm);
}

static inline void
flush_tlb_kernel_page(unsigned long kvaddr)
{
	flush_tlb_kernel_range(kvaddr, kvaddr + PAGE_SIZE);
}

static void
blktap_device_end_dequeued_request(struct blktap_device *dev,
				   struct request *req, int error)
{
	unsigned long flags;
	int ret;

	//spin_lock_irq(&dev->lock);
	spin_lock_irqsave(dev->gd->queue->queue_lock, flags);
	ret = __blk_end_request(req, error, blk_rq_bytes(req));
	spin_unlock_irqrestore(dev->gd->queue->queue_lock, flags);
	//spin_unlock_irq(&dev->lock);

	BUG_ON(ret);
}

static void
blktap_device_fast_flush(struct blktap *tap, struct blktap_request *request)
{
	uint64_t ptep;
	int ret, usr_idx;
	unsigned int i, cnt;
	struct page **map, *page;
	struct blktap_ring *ring;
	struct grant_handle_pair *khandle;
	unsigned long kvaddr, uvaddr, offset;
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST * 2];

	cnt     = 0;
	ring    = &tap->ring;
	usr_idx = request->usr_idx;
	map     = ring->foreign_map.map;

	if (!ring->vma)
		return;

	if (xen_feature(XENFEAT_auto_translated_physmap))
		zap_page_range(ring->vma, 
			       MMAP_VADDR(ring->user_vstart, usr_idx, 0),
			       request->nr_pages << PAGE_SHIFT, NULL);

	for (i = 0; i < request->nr_pages; i++) {
		kvaddr = request_to_kaddr(request, i);
		uvaddr = MMAP_VADDR(ring->user_vstart, usr_idx, i);

		khandle = request->handles + i;

		if (khandle->kernel != INVALID_GRANT_HANDLE) {
			gnttab_set_unmap_op(&unmap[cnt], kvaddr,
					    GNTMAP_host_map, khandle->kernel);
			cnt++;
			set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT,
					    INVALID_P2M_ENTRY);
		}

		if (khandle->user != INVALID_GRANT_HANDLE) {
			BUG_ON(xen_feature(XENFEAT_auto_translated_physmap));
			if (create_lookup_pte_addr(ring->vma->vm_mm,
						   uvaddr, &ptep) != 0) {
				BTERR("Couldn't get a pte addr!\n");
				return;
			}

			gnttab_set_unmap_op(&unmap[cnt], ptep,
					    GNTMAP_host_map
					    | GNTMAP_application_map
					    | GNTMAP_contains_pte,
					    khandle->user);
			cnt++;
		}

		offset = (uvaddr - ring->vma->vm_start) >> PAGE_SHIFT;

		BTDBG("offset: 0x%08lx, page: %p, request: %p, usr_idx: %d, "
		      "seg: %d, kvaddr: 0x%08lx, khandle: %u, uvaddr: "
		      "0x%08lx, handle: %u\n", offset, map[offset], request,
		      usr_idx, i, kvaddr, khandle->kernel, uvaddr,
		      khandle->user);

		page = map[offset];
		if (page) {
			ClearPageReserved(map[offset]);
			if (blkback_pagemap_contains_page(page))
				set_page_private(page, 0);
		}
		map[offset] = NULL;

		khandle->kernel = INVALID_GRANT_HANDLE;
		khandle->user   = INVALID_GRANT_HANDLE;
	}

	if (cnt) {
		ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
						unmap, cnt);
		BUG_ON(ret);
	}

	if (!xen_feature(XENFEAT_auto_translated_physmap))
		zap_page_range(ring->vma, 
			       MMAP_VADDR(ring->user_vstart, usr_idx, 0), 
			       request->nr_pages << PAGE_SHIFT, NULL);
}

static void
blktap_unmap(struct blktap *tap, struct blktap_request *request)
{
	int i, usr_idx;
	unsigned long kvaddr;

	usr_idx = request->usr_idx;

	for (i = 0; i < request->nr_pages; i++) {
		kvaddr = request_to_kaddr(request, i);
		BTDBG("request: %p, seg: %d, kvaddr: 0x%08lx, khandle: %u, "
		      "uvaddr: 0x%08lx, uhandle: %u\n", request, i,
		      kvaddr, request->handles[i].kernel,
		      MMAP_VADDR(tap->ring.user_vstart, usr_idx, i),
		      request->handles[i].user);

		if (request->handles[i].kernel == INVALID_GRANT_HANDLE) {
			blktap_umap_uaddr(current->mm, kvaddr);
			flush_tlb_kernel_page(kvaddr);
			set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT,
					    INVALID_P2M_ENTRY);
		}
	}

	if (blktap_active(tap)) {
		down_write(&tap->ring.vma->vm_mm->mmap_sem);
		blktap_device_fast_flush(tap, request);
		up_write(&tap->ring.vma->vm_mm->mmap_sem);
	}
}

/*
 * called if the tapdisk process dies unexpectedly.
 * fail and release any pending requests and disable queue.
 * may be called from non-tapdisk context.
 */
void
blktap_device_fail_pending_requests(struct blktap *tap)
{
	int usr_idx;
	struct request *req;
	struct blktap_device *dev;
	struct blktap_request *request;

	if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return;

	dev = &tap->device;
	for (usr_idx = 0; usr_idx < MAX_PENDING_REQS; usr_idx++) {
		request = tap->pending_requests[usr_idx];
		if (!request || request->status != BLKTAP_REQUEST_PENDING)
			continue;

		BTERR("%u:%u: failing pending %s of %d pages\n",
		      blktap_device_major, tap->minor,
		      (request->operation == BLKIF_OP_READ ?
		       "read" : "write"), request->nr_pages);

		blktap_unmap(tap, request);
		req = (struct request *)(unsigned long)request->id;
		blktap_device_end_dequeued_request(dev, req, -EIO);
		blktap_request_free(tap, request);
	}

	spin_lock_irq(&dev->lock);

	/* fail any future requests */
	dev->gd->queue->queuedata = NULL;
	blk_start_queue(dev->gd->queue);

	spin_unlock_irq(&dev->lock);
}

void
blktap_device_finish_request(struct blktap *tap,
			     struct blkif_response *res,
			     struct blktap_request *request)
{
	int ret;
	struct request *req;
	struct blktap_device *dev;

	dev = &tap->device;

	blktap_unmap(tap, request);

	req = (struct request *)(unsigned long)request->id;
	ret = res->status == BLKIF_RSP_OKAY ? 0 : -EIO;

	BTDBG("req %p res status %d operation %d/%d id %lld\n", req,
	      res->status, res->operation, request->operation,
	      (unsigned long long)res->id);

	switch (request->operation) {
	case BLKIF_OP_READ:
	case BLKIF_OP_WRITE:
		if (unlikely(res->status != BLKIF_RSP_OKAY))
			BTERR("Bad return from device data "
				"request: %x\n", res->status);
		blktap_device_end_dequeued_request(dev, req, ret);
		break;
	default:
		BUG();
	}

	blktap_request_free(tap, request);
}

static int
blktap_prep_foreign(struct blktap *tap,
		    struct blktap_request *request,
		    struct blkif_request *blkif_req,
		    unsigned int seg, struct page *page,
		    struct blktap_grant_table *table)
{
	uint64_t ptep;
	uint32_t flags;
#ifdef BLKTAP_CHAINED_BLKTAP
	struct page *tap_page;
#endif
	struct blktap_ring *ring;
	struct blkback_pagemap map;
	unsigned long uvaddr, kvaddr;

	ring = &tap->ring;
	map  = blkback_pagemap_read(page);
	blkif_req->seg[seg].gref = map.gref;

	uvaddr = MMAP_VADDR(ring->user_vstart, request->usr_idx, seg);
	kvaddr = request_to_kaddr(request, seg);
	flags  = GNTMAP_host_map |
		(request->operation == BLKIF_OP_WRITE ? GNTMAP_readonly : 0);

	gnttab_set_map_op(&table->grants[table->cnt],
			  kvaddr, flags, map.gref, map.domid);
	table->cnt++;


#ifdef BLKTAP_CHAINED_BLKTAP
	/* enable chained tap devices */
	tap_page = request_to_page(request, seg);
	set_page_private(tap_page, page_private(page));
	SetPageBlkback(tap_page);
#endif

	if (xen_feature(XENFEAT_auto_translated_physmap))
		return 0;

	if (create_lookup_pte_addr(ring->vma->vm_mm, uvaddr, &ptep)) {
		BTERR("couldn't get a pte addr!\n");
		return -1;
	}

	flags |= GNTMAP_application_map | GNTMAP_contains_pte;
	gnttab_set_map_op(&table->grants[table->cnt],
			  ptep, flags, map.gref, map.domid);
	table->cnt++;

	return 0;
}

static int
blktap_map_foreign(struct blktap *tap,
		   struct blktap_request *request,
		   struct blkif_request *blkif_req,
		   struct blktap_grant_table *table)
{
	struct page *page;
	int i, grant, err, usr_idx;
	struct blktap_ring *ring;
	unsigned long uvaddr, foreign_mfn;

	if (!table->cnt)
		return 0;

	err = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
					table->grants, table->cnt);
	BUG_ON(err);

	grant   = 0;
	usr_idx = request->usr_idx;
	ring    = &tap->ring;

	for (i = 0; i < request->nr_pages; i++) {
		if (!blkif_req->seg[i].gref)
			continue;

		uvaddr = MMAP_VADDR(ring->user_vstart, usr_idx, i);

		if (unlikely(table->grants[grant].status)) {
			BTERR("invalid kernel buffer: could not remap it\n");
			err |= 1;
			table->grants[grant].handle = INVALID_GRANT_HANDLE;
		}

		request->handles[i].kernel = table->grants[grant].handle;
		foreign_mfn = table->grants[grant].dev_bus_addr >> PAGE_SHIFT;
		grant++;

		if (xen_feature(XENFEAT_auto_translated_physmap))
			goto done;

		if (unlikely(table->grants[grant].status)) {
			BTERR("invalid user buffer: could not remap it\n");
			err |= 1;
			table->grants[grant].handle = INVALID_GRANT_HANDLE;
		}

		request->handles[i].user = table->grants[grant].handle;
		grant++;

	done:
		if (err)
			continue;

		page = request_to_page(request, i);

		if (!xen_feature(XENFEAT_auto_translated_physmap))
			set_phys_to_machine(page_to_pfn(page),
					    FOREIGN_FRAME(foreign_mfn));
		else if (vm_insert_page(ring->vma, uvaddr, page))
			err |= 1;

		BTDBG("pending_req: %p, seg: %d, page: %p, "
		      "kvaddr: 0x%p, khandle: %u, uvaddr: 0x%08lx, "
		      "uhandle: %u\n", request, i, page,
		      pfn_to_kaddr(page_to_pfn(page)),
		      request->handles[i].kernel,
		      uvaddr, request->handles[i].user);
	}

	return err;
}

static void
blktap_map(struct blktap *tap,
	   struct blktap_request *request,
	   unsigned int seg, struct page *page)
{
	pte_t pte;
	int usr_idx;
	struct blktap_ring *ring;
	unsigned long uvaddr, kvaddr;

	ring    = &tap->ring;
	usr_idx = request->usr_idx;
	uvaddr  = MMAP_VADDR(ring->user_vstart, usr_idx, seg);
	kvaddr  = request_to_kaddr(request, seg);

	pte = mk_pte(page, ring->vma->vm_page_prot);
	blktap_map_uaddr(ring->vma->vm_mm, uvaddr, pte_mkwrite(pte));
	flush_tlb_page(ring->vma, uvaddr);
	blktap_map_uaddr(ring->vma->vm_mm, kvaddr, mk_pte(page, PAGE_KERNEL));
	flush_tlb_kernel_page(kvaddr);

	set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT, pte_mfn(pte));
	request->handles[seg].kernel = INVALID_GRANT_HANDLE;
	request->handles[seg].user   = INVALID_GRANT_HANDLE;

	BTDBG("pending_req: %p, seg: %d, page: %p, kvaddr: 0x%08lx, "
	      "uvaddr: 0x%08lx\n", request, seg, page, kvaddr,
	      uvaddr);
}

static int
blktap_device_process_request(struct blktap *tap,
			      struct blktap_request *request,
			      struct request *req)
{
	struct page *page;
	int i, usr_idx, err;
	struct blktap_ring *ring;
	struct scatterlist *sg;
	struct blktap_grant_table table;
	unsigned int fsect, lsect, nr_sects;
	unsigned long offset, uvaddr;
	struct blkif_request blkif_req, *target;

	err = -1;
	memset(&table, 0, sizeof(table));

	ring    = &tap->ring;
	usr_idx = request->usr_idx;
	blkif_req.id = usr_idx;
	blkif_req.sector_number = (blkif_sector_t)req->sector;
	blkif_req.handle = 0;
	blkif_req.operation = rq_data_dir(req) ?
		BLKIF_OP_WRITE : BLKIF_OP_READ;

	request->id        = (unsigned long)req;
	request->operation = blkif_req.operation;
	request->status    = BLKTAP_REQUEST_PENDING;
	do_gettimeofday(&request->time);

	nr_sects = 0;
	request->nr_pages = 0;
	blkif_req.nr_segments = blk_rq_map_sg(req->q, req, tap->sg);
	BUG_ON(blkif_req.nr_segments > BLKIF_MAX_SEGMENTS_PER_REQUEST);
	for (i = 0; i < blkif_req.nr_segments; ++i) {
			sg = tap->sg + i;
			fsect = sg->offset >> 9;
			lsect = fsect + (sg->length >> 9) - 1;
			nr_sects += sg->length >> 9;

			blkif_req.seg[i] =
				(struct blkif_request_segment) {
				.gref       = 0,
				.first_sect = fsect,
				.last_sect  = lsect };

			if (blkback_pagemap_contains_page(sg_page(sg))) {
				/* foreign page -- use xen */
				if (blktap_prep_foreign(tap,
							request,
							&blkif_req,
							i,
							sg_page(sg),
							&table))
					goto out;
			} else {
				/* do it the old fashioned way */
				blktap_map(tap,
					   request,
					   i,
					   sg_page(sg));
			}

			uvaddr = MMAP_VADDR(ring->user_vstart, usr_idx, i);
			offset = (uvaddr - ring->vma->vm_start) >> PAGE_SHIFT;
			page   = request_to_page(request, i);
			ring->foreign_map.map[offset] = page;
			SetPageReserved(page);

			BTDBG("mapped uaddr %08lx to page %p pfn 0x%lx\n",
			      uvaddr, page, page_to_pfn(page));
			BTDBG("offset: 0x%08lx, pending_req: %p, seg: %d, "
			      "page: %p, kvaddr: %p, uvaddr: 0x%08lx\n",
			      offset, request, i,
			      page, pfn_to_kaddr(page_to_pfn(page)), uvaddr);

			request->nr_pages++;
	}

	if (blktap_map_foreign(tap, request, &blkif_req, &table))
		goto out;

	/* Finally, write the request message to the user ring. */
	target = RING_GET_REQUEST(&ring->ring, ring->ring.req_prod_pvt);
	memcpy(target, &blkif_req, sizeof(blkif_req));
	target->id = request->usr_idx;
	wmb(); /* blktap_poll() reads req_prod_pvt asynchronously */
	ring->ring.req_prod_pvt++;

	if (rq_data_dir(req)) {
		tap->stats.st_wr_sect += nr_sects;
		tap->stats.st_wr_req++;
	} else {
		tap->stats.st_rd_sect += nr_sects;
		tap->stats.st_rd_req++;
	}

	err = 0;

out:
	if (err)
		blktap_device_fast_flush(tap, request);
	return err;
}

/*
 * called from tapdisk context
 */
int
blktap_device_run_queue(struct blktap *tap)
{
	int err, rv;
	struct request_queue *rq;
	struct request *req;
	struct blktap_ring *ring;
	struct blktap_device *dev;
	struct blktap_request *request;

	ring   = &tap->ring;
	dev    = &tap->device;
	rq     = dev->gd->queue;

	BTDBG("running queue for %d\n", tap->minor);
	spin_lock_irq(&dev->lock);

	while ((req = elv_next_request(rq)) != NULL) {
		if (!blk_fs_request(req)) {
			end_request(req, 0);
			continue;
		}

		if (blk_barrier_rq(req)) {
			end_request(req, 0);
			continue;
		}

		if (RING_FULL(&ring->ring)) {
		wait:
			/* Avoid pointless unplugs. */
			blk_stop_queue(rq);
			break;
		}

		request = blktap_request_allocate(tap);
		if (!request) {
			tap->stats.st_oo_req++;
			goto wait;
		}

		BTDBG("req %p: dev %d cmd %p, sec 0x%llx, (0x%x/0x%lx) "
		      "buffer:%p [%s], pending: %p\n", req, tap->minor,
		      req->cmd, (unsigned long long)req->sector,
		      req->current_nr_sectors,
		      req->nr_sectors, req->buffer,
		      rq_data_dir(req) ? "write" : "read", request);

		blkdev_dequeue_request(req);

		spin_unlock_irq(&dev->lock);

		err = blktap_device_process_request(tap, request, req);
		if (err) {
			blktap_device_end_dequeued_request(dev, req, -EIO);
			blktap_request_free(tap, request);
		}

		spin_lock_irq(&dev->lock);
	}

	spin_unlock_irq(&dev->lock);

	rv = ring->ring.req_prod_pvt -
		ring->ring.sring->req_prod;

	RING_PUSH_REQUESTS(&ring->ring);

	return rv;
}

static void
blktap_device_do_request(struct request_queue *rq)
{
	struct request *req;
	struct blktap *tap;
	struct blktap_device *dev;

	dev = rq->queuedata;
	if (!dev)
		goto fail;

	tap = dev_to_blktap(dev);
	if (!blktap_active(tap))
		goto fail;

	blktap_ring_kick_user(tap);
	return;

fail:
	while ((req = elv_next_request(rq))) {
		BTERR("device closed: failing secs %llu - %llu\n",
		      (unsigned long long)req->sector,
		      (unsigned long long)req->sector + req->nr_sectors);
		end_request(req, 0);
	}
}

void
blktap_device_restart(struct blktap *tap)
{
	struct blktap_device *dev;

	dev = &tap->device;
	spin_lock_irq(&dev->lock);

	/* Re-enable calldowns. */
	if (dev->gd) {
		struct request_queue *rq = dev->gd->queue;

		if (blk_queue_stopped(rq))
			blk_start_queue(rq);

		/* Kick things off immediately. */
		blktap_device_do_request(rq);
	}

	spin_unlock_irq(&dev->lock);
}

static void
blktap_device_configure(struct blktap *tap,
			struct blktap_params *params)
{
	struct request_queue *rq;
	struct blktap_device *dev = &tap->device;

	dev = &tap->device;
	rq  = dev->gd->queue;

	spin_lock_irq(&dev->lock);

	set_capacity(dev->gd, params->capacity);

	/* Hard sector size and max sectors impersonate the equiv. hardware. */
	blk_queue_logical_block_size(rq, params->sector_size);
	blk_queue_max_sectors(rq, 512);

	/* Each segment in a request is up to an aligned page in size. */
	blk_queue_segment_boundary(rq, PAGE_SIZE - 1);
	blk_queue_max_segment_size(rq, PAGE_SIZE);

	/* Ensure a merged request will fit in a single I/O ring slot. */
	blk_queue_max_phys_segments(rq, BLKIF_MAX_SEGMENTS_PER_REQUEST);
	blk_queue_max_hw_segments(rq, BLKIF_MAX_SEGMENTS_PER_REQUEST);

	/* Make sure buffer addresses are sector-aligned. */
	blk_queue_dma_alignment(rq, 511);

	spin_unlock_irq(&dev->lock);
}

static int
blktap_device_validate_params(struct blktap *tap,
			      struct blktap_params *params)
{
	struct device *dev = tap->ring.dev;
	int sector_order, name_sz;

	sector_order = ffs(params->sector_size) - 1;

	if (sector_order <  9 ||
	    sector_order > 12 ||
	    params->sector_size != 1U<<sector_order)
		goto fail;

	if (!params->capacity ||
	    (params->capacity > ULLONG_MAX >> sector_order))
		goto fail;

	name_sz = min(sizeof(params->name), sizeof(tap->name));
	if (strnlen(params->name, name_sz) >= name_sz)
		goto fail;

	return 0;

fail:
	params->name[name_sz-1] = 0;
	dev_err(dev, "capacity: %llu, sector-size: %lu, name: %s\n",
		params->capacity, params->sector_size, params->name);
	return -EINVAL;
}

int
blktap_device_destroy(struct blktap *tap)
{
	struct blktap_device *dev = &tap->device;
	struct gendisk *gd = dev->gd;

	if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return 0;

	BTINFO("destroy device %d users %d\n", tap->minor, dev->users);

	if (dev->users) {
		blktap_device_fail_pending_requests(tap);
		blktap_device_restart(tap);
		return -EBUSY;
	}

	spin_lock_irq(&dev->lock);
	/* No more blktap_device_do_request(). */
	blk_stop_queue(gd->queue);
	clear_bit(BLKTAP_DEVICE, &tap->dev_inuse);
	dev->gd = NULL;
	spin_unlock_irq(&dev->lock);

	del_gendisk(gd);
	blk_cleanup_queue(gd->queue);
	put_disk(gd);

	return 0;
}

int
blktap_device_create(struct blktap *tap, struct blktap_params *params)
{
	int minor, err;
	struct gendisk *gd;
	struct request_queue *rq;
	struct blktap_device *tapdev;

	gd     = NULL;
	rq     = NULL;
	tapdev = &tap->device;
	minor  = tap->minor;

	if (test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return -EEXIST;

	if (blktap_device_validate_params(tap, params))
		return -EINVAL;

	gd = alloc_disk(1);
	if (!gd) {
		err = -ENOMEM;
		goto fail;
	}

	if (minor < 26) {
		sprintf(gd->disk_name, "td%c", 'a' + minor % 26);
	} else if (minor < (26 + 1) * 26) {
		sprintf(gd->disk_name, "td%c%c",
			'a' + minor / 26 - 1,'a' + minor % 26);
	} else {
		const unsigned int m1 = (minor / 26 - 1) / 26 - 1;
		const unsigned int m2 = (minor / 26 - 1) % 26;
		const unsigned int m3 =  minor % 26;
		sprintf(gd->disk_name, "td%c%c%c",
			'a' + m1, 'a' + m2, 'a' + m3);
	}

	gd->major = blktap_device_major;
	gd->first_minor = minor;
	gd->fops = &blktap_device_file_operations;
	gd->private_data = tapdev;

	spin_lock_init(&tapdev->lock);
	rq = blk_init_queue(blktap_device_do_request, &tapdev->lock);
	if (!rq) {
		err = -ENOMEM;
		goto fail;
	}
	elevator_init(rq, "noop");

	gd->queue     = rq;
	rq->queuedata = tapdev;
	tapdev->gd    = gd;

	blktap_device_configure(tap, params);
	add_disk(gd);

	if (params->name[0])
		strncpy(tap->name, params->name, sizeof(tap->name)-1);

	set_bit(BLKTAP_DEVICE, &tap->dev_inuse);

	dev_info(&gd->dev, "sector-size: %u capacity: %llu\n",
		 rq->hardsect_size, get_capacity(gd));

	return 0;

fail:
	if (gd)
		del_gendisk(gd);
	if (rq)
		blk_cleanup_queue(rq);

	return err;
}

int __init
blktap_device_init()
{
	int major;

	/* Dynamically allocate a major for this device */
	major = register_blkdev(0, "tapdev");
	if (major < 0) {
		BTERR("Couldn't register blktap device\n");
		return -ENOMEM;
	}

	blktap_device_major = major;
	BTINFO("blktap device major %d\n", major);

	return 0;
}

void
blktap_device_exit(void)
{
	if (blktap_device_major)
		unregister_blkdev(blktap_device_major, "tapdev");
}
