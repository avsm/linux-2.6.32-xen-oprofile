#ifndef _BLKBACK_PAGEMAP_H_
#define _BLKBACK_PAGEMAP_H_

#include <xen/interface/xen.h>
#include <xen/interface/grant_table.h>

typedef unsigned int busid_t;

struct blkback_pagemap {
	struct page     *page;
	domid_t          domid;
	busid_t          busid;
	grant_ref_t      gref;
};

struct blkback_pagemap blkback_pagemap_read(struct page *);

int blkback_pagemap_contains_page(struct page *page);

#endif
