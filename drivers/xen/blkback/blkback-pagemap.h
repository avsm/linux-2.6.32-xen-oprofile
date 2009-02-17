#ifndef _BLKBACK_PAGEMAP_H_
#define _BLKBACK_PAGEMAP_H_

#include <xen/interface/xen.h>
#include <xen/interface/grant_table.h>

typedef unsigned int busid_t;

struct blkback_pagemap {
	domid_t          domid;
	busid_t          busid;
	grant_ref_t      gref;
};

struct blkback_pagemap blkback_pagemap_read(struct page *);

#endif
