/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GCIP helpers for allocating memories.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GCIP_ALLOC_HELPER_H__
#define __GCIP_ALLOC_HELPER_H__

#include <linux/device.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

/*
 * The actual return value from the alloc_noncontiguous function.
 * The user should only care about @sgt. @pages is used internally for freeing memory.
 */
struct gcip_sgt_handle {
	struct sg_table sgt;
	void *mem;
};

/*
 * Allocates non-contiguous memory with size @size bytes.
 *
 * @dev: pointer to device structure. Is used for logging or the NUMA node for page allocation.
 * @size: Total size in bytes. Will be page aligned.
 * @gfp: The GFP flag for malloc internal structures.
 *
 * Returns the SG table represents the non-contiguous region.
 * Returns NULL on any error.
 */
struct sg_table *gcip_alloc_noncontiguous(struct device *dev, size_t size, gfp_t gfp);
/* Frees the memory allocated by gcip_alloc_noncontiguous. */
void gcip_free_noncontiguous(struct sg_table *sgt);

/*
 * Returns the virtual memory that was used to allocate @sgt.
 *
 * @sgt must be the return pointer of gcip_alloc_noncontiguous.
 */
static inline void *gcip_noncontiguous_sgt_to_mem(struct sg_table *sgt)
{
	struct gcip_sgt_handle *sh = container_of(sgt, struct gcip_sgt_handle, sgt);

	return sh->mem;
}

#endif /* __GCIP_ALLOC_HELPER_H__ */
