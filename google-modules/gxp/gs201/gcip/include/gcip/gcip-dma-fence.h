/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GCIP support of DMA fences.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __GCIP_DMA_FENCE_H__
#define __GCIP_DMA_FENCE_H__

#include <linux/device.h>
#include <linux/dma-fence.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define GCIP_FENCE_TIMELINE_NAME_LEN 128

/* Used before accessing the list headed by mgr->fence_list_head. */
#define GCIP_DMA_FENCE_LIST_LOCK(mgr, flags) spin_lock_irqsave(&(mgr)->fence_list_lock, flags)
#define GCIP_DMA_FENCE_LIST_UNLOCK(mgr, flags)                                                     \
	spin_unlock_irqrestore(&(mgr)->fence_list_lock, flags)

/*
 * A macro to loop through all fences under a gcip_dma_fence_manager.
 * @mgr: struct gcip_dma_fence_manager
 * @gfence: struct gcip_dma_fence
 *
 * This macro must be wrapped by GCIP_DMA_FENCE_LIST_(UN)LOCK.
 */
#define gcip_for_each_fence(mgr, gfence)                                                           \
	list_for_each_entry(gfence, &(mgr)->fence_list_head, fence_list)

#define to_gcip_fence(fence) container_of(fence, struct gcip_dma_fence, fence)

struct gcip_dma_fence_manager {
	/* The list of all fence objects for debugging. */
	struct list_head fence_list_head;
	/* Protects the list headed by @fence_list_head. */
	spinlock_t fence_list_lock;
	/* For logging. */
	struct device *dev;
};

struct gcip_dma_fence {
	struct dma_fence fence;
	/* The manager used to init this object. */
	struct gcip_dma_fence_manager *mgr;
	char timeline_name[GCIP_FENCE_TIMELINE_NAME_LEN];
	/* Protects @fence. */
	spinlock_t lock;
	/* Is protected by manager->fence_list_lock. */
	struct list_head fence_list;
};

struct gcip_dma_fence_data {
	/*
	 * A null-terminated string with length less than GCIP_FENCE_TIMELINE_NAME_LEN.
	 * The content of this buffer will be copied so it's fine to release this pointer after
	 * the gcip_dma_fence_init() call.
	 */
	char *timeline_name;
	/*
	 * The DMA fence operators to initialize the fence with.
	 */
	const struct dma_fence_ops *ops;
	/* The sequence number to initialize the fence with. */
	u32 seqno;
	/* Output: The fd of the new sync_file with the new fence. */
	int fence;
	/*
	 * The callback to be called after @gfence is initialized, before an FD has been installed.
	 * Returns 0 on success. A non-zero return value will revert the initialization of
	 * @gfence and the returned error is returned by gcip_dma_fence_init().
	 *
	 * There is no 'before_exit' callback because the user is supposed to set a custom
	 * dma_fence_ops.release callback which does the revert of after_init and then call
	 * gcip_dma_fence_exit().
	 *
	 * This callback is optional.
	 */
	int (*after_init)(struct gcip_dma_fence *gfence);
};

/*
 * Allocates and returns a GCIP DMA fence manager. Memory is allocated as @dev managed so there is
 * no release function of the manager.
 *
 * Returns a negative errno on error.
 */
struct gcip_dma_fence_manager *gcip_dma_fence_manager_create(struct device *dev);

/* Helpers for setting dma_fence_ops. */

/* Returns the timeline name. @fence must be contained within a gcip_dma_fence. */
const char *gcip_dma_fence_get_timeline_name(struct dma_fence *fence);

/* Always return true. Can be used for the enable_signaling callback. */
bool gcip_dma_fence_always_true(struct dma_fence *fence);

/* End of helpers for setting dma_fence_ops. */

/*
 * This function does
 *  1. Initialize the DMA fence object
 *  2. Call after_init() if present
 *  3. Install an FD associates to the created DMA fence
 *
 * This function never fails on step 1, so this function returns an error only if after_init() fails
 * (step 2) or FD allocation fails (step 3).
 * In either failure case, @ops->release is always called. Therefore @ops->release may need to
 * distinguish whether after_init() succeeded.
 *
 * It's always safe to call gcip_dma_fence_exit() in @ops->release because that function reverts
 * step 1.
 */
int gcip_dma_fence_init(struct gcip_dma_fence_manager *mgr, struct gcip_dma_fence *gfence,
			struct gcip_dma_fence_data *data);

/*
 * Reverts gcip_dma_fence_init(). Removes @gfence from the manager's list.
 * This function will not free @gfence.
 */
void gcip_dma_fence_exit(struct gcip_dma_fence *gfence);

/*
 * Sets @status to the DMA fence status of DMA fence FD @fence.
 * @status is only set when this function returns 0.
 *
 * It is OK if @fence does not refer to a gcip_dma_fence.
 *
 * Returns 0 on success. Otherwise a negative errno.
 */
int gcip_dma_fence_status(int fence, int *status);

/*
 * Signals the fence error of DMA fence FD @fence.
 *
 * If the fence has been signaled,
 *  - if @ignore_signaled is true, this function does nothing.
 *  - otherwise, returns -EALREADY.
 *
 * It is OK if @fence does not refer to a gcip_dma_fence.
 *
 * Returns 0 on success. Otherwise a negative errno.
 */
int gcip_dma_fence_signal(int fence, int error, bool ignore_signaled);
/* Identical to gcip_dma_fence_signal except this function accepts gcip_dma_fence as the input. */
int gcip_dma_fenceptr_signal(struct gcip_dma_fence *gfence, int error, bool ignore_signaled);

/* Prints data of @gfence to the sequence file @s. For debug purpose only. */
void gcip_dma_fence_show(struct gcip_dma_fence *gfence, struct seq_file *s);

#endif /* __GCIP_DMA_FENCE_H__ */
