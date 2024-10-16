/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GCIP Mailbox Interface.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GCIP_MAILBOX_H__
#define __GCIP_MAILBOX_H__

#include <linux/compiler.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#define CIRC_QUEUE_WRAPPED(idx, wrap_bit) ((idx)&wrap_bit)
#define CIRC_QUEUE_INDEX_MASK(wrap_bit) (wrap_bit - 1)
#define CIRC_QUEUE_VALID_MASK(wrap_bit) (CIRC_QUEUE_INDEX_MASK(wrap_bit) | wrap_bit)
#define CIRC_QUEUE_REAL_INDEX(idx, wrap_bit) ((idx)&CIRC_QUEUE_INDEX_MASK(wrap_bit))

#define CIRC_QUEUE_MAX_SIZE(wrap_bit) (wrap_bit - 1)

/*
 * The status field in a firmware response is set to this by us when the response is fetched from
 * the queue.
 */
#define GCIP_MAILBOX_STATUS_OK (0)
/*
 * gcip_mailbox#wait_list uses this value to record the status of responses that haven't been
 * received yet.
 */
#define GCIP_MAILBOX_STATUS_WAITING_RESPONSE (1)
/*
 * Used when an expected response is not received, see the documentation of
 * gcip_mailbox_consume_wait_list() for details.
 */
#define GCIP_MAILBOX_STATUS_NO_RESPONSE (2)

/* To specify the operation is toward cmd or resp queue. */
enum gcip_mailbox_queue_type { GCIP_MAILBOX_CMD_QUEUE, GCIP_MAILBOX_RESP_QUEUE };

/* Utilities of circular queue operations */

/*
 * Returns the number of elements in a circular queue given its @head, @tail,
 * and @queue_size.
 */
static inline u32 gcip_circ_queue_cnt(u32 head, u32 tail, u32 queue_size, u32 wrap_bit)
{
	u32 ret;

	if (CIRC_QUEUE_WRAPPED(tail, wrap_bit) != CIRC_QUEUE_WRAPPED(head, wrap_bit))
		ret = queue_size - CIRC_QUEUE_REAL_INDEX(head, wrap_bit) +
		      CIRC_QUEUE_REAL_INDEX(tail, wrap_bit);
	else
		ret = tail - head;

	if (unlikely(ret > queue_size))
		return 0;

	return ret;
}

/* Increases @index of a circular queue by @inc. */
static inline u32 gcip_circ_queue_inc(u32 index, u32 inc, u32 queue_size, u32 wrap_bit)
{
	u32 new_index = CIRC_QUEUE_REAL_INDEX(index, wrap_bit) + inc;

	if (unlikely(new_index >= queue_size))
		return (index + inc - queue_size) ^ wrap_bit;
	else
		return index + inc;
}

/*
 * Checks if @size is a valid circular queue size, which should be a positive
 * number and less than or equal to MAX_QUEUE_SIZE.
 */
static inline bool gcip_valid_circ_queue_size(u32 size, u32 wrap_bit)
{
	if (!size || size > CIRC_QUEUE_MAX_SIZE(wrap_bit))
		return false;
	return true;
}

struct gcip_mailbox;

/* Wrapper struct for responses consumed by a thread other than the one which sent the command. */
struct gcip_mailbox_resp_awaiter {
	/* Response. */
	void *resp;
	/* The work which will be executed when the timeout occurs. */
	struct delayed_work timeout_work;
	/*
	 * If this response times out, this pointer to the owning mailbox is
	 * needed to delete this response from the list of pending responses.
	 */
	struct gcip_mailbox *mailbox;
	/* User-defined data. */
	void *data;
	/* Reference count. */
	refcount_t refs;
	/*
	 * The callback for releasing the @data.
	 * It will be set as @release_awaiter_data of struct gcip_mailbox_ops.
	 */
	void (*release_data)(void *data);
};

/*
 * Mailbox operators.
 * For in_interrupt() context, see the implementation of gcip_mailbox_handle_irq for details.
 */
struct gcip_mailbox_ops {
	/* Mandatory. */
	/*
	 * Gets the head of mailbox command queue.
	 * Context: normal.
	 */
	u32 (*get_cmd_queue_head)(struct gcip_mailbox *mailbox);
	/*
	 * Gets the tail of mailbox command queue.
	 * Context: normal.
	 */
	u32 (*get_cmd_queue_tail)(struct gcip_mailbox *mailbox);
	/*
	 * Increases the tail of mailbox command queue by @inc.
	 * Context: normal.
	 */
	void (*inc_cmd_queue_tail)(struct gcip_mailbox *mailbox, u32 inc);
	/*
	 * Acquires the lock of cmd_queue. If @try is true, "_trylock" functions can be used, but
	 * also it can be ignored. Returns 1 if succeed, 0 if failed. This callback will be called
	 * in the following situations.
	 * - Enqueue a command to the cmd_queue.
	 * The lock can be mutex lock or spin lock and it will be released by calling
	 * `release_cmd_queue_lock` callback.
	 * Context: normal.
	 */
	int (*acquire_cmd_queue_lock)(struct gcip_mailbox *mailbox, bool try);
	/*
	 * Releases the lock of cmd_queue which is acquired by calling `acquire_cmd_queue_lock`.
	 * Context: normal.
	 */
	void (*release_cmd_queue_lock)(struct gcip_mailbox *mailbox);
	/*
	 * Gets the sequence number of @cmd queue element.
	 * Context: normal.
	 */
	u64 (*get_cmd_elem_seq)(struct gcip_mailbox *mailbox, void *cmd);
	/*
	 * Sets the sequence number of @cmd queue element.
	 * Context: normal.
	 */
	void (*set_cmd_elem_seq)(struct gcip_mailbox *mailbox, void *cmd, u64 seq);
	/*
	 * Gets the code of @cmd queue element.
	 * Context: normal.
	 */
	u32 (*get_cmd_elem_code)(struct gcip_mailbox *mailbox, void *cmd);

	/*
	 * Gets the size of mailbox response queue.
	 * Context: normal.
	 */
	u32 (*get_resp_queue_size)(struct gcip_mailbox *mailbox);
	/*
	 * Gets the head of mailbox response queue.
	 * Context: normal and in_interrupt().
	 */
	u32 (*get_resp_queue_head)(struct gcip_mailbox *mailbox);
	/*
	 * Gets the tail of mailbox response queue.
	 * Context: normal and in_interrupt().
	 */
	u32 (*get_resp_queue_tail)(struct gcip_mailbox *mailbox);
	/*
	 * Increases the head of mailbox response queue by @inc.
	 * Context: normal and in_interrupt().
	 */
	void (*inc_resp_queue_head)(struct gcip_mailbox *mailbox, u32 inc);
	/*
	 * Acquires the lock of resp_queue. If @try is true, "_trylock" functions can be used, but
	 * also it can be ignored. Returns 1 if succeed, 0 if failed. This callback will be called
	 * in the following situations.
	 * - Fetch response(s) from the resp_queue.
	 * The lock can be a mutex lock or a spin lock. However, if @try is considered and the
	 * "_trylock" is used, it must be a spin lock only.
	 * The lock will be released by calling `release_resp_queue_lock` callback.
	 * Context: normal and in_interrupt().
	 */
	int (*acquire_resp_queue_lock)(struct gcip_mailbox *mailbox, bool try);
	/*
	 * Releases the lock of resp_queue which is acquired by calling `acquire_resp_queue_lock`.
	 * Context: normal and in_interrupt().
	 */
	void (*release_resp_queue_lock)(struct gcip_mailbox *mailbox);
	/*
	 * Gets the sequence number of @resp queue element.
	 * Context: normal and in_interrupt().
	 */
	u64 (*get_resp_elem_seq)(struct gcip_mailbox *mailbox, void *resp);
	/*
	 * Sets the sequence number of @resp queue element.
	 * Context: normal and in_interrupt().
	 */
	void (*set_resp_elem_seq)(struct gcip_mailbox *mailbox, void *resp, u64 seq);
	/*
	 * Gets the status of @resp queue element.
	 * Context: normal and in_interrupt().
	 */
	u16 (*get_resp_elem_status)(struct gcip_mailbox *mailbox, void *resp);
	/*
	 * Sets the status of @resp queue element.
	 * Context: normal and in_interrupt().
	 */
	void (*set_resp_elem_status)(struct gcip_mailbox *mailbox, void *resp, u16 status);

	/*
	 * Acquires the lock of wait_list. If @irqsave is true, "_irqsave" functions can be used to
	 * store the irq state to @flags, but also it can be ignored.
	 * This callback will be called in following situations.
	 * - Push a waiting response to the @mailbox->wait_list.
	 * - Delete a waiting response from the @mailbox->wait_list.
	 * - Handle an arrived response and delete it from the @mailbox->wait_list.
	 * - Flush the asynchronous responses in the @mailbox->wait_list when release the @mailbox.
	 * The lock can be a mutex lock or a spin lock. However, if @irqsave is considered and
	 * "_irqsave" is used, it must be spin lock only.
	 * The lock will be released by calling `release_wait_list_lock` callback.
	 * Context: normal and in_interrupt().
	 */
	void (*acquire_wait_list_lock)(struct gcip_mailbox *mailbox, bool irqsave,
				       unsigned long *flags);
	/*
	 * Releases the lock of wait_list which is acquired by calling `acquire_wait_list_lock`.
	 * If @irqsave is true, restores @flags from `acquire_wait_list_lock` to the irq state.
	 * Or it can be ignored, if @irqsave was not considered in the `acquire_wait_list_lock`.
	 * Context: normal and in_interrupt().
	 */
	void (*release_wait_list_lock)(struct gcip_mailbox *mailbox, bool irqrestore,
				       unsigned long flags);

	/* Optional. */
	/*
	 * Waits for the cmd queue of @mailbox has a available space for putting the command. If
	 * the queue has a space, returns 0. Otherwise, returns error as non-zero value. It depends
	 * on the implementation details, but it is okay to return right away with error when the
	 * queue is full. If this callback returns an error, `gcip_mailbox_send_cmd` function or
	 * `gcip_mailbox_put_cmd` function will return that error too. This callback is called with
	 * the `cmd_queue_lock` being held.
	 *
	 * Note: if this callback is NULL, it will simply check the fullness of cmd_queue and
	 * return -EAGAIN error right away if it is full. Please refer the implementation of the
	 * `gcip_mailbox_enqueue_cmd` function.
	 *
	 * Context: normal.
	 */
	int (*wait_for_cmd_queue_not_full)(struct gcip_mailbox *mailbox);
	/*
	 * This callback will be called before putting the @resp into @mailbox->wait_list and
	 * putting @cmd of @resp into the command queue. After this callback returns, the consumer
	 * is able to start processing it and the mailbox is going to wait for it. Therefore, this
	 * callback is the final checkpoint of deciding whether it is good to wait for the response
	 * or not. If you don't want to wait for it, return a non-zero value error.
	 *
	 * If the implement side has its own wait queue, this callback is suitable to put @resp or
	 * @awaiter into that.
	 *
	 * If @resp is synchronous, @awaiter will be NULL.
	 *
	 * Context: normal.
	 */
	int (*before_enqueue_wait_list)(struct gcip_mailbox *mailbox, void *resp,
					struct gcip_mailbox_resp_awaiter *awaiter);
	/*
	 * This callback will be called after putting the @cmd to the command queue. It can be used
	 * for triggering the doorbell. Also, @mailbox->cur_seq will be increased by the return
	 * value. If error occurs, returns negative value and @mailbox->cur_seq will not be changed
	 * in that case. If this callback is not defined, @mailbox->cur_seq will be increased by 1
	 * each time cmd enters the queue. This is called with the `cmd_queue_lock` being held.
	 * Context: normal.
	 */
	int (*after_enqueue_cmd)(struct gcip_mailbox *mailbox, void *cmd);
	/*
	 * This callback will be called after fetching responses. It can be used for triggering
	 * a signal to break up waiting consuming the response queue. This is called without
	 * holding any locks.
	 * - @num_resps: the number of fetched responses.
	 * Context: normal and in_interrupt().
	 */
	void (*after_fetch_resps)(struct gcip_mailbox *mailbox, u32 num_resps);
	/*
	 * Before handling each fetched responses, this callback will be called. If this callback
	 * is not defined or returns true, the mailbox will handle the @resp normally. If the @resp
	 * should not be handled, returns false. This is called without holding any locks.
	 * Context: normal and in_interrupt().
	 */
	bool (*before_handle_resp)(struct gcip_mailbox *mailbox, const void *resp);
	/*
	 * Handles the asynchronous response which arrives well. How to handle it depends on the
	 * chip implementation. However, @awaiter should be released by calling the
	 * `gcip_mailbox_release_awaiter` function when the kernel driver doesn't need
	 * @awaiter anymore. This is called with the `wait_list_lock` being held.
	 * Context: normal and in_interrupt().
	 */
	void (*handle_awaiter_arrived)(struct gcip_mailbox *mailbox,
				       struct gcip_mailbox_resp_awaiter *awaiter);
	/*
	 * Handles the timed out asynchronous response. How to handle it depends on the chip
	 * implementation. However, @awaiter should be released by calling the
	 * `gcip_mailbox_release_awaiter` function when the kernel driver doesn't need
	 * @awaiter anymore. This is called without holding any locks.
	 * Context: normal and in_interrupt().
	 */
	void (*handle_awaiter_timedout)(struct gcip_mailbox *mailbox,
					struct gcip_mailbox_resp_awaiter *awaiter);
	/*
	 * Cleans up asynchronous response which is not arrived yet, but also not timed out.
	 * The @awaiter should be marked as unprocessable to make it not to be processed by
	 * the `handle_awaiter_arrived` or `handle_awaiter_timedout` callbacks in race
	 * conditions. Don't have to release @awaiter of this function by calling the
	 * `gcip_mailbox_release_awaiter` function. It will be released internally. This is
	 * called with the `wait_list_lock` being held.
	 * Context: normal.
	 */
	void (*flush_awaiter)(struct gcip_mailbox *mailbox,
			      struct gcip_mailbox_resp_awaiter *awaiter);
	/*
	 * Releases the @data which was passed to the `gcip_mailbox_put_cmd` function. This is
	 * called without holding any locks.
	 * Context: normal and in_interrupt().
	 */
	void (*release_awaiter_data)(void *data);
};

struct gcip_mailbox {
	/* Device used for logging and memory allocation. */
	struct device *dev;
	/* Warp bit for both cmd and resp queue. */
	u64 queue_wrap_bit;
	/* Cmd sequence number. */
	u64 cur_seq;

	/* Cmd queue pointer. */
	void *cmd_queue;
	/* Size of element of cmd queue. */
	u32 cmd_elem_size;

	/* Resp queue pointer. */
	void *resp_queue;
	/* Size of element of resp queue. */
	u32 resp_elem_size;

	/* List of commands that need to wait for responses. */
	struct list_head wait_list;
	/* Queue for waiting for the wait_list to be consumed. */
	wait_queue_head_t wait_list_waitq;

	/* Mailbox timeout in milliseconds. */
	u32 timeout;
	/* Mailbox operators. */
	const struct gcip_mailbox_ops *ops;
	/* User-defined data. */
	void *data;

	/*
	 * The flag to specify sequence numbers of command responses are not
	 * required to be in order.
	 */
	bool ignore_seq_order;
};

/* Arguments for gcip_mailbox_init. See struct gcip_mailbox for details. */
struct gcip_mailbox_args {
	struct device *dev;
	u32 queue_wrap_bit;

	void *cmd_queue;
	u32 cmd_elem_size;

	void *resp_queue;
	u32 resp_elem_size;

	u32 timeout;
	const struct gcip_mailbox_ops *ops;
	void *data;

	bool ignore_seq_order;
};

/* Initializes a mailbox object. */
int gcip_mailbox_init(struct gcip_mailbox *mailbox, const struct gcip_mailbox_args *args);

/* Releases a mailbox object which is initialized by gcip_mailbox_init */
void gcip_mailbox_release(struct gcip_mailbox *mailbox);

/*
 * Fetches and handles responses, then wakes up threads that are waiting for a response.
 * To consume response queue and get responses, this function should be used as deferred work
 * such as `struct work_struct` or `struct kthread_work`.
 *
 * Note: this worker is scheduled in the IRQ handler, to prevent use-after-free or race-condition
 * bugs, cancel all works before free the mailbox.
 */
void gcip_mailbox_consume_responses_work(struct gcip_mailbox *mailbox);

/*
 * Pushes an element to cmd queue and waits for the response (synchronous).
 * Returns -ETIMEDOUT if no response is received within mailbox->timeout msecs.
 *
 * Returns the code of response, or a negative errno on error.
 * @resp is updated with the response, as to retrieve returned retval field.
 */
int gcip_mailbox_send_cmd(struct gcip_mailbox *mailbox, void *cmd, void *resp);

/*
 * Executes @cmd command asynchronously. This function returns an instance of
 * `struct gcip_mailbox_resp_awaiter` which handles the arrival and time-out of the response.
 * The implementation side can cancel the asynchronous response by calling the
 * `gcip_mailbox_cancel_awaiter` or `gcip_mailbox_cancel_awaiter_timeout` function with it.
 *
 * Arrived asynchronous response will be handled by `handle_awaiter_arrived` callback and timed out
 * asynchronous response will be handled by `handle_awaiter_timedout` callback. Those callbacks
 * will pass the @awaiter as a parameter which is the same with the return of this function.
 * The response can be accessed from `resp` member of it. Also, the @data passed to this function
 * can be accessed from `data` member variable of it. The @awaiter must be released by calling
 * the `gcip_mailbox_release_awaiter` function when it is not needed anymore.
 *
 * If the mailbox is released before the response arrives, all the waiting asynchronous responses
 * will be flushed. In this case, the `flush_awaiter` callback will be called for that response
 * and @awaiter don't have to be released by the implementation side.
 * (i.e, the `gcip_mailbox_release_awaiter` function will be called internally.)
 *
 * The caller defines the way of cleaning up the @data to the `release_awaiter_data` callback.
 * This callback will be called when the `gcip_mailbox_release_awaiter` function is called or
 * the response is flushed.
 *
 * If this function fails to request the command, it will return the error pointer. In this case,
 * the caller should free @data explicitly. (i.e, the callback `release_awaiter_data` will not
 * be.)
 *
 * Note: the asynchronous responses fetched from @resp_queue should be released by calling the
 * `gcip_mailbox_release_awaiter` function.
 *
 * Note: if the life cycle of the mailbox is longer than the caller part, you should make sure
 * that the callbacks don't access the variables of caller part after the release of it.
 *
 * Note: if you don't need the result of the response (e.g., if you pass @resp as NULL), you
 * can release the returned awaiter right away by calling the `gcip_mailbox_release_awaiter`
 * function.
 */
struct gcip_mailbox_resp_awaiter *gcip_mailbox_put_cmd(struct gcip_mailbox *mailbox, void *cmd,
						       void *resp, void *data);

/*
 * Cancels awaiting the asynchronous response.
 * This function will remove @awaiter from the waiting list to make it not to be handled by the
 * arrived callback. Also, it will cancel the timeout work of @awaiter synchronously. Therefore,
 * AFTER the return of this function, you can guarantee that arrived or timedout callback will
 * not be called for @awaiter.
 *
 * However, by the race condition, you must note that arrived or timedout callback can be executed
 * BEFORE this function returns. (i.e, this function and arrived/timedout callback is called at the
 * same time but the callback acquired the lock earlier.)
 *
 * Note: this function will cancel or wait for the completion of arrived or timedout callbacks
 * synchronously. Therefore, make sure that the caller side doesn't hold any locks which can be
 * acquired by the arrived or timedout callbacks.
 *
 * If you already got a response of @awaiter and want to ensure that timedout handler is finished,
 * you can use the `gcip_mailbox_cancel_awaiter_timeout` function instead.
 */
void gcip_mailbox_cancel_awaiter(struct gcip_mailbox_resp_awaiter *awaiter);

/*
 * Cancels the timeout work of the asynchronous response. In normally, the response arrives and
 * the timeout is canceled, or the response timed out and the timeout handler executes. However,
 * rarely, the response handler cancels the timeout handler while it has been already in progress.
 * To handle this and ensure any in-process timeout handler has been able to exit cleanly, it is
 * recommended to call this function after fetching the asynchronous response even though the
 * response arrived successfully.
 *
 * Note: this function will cancel or wait for the completion of timedout callbacks synchronously.
 * Therefore, make sure that the caller side doesn't hold any locks which can be acquired by the
 * timedout callbacks.
 *
 * If you haven't gotten a response of @awaiter yet and want to make it not to be processed by
 * arrived and timedout callbacks, use the `gcip_mailbox_cancel_awaiter` function.
 */
void gcip_mailbox_cancel_awaiter_timeout(struct gcip_mailbox_resp_awaiter *awaiter);

/*
 * Releases @awaiter. Every fetched (arrived or timed out) asynchronous responses should be
 * released by calling this. It will call the `release_awaiter_data` callback internally.
 */
void gcip_mailbox_release_awaiter(struct gcip_mailbox_resp_awaiter *awaiter);

/*
 * Consume one response and handle it. This can be used for consuming one response quickly and then
 * schedule `gcip_mailbox_consume_responses_work` work in the IRQ handler of mailbox.
 */
void gcip_mailbox_consume_one_response(struct gcip_mailbox *mailbox, void *resp);

/* Getters for member variables of the `struct gcip_mailbox`. */

static inline u64 gcip_mailbox_get_cur_seq(struct gcip_mailbox *mailbox)
{
	return mailbox->cur_seq;
}

static inline void *gcip_mailbox_get_cmd_queue(struct gcip_mailbox *mailbox)
{
	return mailbox->cmd_queue;
}

static inline u32 gcip_mailbox_get_cmd_elem_size(struct gcip_mailbox *mailbox)
{
	return mailbox->cmd_elem_size;
}

static inline void *gcip_mailbox_get_resp_queue(struct gcip_mailbox *mailbox)
{
	return mailbox->resp_queue;
}

static inline u32 gcip_mailbox_get_resp_elem_size(struct gcip_mailbox *mailbox)
{
	return mailbox->resp_elem_size;
}

static inline u64 gcip_mailbox_get_queue_wrap_bit(struct gcip_mailbox *mailbox)
{
	return mailbox->queue_wrap_bit;
}

static inline struct list_head *gcip_mailbox_get_wait_list(struct gcip_mailbox *mailbox)
{
	return &mailbox->wait_list;
}

static inline u32 gcip_mailbox_get_timeout(struct gcip_mailbox *mailbox)
{
	return mailbox->timeout;
}

static inline void *gcip_mailbox_get_data(struct gcip_mailbox *mailbox)
{
	return mailbox->data;
}

#endif /* __GCIP_MAILBOX_H__ */
