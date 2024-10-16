// SPDX-License-Identifier: GPL-2.0
/*
 * GXP client structure.
 *
 * Copyright (C) 2021 Google LLC
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <gcip/gcip-pm.h>

#include "gxp-client.h"
#include "gxp-dma.h"
#include "gxp-internal.h"
#include "gxp-pm.h"
#include "gxp-vd.h"
#include "gxp.h"

struct gxp_client *gxp_client_create(struct gxp_dev *gxp)
{
	struct gxp_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	client->gxp = gxp;
	lockdep_register_key(&client->key);
	__init_rwsem(&client->semaphore, "&client->semaphore", &client->key);
	client->has_block_wakelock = false;
	client->has_vd_wakelock = false;
	client->requested_states = off_states;
	client->vd = NULL;

	return client;
}

void gxp_client_destroy(struct gxp_client *client)
{
	struct gxp_dev *gxp = client->gxp;
	int core;

	if (client->vd && client->vd->state != GXP_VD_OFF) {
		down_write(&gxp->vd_semaphore);
		gxp_vd_stop(client->vd);
		up_write(&gxp->vd_semaphore);
	}

	if (client->vd && client->has_block_wakelock) {
		down_write(&gxp->vd_semaphore);
		gxp_vd_block_unready(client->vd);
		up_write(&gxp->vd_semaphore);
	}

	for (core = 0; core < GXP_NUM_CORES; core++) {
		if (client->mb_eventfds[core])
			gxp_eventfd_put(client->mb_eventfds[core]);
	}

#if (IS_ENABLED(CONFIG_GXP_TEST) || IS_ENABLED(CONFIG_ANDROID)) &&             \
	!IS_ENABLED(CONFIG_GXP_GEM5)
	if (client->tpu_file) {
		if (client->vd) {
			if (gxp->before_unmap_tpu_mbx_queue)
				gxp->before_unmap_tpu_mbx_queue(gxp, client);
			if (gxp_is_direct_mode(gxp))
				gxp_dma_unmap_tpu_buffer(gxp,
							 client->vd->domain,
							 client->mbx_desc);
		}
		fput(client->tpu_file);
		client->tpu_file = NULL;
	}
#endif

	if (client->has_block_wakelock) {
		gcip_pm_put(client->gxp->power_mgr->pm);
		gxp_pm_update_requested_power_states(
			gxp, client->requested_states, off_states);
	}

	if (client->vd) {
		down_write(&gxp->vd_semaphore);
		gxp_vd_release(client->vd);
		up_write(&gxp->vd_semaphore);
	}

	lockdep_unregister_key(&client->key);
	kfree(client);
}

static int gxp_set_secure_vd(struct gxp_virtual_device *vd)
{
	struct gxp_dev *gxp = vd->gxp;

	if (gxp_is_direct_mode(gxp))
		return 0;

	mutex_lock(&gxp->secure_vd_lock);
	if (gxp->secure_vd) {
		mutex_unlock(&gxp->secure_vd_lock);
		return -EEXIST;
	}
	vd->is_secure = true;
	gxp->secure_vd = vd;
	mutex_unlock(&gxp->secure_vd_lock);

	return 0;
}

int gxp_client_allocate_virtual_device(struct gxp_client *client,
				       uint core_count, u8 flags)
{
	struct gxp_dev *gxp = client->gxp;
	struct gxp_virtual_device *vd;
	int ret;

	lockdep_assert_held(&client->semaphore);
	if (client->vd) {
		dev_err(gxp->dev,
			"Virtual device was already allocated for client\n");
		return -EINVAL;
	}

	down_write(&gxp->vd_semaphore);
	vd = gxp_vd_allocate(gxp, core_count);
	if (IS_ERR(vd)) {
		ret = PTR_ERR(vd);
		dev_err(gxp->dev,
			"Failed to allocate virtual device for client (%d)\n",
			ret);
		goto error;
	}
	if (flags & GXP_ALLOCATE_VD_SECURE) {
		ret = gxp_set_secure_vd(vd);
		if (ret)
			goto error_vd_release;
	}
	if (client->has_block_wakelock) {
		ret = gxp_vd_block_ready(vd);
		if (ret)
			goto error_vd_release;
	}
	up_write(&gxp->vd_semaphore);

	client->vd = vd;
	return 0;

error_vd_release:
	gxp_vd_release(vd);
error:
	up_write(&gxp->vd_semaphore);
	return ret;
}

static int gxp_client_request_power_states(struct gxp_client *client,
					   struct gxp_power_states requested_states)
{
	struct gxp_dev *gxp = client->gxp;
	int ret;

	if (gxp->request_power_states) {
		ret = gxp->request_power_states(client, requested_states);
		if (ret != -EOPNOTSUPP)
			return ret;
	}
	gxp_pm_update_requested_power_states(gxp, client->requested_states,
					     requested_states);
	client->requested_states = requested_states;
	return 0;
}

int gxp_client_acquire_block_wakelock(struct gxp_client *client,
				      bool *acquired_wakelock)
{
	struct gxp_dev *gxp = client->gxp;
	int ret;

	lockdep_assert_held(&client->semaphore);
	if (!client->has_block_wakelock) {
		ret = gcip_pm_get(gxp->power_mgr->pm);
		if (ret)
			return ret;
		*acquired_wakelock = true;
		if (client->vd) {
			down_write(&gxp->vd_semaphore);
			ret = gxp_vd_block_ready(client->vd);
			up_write(&gxp->vd_semaphore);
			if (ret)
				goto err_wakelock_release;
		}
	} else {
		*acquired_wakelock = false;
	}
	client->has_block_wakelock = true;

	/*
	 * Update client's TGID+PID in case the process that opened
	 * /dev/gxp is not the one that called this IOCTL.
	 */
	client->tgid = current->tgid;
	client->pid = current->pid;

	return 0;

err_wakelock_release:
	if (*acquired_wakelock) {
		gcip_pm_put(gxp->power_mgr->pm);
		*acquired_wakelock = false;
	}
	return ret;
}

void gxp_client_release_block_wakelock(struct gxp_client *client)
{
	struct gxp_dev *gxp = client->gxp;

	lockdep_assert_held(&client->semaphore);
	if (!client->has_block_wakelock)
		return;

	gxp_client_release_vd_wakelock(client);

	if (client->vd) {
		down_write(&gxp->vd_semaphore);
		gxp_vd_block_unready(client->vd);
		up_write(&gxp->vd_semaphore);
	}

	gcip_pm_put(gxp->power_mgr->pm);
	client->has_block_wakelock = false;
}

int gxp_client_acquire_vd_wakelock(struct gxp_client *client,
				   struct gxp_power_states requested_states)
{
	struct gxp_dev *gxp = client->gxp;
	int ret = 0;
	enum gxp_virtual_device_state orig_state;

	lockdep_assert_held(&client->semaphore);
	if (!client->has_block_wakelock) {
		dev_err(gxp->dev,
			"Must hold BLOCK wakelock to acquire VIRTUAL_DEVICE wakelock\n");
		return -EINVAL;
	}

	if (client->vd->state == GXP_VD_UNAVAILABLE) {
		dev_err(gxp->dev,
			"Cannot acquire VIRTUAL_DEVICE wakelock on a broken virtual device\n");
		return -ENODEV;
	}

	if (!client->has_vd_wakelock) {
		down_write(&gxp->vd_semaphore);
		orig_state = client->vd->state;
		if (client->vd->state == GXP_VD_READY || client->vd->state == GXP_VD_OFF)
			ret = gxp_vd_run(client->vd);
		else
			ret = gxp_vd_resume(client->vd);
		up_write(&gxp->vd_semaphore);
	}

	if (ret)
		goto out;

	ret = gxp_client_request_power_states(client, requested_states);
	if (ret)
		goto out_release_vd_wakelock;

	client->has_vd_wakelock = true;
	return 0;

out_release_vd_wakelock:
	if (!client->has_vd_wakelock) {
		down_write(&gxp->vd_semaphore);
		if (orig_state == GXP_VD_READY || orig_state == GXP_VD_OFF)
			gxp_vd_stop(client->vd);
		else
			gxp_vd_suspend(client->vd);
		up_write(&gxp->vd_semaphore);
	}
out:
	return ret;
}

void gxp_client_release_vd_wakelock(struct gxp_client *client)
{
	struct gxp_dev *gxp = client->gxp;

	lockdep_assert_held(&client->semaphore);
	if (!client->has_vd_wakelock)
		return;

	/*
	 * Currently VD state will not be GXP_VD_UNAVAILABLE if
	 * has_vd_wakelock is true. Add this check just in case
	 * GXP_VD_UNAVAILABLE will occur in more scenarios in the
	 * future.
	 */
	if (client->vd->state == GXP_VD_UNAVAILABLE)
		return;

	down_write(&gxp->vd_semaphore);
	gxp_vd_suspend(client->vd);
	up_write(&gxp->vd_semaphore);

	gxp_client_request_power_states(client, off_states);
	client->has_vd_wakelock = false;
}

bool gxp_client_has_available_vd(struct gxp_client *client, const char *name)
{
	struct gxp_dev *gxp = client->gxp;

	lockdep_assert_held(&client->semaphore);
	if (!client->vd) {
		dev_err(gxp->dev,
			"%s requires the client allocate a VIRTUAL_DEVICE\n",
			name);
		return false;
	}
	if (client->vd->state == GXP_VD_UNAVAILABLE) {
		dev_err(gxp->dev, "Cannot do %s on a broken virtual device\n",
			name);
		return false;
	}
	return true;
}
