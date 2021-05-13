/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>

#include "gdma.h"
#include "hw_channel.h"


static int
mana_hwc_create_gdma_cq(struct hw_channel_context *hwc,
    uint64_t queue_size,
    void *ctx, gdma_cq_callback *cb,
    struct gdma_queue *parent_eq,
    struct gdma_queue **queue)
{
	struct gdma_queue_spec spec = {};

	spec.type = GDMA_CQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = queue_size;
	spec.cq.context = ctx;
	spec.cq.callback = cb;
	spec.cq.parent_eq = parent_eq;

	return mana_gd_create_hwc_queue(hwc->gdma_dev, &spec, queue);
}

static int
mana_hwc_create_gdma_eq(struct hw_channel_context *hwc,
    uint64_t queue_size,
    void *ctx, gdma_eq_callback *cb,
    struct gdma_queue **queue)
{
	struct gdma_queue_spec spec = {};

	spec.type = GDMA_EQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = queue_size;
	spec.eq.context = ctx;
	spec.eq.callback = cb;
	spec.eq.log2_throttle_limit = DEFAULT_LOG2_THROTTLING_FOR_ERROR_EQ;

	return mana_gd_create_hwc_queue(hwc->gdma_dev, &spec, queue);
}

static int
mana_hwc_create_cq(struct hw_channel_context *hwc,
    uint16_t q_depth,
    gdma_eq_callback *callback, void *ctx,
    hwc_rx_event_handler_t *rx_ev_hdlr, void *rx_ev_ctx,
    hwc_tx_event_handler_t *tx_ev_hdlr, void *tx_ev_ctx,
    struct hwc_cq **hwc_cq_ptr)
{
	struct gdma_queue *eq, *cq;
	struct gdma_comp *comp_buf;
	struct hwc_cq *hwc_cq;
	uint32_t eq_size, cq_size;
	int err;

	eq_size = roundup_pow_of_two(GDMA_EQE_SIZE * q_depth);
	if (eq_size < MINIMUM_SUPPORTED_PAGE_SIZE)
		eq_size = MINIMUM_SUPPORTED_PAGE_SIZE;

	cq_size = roundup_pow_of_two(GDMA_CQE_SIZE * q_depth);
	if (cq_size < MINIMUM_SUPPORTED_PAGE_SIZE)
		cq_size = MINIMUM_SUPPORTED_PAGE_SIZE;

	hwc_cq = malloc(sizeof(*hwc_cq), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!hwc_cq)
		return ENOMEM;

	err = mana_hwc_create_gdma_eq(hwc, eq_size, ctx, callback, &eq);
	if (err) {
		device_printf(hwc->dev,
		    "Failed to create HWC EQ for RQ: %d\n", err);
		goto out;
	}
	hwc_cq->gdma_eq = eq;

	err = mana_hwc_create_gdma_cq(hwc, cq_size, hwc_cq, mana_hwc_comp_event,
				      eq, &cq);
	if (err) {
		device_printf(hwc->dev,
		    "Failed to create HWC CQ for RQ: %d\n", err);
		goto out;
	}
	hwc_cq->gdma_cq = cq;

	comp_buf = mallocarray(q_depth, sizeof(struct gdma_comp),
	    M_DEVBUF, M_WAITOK);
	if (!comp_buf) {
		err = ENOMEM;
		goto out;
	}

	hwc_cq->hwc = hwc;
	hwc_cq->comp_buf = comp_buf;
	hwc_cq->queue_depth = q_depth;
	hwc_cq->rx_event_handler = rx_ev_hdlr;
	hwc_cq->rx_event_ctx = rx_ev_ctx;
	hwc_cq->tx_event_handler = tx_ev_hdlr;
	hwc_cq->tx_event_ctx = tx_ev_ctx;

	*hwc_cq_ptr = hwc_cq;
	return 0;
out:
	mana_hwc_destroy_cq(hwc->gdma_dev->gdma_context, hwc_cq);
	return err;
}

static int
mana_hwc_init_inflight_msg(struct hw_channel_context *hwc, uint16_t num_msg)
{
	int err;

	sema_init(&hwc->sema, num_msg, "gdma hwc sema");

	err = mana_gd_alloc_res_map(num_msg, &hwc->inflight_msg_res,
	    "gdma hwc res lock");
	if (err)
		device_printf(hwc->dev,
		    "Failed to init inflight_msg_res: %d\n", err);

	return (err);
}

static int
mana_hwc_init_queues(struct hw_channel_context *hwc, uint16_t q_depth,
    uint32_t max_req_msg_size, uint32_t max_resp_msg_size)
{
	struct hwc_wq *hwc_rxq = NULL;
	struct hwc_wq *hwc_txq = NULL;
	struct hwc_cq *hwc_cq = NULL;
	int err;

	err = mana_hwc_init_inflight_msg(hwc, q_depth);
	if (err)
		return err;

	/* CQ is shared by SQ and RQ, so CQ's queue depth is the sum of SQ
	 * queue depth and RQ queue depth.
	 */
	err = mana_hwc_create_cq(hwc, q_depth * 2,
				 mana_hwc_init_event_handler, hwc,
				 mana_hwc_rx_event_handler, hwc,
				 mana_hwc_tx_event_handler, hwc, &hwc_cq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC CQ: %d\n", err);
		goto out;
	}
	hwc->cq = hwc_cq;

	err = mana_hwc_create_wq(hwc, GDMA_RQ, q_depth, max_req_msg_size,
				 hwc_cq, &hwc_rxq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC RQ: %d\n", err);
		goto out;
	}
	hwc->rxq = hwc_rxq;

	err = mana_hwc_create_wq(hwc, GDMA_SQ, q_depth, max_resp_msg_size,
				 hwc_cq, &hwc_txq);
	if (err) {
		dev_err(hwc->dev, "Failed to create HWC SQ: %d\n", err);
		goto out;
	}
	hwc->txq = hwc_txq;

	hwc->num_inflight_msg = q_depth;
	hwc->max_req_msg_size = max_req_msg_size;

	return 0;
out:
	if (hwc_txq)
		mana_hwc_destroy_wq(hwc, hwc_txq);

	if (hwc_rxq)
		mana_hwc_destroy_wq(hwc, hwc_rxq);

	if (hwc_cq)
		mana_hwc_destroy_cq(hwc->gdma_dev->gdma_context, hwc_cq);

	mana_gd_free_res_map(&hwc->inflight_msg_res);
	return err;
}

int
mana_hwc_create_channel(struct gdma_context *gc)
{
	uint32_t max_req_msg_size, max_resp_msg_size;
	struct gdma_dev *gd = &gc->hwc;
	struct hw_channel_context *hwc;
	uint16_t q_depth_max;
	int err;

	hwc = malloc(sizeof(*hwc), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!hwc)
		return ENOMEM;

	gd->gdma_context = gc;
	gd->driver_data = hwc;
	hwc->gdma_dev = gd;
	hwc->dev = gc->dev;

	/* HWC's instance number is always 0. */
	gd->dev_id.as_uint32 = 0;
	gd->dev_id.type = GDMA_DEVICE_HWC;

	gd->pdid = INVALID_PDID;
	gd->doorbell = INVALID_DOORBELL;

	err = mana_hwc_init_queues(hwc, HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH,
				   HW_CHANNEL_MAX_REQUEST_SIZE,
				   HW_CHANNEL_MAX_RESPONSE_SIZE);
	if (err) {
		device_printf(hwc->dev, "Failed to initialize HWC: %d\n",
		    err);
		goto out;
	}

	err = mana_hwc_establish_channel(gc, &q_depth_max, &max_req_msg_size,
					 &max_resp_msg_size);
	if (err) {
		device_printf(hwc->dev, "Failed to establish HWC: %d\n", err);
		goto out;
	}

	err = mana_hwc_test_channel(gc->hwc.driver_data,
				    HW_CHANNEL_VF_BOOTSTRAP_QUEUE_DEPTH,
				    max_req_msg_size, max_resp_msg_size);
	if (err) {
		device_printf(hwc->dev, "Failed to test HWC: %d\n", err);
		goto out;
	}

	return 0;
out:
	free(hwc, M_DEVBUF);
	return (err);
}
