
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/time.h>
#include <sys/eventhandler.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/in_cksum.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>
#ifdef RSS
#include <net/rss_config.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "mana.h"

static void
mana_rss_key_fill(void *k, size_t size)
{
	static bool rss_key_generated = false;
	static uint8_t rss_key[MANA_HASH_KEY_SIZE];

	KASSERT(size <= MANA_HASH_KEY_SIZE,
	    ("Request more buytes than MANA RSS key can hold"));

	if (!rss_key_generated) {
		arc4random_buf(rss_key, MANA_HASH_KEY_SIZE);
		rss_key_generated = true;
	}
	memcpy(k, rss_key, size);
}

static int
mana_ifmedia_change(struct ifnet *ifp __unused)
{
	return EOPNOTSUPP;
}

static void
mana_ifmedia_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct mana_port_context *apc = if_getsoftc(ifp);

	if (!apc) {
		if_printf(ifp, "Port not available\n");
		return;
	}

	MANA_APC_LOCK_LOCK(apc);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!apc->port_is_up) {
		MANA_APC_LOCK_UNLOCK(apc);
		mana_trc_info(NULL, "Port %u link is down\n", apc->port_idx);
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;
	ifmr->ifm_active |= IFM_UNKNOWN | IFM_FDX;

	MANA_APC_LOCK_UNLOCK(apc);
}

static uint64_t
mana_get_counter(struct ifnet *ifp, ift_counter cnt)
{
	return (if_get_counter_default(ifp, cnt));
}

static void
mana_qflush(struct ifnet *ifp)
{
	if_qflush(ifp);
}

static int
mana_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	//struct ifreq *ifr = (struct ifreq *)data;
	int rc = 0;

#if 1
	switch (command) {
	case SIOCSIFMTU:
	case SIOCSIFFLAGS:
	default:
		rc = ether_ioctl(ifp, command, data);
		break;
	}
#endif

	return (rc);
}

static inline int
mana_alloc_rx_mbuf(struct mana_port_context *apc, mana_rxq *rxq,
    struct mana_recv_buf_oob *rx_oob)
{
	bus_dma_segment_t segs[1];
	int nsegs, err;
	uint32_t mlen;

	/* If previously allocated mbuf exists */
	if (unlikely(rx_oob->mbuf))
		return 0;

	rx_oob->mbuf = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
	    rxq->datasize);
	if (unlikely(rx_oob->mbuf == NULL)) {
		rx_info->mbuf = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		if (unlikely(rx_oob->mbuf == NULL)) {
			return ENOMEM;
		}
		mlen = MCLBYTES;
	} else {
		mlen = rxq->datasize;
	}

	rx_oob->mbuf->m_pkthdr.len = rx_oob->mbuf->m_len = mlen;

	err = bus_dmamap_load_mbuf_sg(apc->rx_buf_tag, rx_oob->dma_map,
	    rx_oob->mbuf, segs, &nsegs, BUS_DMA_NOWAIT);

	if (unlikely((err != 0) || (nsegs != 1))) {
		mana_trc_dbg(NULL, "Failed to map mbuf, error: %d, "
		    "nsegs: %d\n", err, nsegs);
		goto error.
	}

	bus_dmamap_sync(apc->rx_buf_tag, rx_oob->dma_map,
	    BUS_DMASYNC_PREREAD);

	rx_oob->num_sge = 1;
	rx_oob->sgl[0].address = segs[0].ds_addr;
	rx_oob->sgl[0].size = mlen;
	rx_oob->sgl[0].mem_key = apc->ac->gdma_dev->gpa_mkey;

	return 0;

error:
	m_freem(rx_oob->mbuf);
	rx_oob->mbuf = NULL;
	return EFAULT;
}

static void
mana_free_rx_mbuf(struct mana_port_context *apc, mana_rxq *rxq,
    struct mana_recv_buf_oob *rx_oob)
{
	bus_dmamap_sync(apc->rx_buf_tag, rx_oob->dma_map,
	    BUS_DMASYNC_POSTREAD);
	bus_dmamap_unload((apc->rx_buf_tag, rx_oob->dma_map);
	m_freem(rx_oob->mbuf);
	rx_oob->mbuf = NULL;
}

static int
mana_start_xmit(struct ifnet *ifp, struct mbuf *m)
{
	if (unlikely((if_getdrvflags(ifp) & IFF_DRV_RUNNING) == 0))
		return ENODEV;

	return (EBUSY);
}

static void
mana_cleanup_port_context(struct mana_port_context *apc)
{
	bus_dma_tag_destroy(apc->rx_buf_tag);
	apc->rx_buf_tag = NULL;

	free(apc->rxqs, M_DEVBUF);
	apc->rxqs = NULL;
}

static int
mana_init_port_context(struct mana_port_context *apc)
{
	device_t dev = apc->ac->gdma_dev->gdma_context->dev;
	int err;

	/* Create DMA tag for rx bufs */
	err = bus_dma_tag_create(bus_get_dma_tag(dev),	/* parent */
	    64, 0,			/* alignment, boundary	*/
	    BUS_SPACE_MAXADDR,		/* lowaddr		*/
	    BUS_SPACE_MAXADDR,		/* highaddr		*/
	    NULL, NULL,			/* filter, filterarg	*/
	    MJUMPAGESIZE,		/* maxsize		*/
	    1,				/* nsegments		*/
	    MJUMPAGESIZE,		/* maxsegsize		*/
	    0,				/* flags		*/
	    NULL, NULL,			/* lockfunc, lockfuncarg*/
	    &apc->rx_buf_tag);
	if (unlikely(err)) {
		device_printf(dev, "Feiled to create RX DMA tag\n");
		return err;
	}

	apc->rxqs = mallocarray(apc->num_queues, sizeof(struct mana_rxq *),
	    M_DEVBUF, M_WAITOK | M_ZERO);

	if (!apc->rxqs) {
		bus_dma_tag_destroy(apc->rx_buf_tag);
		apc->rx_buf_tag = NULL;
		return ENOMEM;
	}

	return 0;
}

static int
mana_send_request(struct mana_context *ac, void *in_buf,
    uint32_t in_len, void *out_buf, uint32_t out_len)
{
	struct gdma_context *gc = ac->gdma_dev->gdma_context;
	struct gdma_resp_hdr *resp = out_buf;
	struct gdma_req_hdr *req = in_buf;
	device_t dev = gc->dev;
	atomic_t activity_id;
	int err;

	req->dev_id = gc->mana.dev_id;
	req->activity_id = atomic_inc_return(&activity_id);

	mana_trc_dbg(NULL, "activity_id  = %u\n", activity_id);

	err = mana_gd_send_request(gc, in_len, in_buf, out_len,
	    out_buf);
	if (err || resp->status) {
		device_printf(dev, "Failed to send mana message: %d, 0x%x\n",
			err, resp->status);
		return err ? err : EPROTO;
	}

	if (req->dev_id.as_uint32 != resp->dev_id.as_uint32 ||
	    req->activity_id != resp->activity_id) {
		device_printf(dev,
		    "Unexpected mana message response: %x,%x,%x,%x\n",
		    req->dev_id.as_uint32, resp->dev_id.as_uint32,
		    req->activity_id, resp->activity_id);
		return EPROTO;
	}

	return 0;
}

static int
mana_verify_resp_hdr(const struct gdma_resp_hdr *resp_hdr,
    const enum mana_command_code expected_code,
    const uint32_t min_size)
{
	if (resp_hdr->response.msg_type != expected_code)
		return EPROTO;

	if (resp_hdr->response.msg_version < GDMA_MESSAGE_V1)
		return EPROTO;

	if (resp_hdr->response.msg_size < min_size)
		return EPROTO;

	return 0;
}

static int
mana_query_device_cfg(struct mana_context *ac, uint32_t proto_major_ver,
    uint32_t proto_minor_ver, uint32_t proto_micro_ver,
    uint16_t *max_num_vports)
{
	struct gdma_context *gc = ac->gdma_dev->gdma_context;
	struct mana_query_device_cfg_resp resp = {};
	struct mana_query_device_cfg_req req = {};
	device_t dev = gc->dev;
	int err = 0;

	mana_gd_init_req_hdr(&req.hdr, MANA_QUERY_DEV_CONFIG,
	    sizeof(req), sizeof(resp));
	req.proto_major_ver = proto_major_ver;
	req.proto_minor_ver = proto_minor_ver;
	req.proto_micro_ver = proto_micro_ver;

	err = mana_send_request(ac, &req, sizeof(req), &resp, sizeof(resp));
	if (err) {
		device_printf(dev, "Failed to query config: %d", err);
		return err;
	}

	err = mana_verify_resp_hdr(&resp.hdr, MANA_QUERY_DEV_CONFIG,
	    sizeof(resp));
	if (err || resp.hdr.status) {
		device_printf(dev, "Invalid query result: %d, 0x%x\n", err,
		    resp.hdr.status);
		if (!err)
			err = EPROTO;
		return err;
	}

	*max_num_vports = resp.max_num_vports;

	mana_trc_dbg(NULL, "mana max_num_vports from device = %d\n",
	    *max_num_vports);

	return 0;
}

static int
mana_query_vport_cfg(struct mana_port_context *apc, uint32_t vport_index,
    uint32_t *max_sq, uint32_t *max_rq, uint32_t *num_indir_entry)
{
	struct mana_query_vport_cfg_resp resp = {};
	struct mana_query_vport_cfg_req req = {};
	int err;

	mana_gd_init_req_hdr(&req.hdr, MANA_QUERY_VPORT_CONFIG,
	    sizeof(req), sizeof(resp));

	req.vport_index = vport_index;

	err = mana_send_request(apc->ac, &req, sizeof(req), &resp,
	    sizeof(resp));
	if (err)
		return err;

	err = mana_verify_resp_hdr(&resp.hdr, MANA_QUERY_VPORT_CONFIG,
	    sizeof(resp));
	if (err)
		return err;

	if (resp.hdr.status)
		return EPROTO;

	*max_sq = resp.max_num_sq;
	*max_rq = resp.max_num_rq;
	*num_indir_entry = resp.num_indirection_ent;

	apc->port_handle = resp.vport;
	memcpy(apc->mac_addr, resp.mac_addr, ETHER_ADDR_LEN);

	return 0;
}

static int
mana_cfg_vport(struct mana_port_context *apc, uint32_t protection_dom_id,
    uint32_t doorbell_pg_id)
{
	struct mana_config_vport_resp resp = {};
	struct mana_config_vport_req req = {};
	int err;

	mana_gd_init_req_hdr(&req.hdr, MANA_CONFIG_VPORT_TX,
	    sizeof(req), sizeof(resp));
	req.vport = apc->port_handle;
	req.pdid = protection_dom_id;
	req.doorbell_pageid = doorbell_pg_id;

	err = mana_send_request(apc->ac, &req, sizeof(req), &resp,
	    sizeof(resp));
	if (err) {
		if_printf(apc->ndev, "Failed to configure vPort: %d\n", err);
		goto out;
	}

	err = mana_verify_resp_hdr(&resp.hdr, MANA_CONFIG_VPORT_TX,
	    sizeof(resp));
	if (err || resp.hdr.status) {
		if_printf(apc->ndev, "Failed to configure vPort: %d, 0x%x\n",
		    err, resp.hdr.status);
		if (!err)
			err = EPROTO;

		goto out;
	}

	apc->tx_shortform_allowed = resp.short_form_allowed;
	apc->tx_vp_offset = resp.tx_vport_offset;
out:
	return err;
}

static int
mana_cfg_vport_steering(struct mana_port_context *apc,
    enum TRI_STATE rx,
    bool update_default_rxobj, bool update_key,
    bool update_tab)
{
	uint16_t num_entries = MANA_INDIRECT_TABLE_SIZE;
	struct mana_cfg_rx_steer_req *req = NULL;
	struct mana_cfg_rx_steer_resp resp = {};
	struct ifnet *ndev = apc->ndev;
	mana_handle_t *req_indir_tab;
	uiint32_t req_buf_size;
	int err;

	req_buf_size = sizeof(*req) + sizeof(mana_handle_t) * num_entries;
	req = malloc(req_buf_size, M_DEVBUF, M_WAITOK | M_ZERO);
	if (!req)
		return ENOMEM;

	mana_gd_init_req_hdr(&req->hdr, MANA_CONFIG_VPORT_RX, req_buf_size,
	    sizeof(resp));

	req->vport = apc->port_handle;
	req->num_indir_entries = num_entries;
	req->indir_tab_offset = sizeof(*req);
	req->rx_enable = rx;
	req->rss_enable = apc->rss_state;
	req->update_default_rxobj = update_default_rxobj;
	req->update_hashkey = update_key;
	req->update_indir_tab = update_tab;
	req->default_rxobj = apc->default_rxobj;

	if (update_key)
		memcpy(&req->hashkey, apc->hashkey, MANA_HASH_KEY_SIZE);

	if (update_tab) {
		req_indir_tab = (mana_handle_t *)(req + 1);
		memcpy(req_indir_tab, apc->rxobj_table,
		       req->num_indir_entries * sizeof(mana_handle_t));
	}

	err = mana_send_request(apc->ac, req, req_buf_size, &resp,
	    sizeof(resp));
	if (err) {
		if_printf(ndev, "Failed to configure vPort RX: %d\n", err);
		goto out;
	}

	err = mana_verify_resp_hdr(&resp.hdr, MANA_CONFIG_VPORT_RX,
	    sizeof(resp));
	if (err) {
		if_printf(ndev, "vPort RX configuration failed: %d\n", err);
		goto out;
	}

	if (resp.hdr.status) {
		if_printf(ndev, "vPort RX configuration failed: 0x%x\n",
		    resp.hdr.status);
		err = EPROTO;
	}
out:
	free(req, M_DEVBUF);
	return err;
}

static int
mana_create_wq_obj(struct mana_port_context *apc,
    mana_handle_t vport,
    uint32_t wq_type, struct mana_obj_spec *wq_spec,
    struct mana_obj_spec *cq_spec,
    mana_handle_t *wq_obj)
{
	struct mana_create_wqobj_resp resp = {};
	struct mana_create_wqobj_req req = {};
	struct ifnet *ndev = apc->ndev;
	int err;

	mana_gd_init_req_hdr(&req.hdr, MANA_CREATE_WQ_OBJ,
	    sizeof(req), sizeof(resp));
	req.vport = vport;
	req.wq_type = wq_type;
	req.wq_gdma_region = wq_spec->gdma_region;
	req.cq_gdma_region = cq_spec->gdma_region;
	req.wq_size = wq_spec->queue_size;
	req.cq_size = cq_spec->queue_size;
	req.cq_moderation_ctx_id = cq_spec->modr_ctx_id;
	req.cq_parent_qid = cq_spec->attached_eq;

	err = mana_send_request(apc->ac, &req, sizeof(req), &resp,
	    sizeof(resp));
	if (err) {
		if_printf(ndev, "Failed to create WQ object: %d\n", err);
		goto out;
	}

	err = mana_verify_resp_hdr(&resp.hdr, MANA_CREATE_WQ_OBJ,
	    sizeof(resp));
	if (err || resp.hdr.status) {
		if_printf(ndev, "Failed to create WQ object: %d, 0x%x\n", err,
		    resp.hdr.status);
		if (!err)
			err = EPROTO;
		goto out;
	}

	if (resp.wq_obj == INVALID_MANA_HANDLE) {
		if_printf(ndev, "Got an invalid WQ object handle\n");
		err = EPROTO;
		goto out;
	}

	*wq_obj = resp.wq_obj;
	wq_spec->queue_index = resp.wq_id;
	cq_spec->queue_index = resp.cq_id;

	return 0;
out:
	return err;
}

static void
mana_destroy_wq_obj(struct mana_port_context *apc, uint32_t wq_type,
    mana_handle_t wq_obj)
{
	struct mana_destroy_wqobj_resp resp = {};
	struct mana_destroy_wqobj_req req = {};
	struct ifnet *ndev = apc->ndev;
	int err;

	mana_gd_init_req_hdr(&req.hdr, MANA_DESTROY_WQ_OBJ,
	    sizeof(req), sizeof(resp));
	req.wq_type = wq_type;
	req.wq_obj_handle = wq_obj;

	err = mana_send_request(apc->ac, &req, sizeof(req), &resp,
	    sizeof(resp));
	if (err) {
		if_printf(ndev, "Failed to destroy WQ object: %d\n", err);
		return;
	}

	err = mana_verify_resp_hdr(&resp.hdr, MANA_DESTROY_WQ_OBJ,
	    sizeof(resp));
	if (err || resp.hdr.status)
		if_printf(ndev, "Failed to destroy WQ object: %d, 0x%x\n",
		    err, resp.hdr.status);
}

static void
mana_init_cqe_poll_buf(struct gdma_comp *cqe_poll_buf)
{
	int i;

	for (i = 0; i < CQE_POLLING_BUFFER; i++)
		memset(&cqe_poll_buf[i], 0, sizeof(struct gdma_comp));
}

static void
mana_destroy_eq(struct gdma_context *gc, struct mana_port_context *apc)
{
	struct gdma_queue *eq;
	int i;

	if (!apc->eqs)
		return;

	for (i = 0; i < apc->num_queues; i++) {
		eq = apc->eqs[i].eq;
		if (!eq)
			continue;

		mana_gd_destroy_queue(gc, eq);
	}

	free(apc->eqs, M_DEVBUF);
	apc->eqs = NULL;
}

static int
mana_create_eq(struct mana_port_context *apc)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;
	struct gdma_queue_spec spec = {};
	int err;
	int i;

	apc->eqs = mallocarry(apc->num_queues, sizeof(struct mana_eq),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (!apc->eqs)
		return ENOMEM;

	spec.type = GDMA_EQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = EQ_SIZE;
	spec.eq.callback = NULL;
	spec.eq.context = apc->eqs;
	spec.eq.log2_throttle_limit = LOG2_EQ_THROTTLE;
	spec.eq.ndev = apc->ndev;

	for (i = 0; i < apc->num_queues; i++) {
		mana_init_cqe_poll_buf(apc->eqs[i].cqe_poll);

		err = mana_gd_create_mana_eq(gd, &spec, &apc->eqs[i].eq);
		if (err)
			goto out;
	}

	return 0;
out:
	mana_destroy_eq(gd->gdma_context, apc);
	return err;
}

static void
mana_deinit_cq(struct mana_port_context *apc, struct mana_cq *cq)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;

	if (!cq->gdma_cq)
		return;

	mana_gd_destroy_queue(gd->gdma_context, cq->gdma_cq);
}

static void
mana_deinit_txq(struct mana_port_context *apc, struct mana_txq *txq)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;

	if (!txq->gdma_sq)
		return;

	/*XXX Flush buf ring here? */
	if (txq->txq_br)
		buf_ring_free(txq->txq_br, M_DEVBUF);

	/*XXX drain taskqueue here? */
	if (txq->enqueue_tq)
		 taskqueue_free(txq->enqueue_tq);

	mana_gd_destroy_queue(gd->gdma_context, txq->gdma_sq);

	mtx_destroy(&txq->txq_mtx);
}

static void
mana_destroy_txq(struct mana_port_context *apc)
{
	int i;

	if (!apc->tx_qp)
		return;

	for (i = 0; i < apc->num_queues; i++) {
		mana_destroy_wq_obj(apc, GDMA_SQ, apc->tx_qp[i].tx_object);

		mana_deinit_cq(apc, &apc->tx_qp[i].tx_cq);

		mana_deinit_txq(apc, &apc->tx_qp[i].txq);
	}

	free(apc->tx_qp, M_DEVBUF);
	apc->tx_qp = NULL;
}

static int
mana_create_txq(struct mana_port_context *apc, struct ifnet *net)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;
	struct mana_obj_spec wq_spec;
	struct mana_obj_spec cq_spec;
	struct gdma_queue_spec spec;
	struct gdma_context *gc;
	struct mana_txq *txq;
	struct mana_cq *cq;
	uint32_t txq_size;
	uint32_t cq_size;
	int err;
	int i;

	apc->tx_qp = mallocarray(apc->num_queues, sizeof(struct mana_tx_qp),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (!apc->tx_qp)
		return ENOMEM;

	/*  The minimum size of the WQE is 32 bytes, hence
	 *  MAX_SEND_BUFFERS_PER_QUEUE represents the maximum number of WQEs
	 *  the SQ can store. This value is then used to size other queues
	 *  to prevent overflow.
	 */
	txq_size = MAX_SEND_BUFFERS_PER_QUEUE * 32;
	CTASSERT(IS_ALIGNED(txq_size, PAGE_SIZE));

	cq_size = MAX_SEND_BUFFERS_PER_QUEUE * COMP_ENTRY_SIZE;
	cq_size = ALIGN(cq_size, PAGE_SIZE);

	gc = gd->gdma_context;

	for (i = 0; i < apc->num_queues; i++) {
		apc->tx_qp[i].tx_object = INVALID_MANA_HANDLE;

		/* Create SQ */
		txq = &apc->tx_qp[i].txq;

		// u64_stats_init(&txq->stats.syncp);
		txq->ndev = net;
		// txq->net_txq = netdev_get_tx_queue(net, i);
		txq->vp_offset = apc->tx_vp_offset;
		skb_queue_head_init(&txq->pending_skbs);

		memset(&spec, 0, sizeof(spec));
		spec.type = GDMA_SQ;
		spec.monitor_avl_buf = true;
		spec.queue_size = txq_size;
		err = mana_gd_create_mana_wq_cq(gd, &spec, &txq->gdma_sq);
		if (err)
			goto out;

		/* Create SQ's CQ */
		cq = &apc->tx_qp[i].tx_cq;
		cq->gdma_comp_buf = apc->eqs[i].cqe_poll;
		cq->type = MANA_CQ_TYPE_TX;

		cq->txq = txq;

		memset(&spec, 0, sizeof(spec));
		spec.type = GDMA_CQ;
		spec.monitor_avl_buf = false;
		spec.queue_size = cq_size;
		spec.cq.callback = mana_cq_handler;
		spec.cq.parent_eq = apc->eqs[i].eq;
		spec.cq.context = cq;
		err = mana_gd_create_mana_wq_cq(gd, &spec, &cq->gdma_cq);
		if (err)
			goto out;

		memset(&wq_spec, 0, sizeof(wq_spec));
		memset(&cq_spec, 0, sizeof(cq_spec));

		wq_spec.gdma_region = txq->gdma_sq->mem_info.gdma_region;
		wq_spec.queue_size = txq->gdma_sq->queue_size;

		cq_spec.gdma_region = cq->gdma_cq->mem_info.gdma_region;
		cq_spec.queue_size = cq->gdma_cq->queue_size;
		cq_spec.modr_ctx_id = 0;
		cq_spec.attached_eq = cq->gdma_cq->cq.parent->id;

		err = mana_create_wq_obj(apc, apc->port_handle, GDMA_SQ,
		    &wq_spec, &cq_spec, &apc->tx_qp[i].tx_object);

		if (err)
			goto out;

		txq->gdma_sq->id = wq_spec.queue_index;
		cq->gdma_cq->id = cq_spec.queue_index;

		txq->gdma_sq->mem_info.gdma_region = GDMA_INVALID_DMA_REGION;
		cq->gdma_cq->mem_info.gdma_region = GDMA_INVALID_DMA_REGION;

		txq->gdma_txq_id = txq->gdma_sq->id;

		cq->gdma_id = cq->gdma_cq->id;

		if (cq->gdma_id >= gc->max_num_cqs) {
			if_printf(net, "CQ id %u too large.\n", cq->gdma_id);
			return EINVAL;
		}

		gc->cq_table[cq->gdma_id] = cq->gdma_cq;

		/* Initialize tx specific data */
		snprintf(txq->txq_mtx_name, nitems(txq->txq_mtx_name),
		    "mana:tx(%d)", i);
		mtx_init(&txq->txq_mtx, txq->txq_mtx_name, NULL< MTX_DEF);

		txq->txq_br = buf_ring_alloc(MAX_SEND_BUFFERS_PER_QUEUE,
		    M_DEVBUF, M_WAITOK, &txq->txq_mtx);
		if (unlikely(txq->txq_br == NULL)) {
			if_printf(net,
			    "Failed to allocate buf ring for CQ %u\n",
			    cq->gdma_id);
			err = ENOMEM;
			goto out;
		}

		/* Allocate taskqueue for deferred send */
		TASK_INIT(&txq->enqueue_task, 0, mana_xmit_taskfunc, txq);
		txq->enqueue_tq = taskqueue_create_fast("mana_tx_enque",
		    M_NOWAIT, taskqueue_thread_enqueue, &txq->enqueue_tq);
		if (unlikely(txq->enqueue_tq == NULL)) {
			if_printf(net,
			    "Unable to create tx %d enqueue task queue\n", i);
			err = ENOMEM;
			goto out;
		}

		mana_gd_arm_cq(cq->gdma_cq);
	}

	return 0;
out:
	mana_destroy_txq(apc);
	return err;
}

static void
mana_destroy_rxq(struct mana_port_context *apc, struct mana_rxq *rxq,
    bool validate_state)
{
	struct gdma_context *gc = apc->ac->gdma_dev->gdma_context;
	struct mana_recv_buf_oob *rx_oob;
	struct device *dev = gc->dev;
	int i;

	if (!rxq)
		return;

	if (validate_state) {
		// XXX mana_napi_sync_for_rx(rxq); should we flush and stor Q here?
		;
	}

	mana_destroy_wq_obj(apc, GDMA_RQ, rxq->rxobj);

	mana_deinit_cq(apc, &rxq->rx_cq);

	for (i = 0; i < rxq->num_rx_buf; i++) {
		rx_oob = &rxq->rx_oobs[i];

		if (!rx_oob->mbuf)
			continue;

		mana_free_rx_mbuf(apc, rxq, rx_oob);
	}

	if (rxq->gdma_rq)
		mana_gd_destroy_queue(gc, rxq->gdma_rq);

	free(rxq, M_DEVBUF);
}

#define MANA_WQE_HEADER_SIZE 16
#define MANA_WQE_SGE_SIZE 16

static int
mana_alloc_rx_wqe(struct mana_port_context *apc,
    struct mana_rxq *rxq, uint32_t *rxq_size, uint32_t *cq_size)
{
	struct gdma_context *gc = apc->ac->gdma_dev->gdma_context;
	struct mana_recv_buf_oob *rx_oob;
	struct device *dev = gc->dev;
	struct page *page;
	uint32_t buf_idx;
	dma_addr_t da;

	WARN_ON(rxq->datasize == 0 || rxq->datasize > PAGE_SIZE);

	*rxq_size = 0;
	*cq_size = 0;

	for (buf_idx = 0; buf_idx < rxq->num_rx_buf; buf_idx++) {
		rx_oob = &rxq->rx_oobs[buf_idx];
		memset(rx_oob, 0, sizeof(*rx_oob));

		err = bus_dmamap_create(apc->rx_buf_tag, 0,
		    &rx_oob->dma_map);
		if (err) {
			mana_trc_err(NULL,
			    "Failed to  create rx DMA map for buf %d\n", i);
			return err;
		}

		err = mana_alloc_rx_mbuf(apc, rxq, rx_oob);
		if (err) {
			mana_trc_err(NULL,
			    "Failed to  create rx DMA map for buf %d\n", i);
			bus_dmamap_destroy(apc->rx_buf_tag, rx_oob->dma_map);
			return err;
		}

		rx_oob->wqe_req.sgl = rx_oob->sgl;
		rx_oob->wqe_req.num_sge = rx_oob->num_sge;
		rx_oob->wqe_req.inline_oob_size = 0;
		rx_oob->wqe_req.inline_oob_data = NULL;
		rx_oob->wqe_req.flags = 0;
		rx_oob->wqe_req.client_data_unit = 0;

		*rxq_size += ALIGN(MANA_WQE_HEADER_SIZE +
				   MANA_WQE_SGE_SIZE * rx_oob->num_sge, 32);
		*cq_size += COMP_ENTRY_SIZE;
	}

	return 0;
}

static int
mana_push_wqe(struct mana_rxq *rxq)
{
	struct mana_recv_buf_oob *rx_oob;
	uint32_t buf_idx;
	int err;

	for (buf_idx = 0; buf_idx < rxq->num_rx_buf; buf_idx++) {
		rx_oob = &rxq->rx_oobs[buf_idx];

		err = mana_gd_post_and_ring(rxq->gdma_rq, &rx_oob->wqe_req,
		    &rx_oob->wqe_inf);
		if (err)
			return ENOSPC;
	}

	return 0;
}

static struct mana_rxq *
mana_create_rxq(struct mana_port_context *apc, uint32_t rxq_idx,
    struct mana_eq *eq, struct ifnet *ndev)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;
	struct mana_obj_spec wq_spec;
	struct mana_obj_spec cq_spec;
	struct gdma_queue_spec spec;
	struct mana_cq *cq = NULL;
	uint32_t cq_size, rq_size;
	struct gdma_context *gc;
	struct mana_rxq *rxq;
	int err;

	gc = gd->gdma_context;

	rxq = malloc(sizeof(*rxq) +
	    RX_BUFFERS_PER_QUEUE * sizeof(struct mana_recv_buf_oob),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (!rxq)
		return NULL;

	rxq->ndev = ndev;
	rxq->num_rx_buf = RX_BUFFERS_PER_QUEUE;
	rxq->rxq_idx = rxq_idx;
	/*
	 * Minimum size is MCLBYTES(2048) bytes for a mbuf cluster.
	 * Now we just allow maxium size of 4096.
	 */
	// XXX rxq->datasize = ALIGN(MAX_FRAME_SIZE, 64);
	rxq->datasize = ALIGN(rxq->datasize, MCLBYTES);
	if (rxq->datasize > 4096)
		rxq->datasize = 4096;

	rxq->rxobj = INVALID_MANA_HANDLE;

	err = mana_alloc_rx_wqe(apc, rxq, &rq_size, &cq_size);
	if (err)
		goto out;

	rq_size = PAGE_ALIGN(rq_size);
	cq_size = PAGE_ALIGN(cq_size);

	/* Create RQ */
	memset(&spec, 0, sizeof(spec));
	spec.type = GDMA_RQ;
	spec.monitor_avl_buf = true;
	spec.queue_size = rq_size;
	err = mana_gd_create_mana_wq_cq(gd, &spec, &rxq->gdma_rq);
	if (err)
		goto out;

	/* Create RQ's CQ */
	cq = &rxq->rx_cq;
	cq->gdma_comp_buf = eq->cqe_poll;
	cq->type = MANA_CQ_TYPE_RX;
	cq->rxq = rxq;

	memset(&spec, 0, sizeof(spec));
	spec.type = GDMA_CQ;
	spec.monitor_avl_buf = false;
	spec.queue_size = cq_size;
	spec.cq.callback = mana_cq_handler;
	spec.cq.parent_eq = eq->eq;
	spec.cq.context = cq;
	err = mana_gd_create_mana_wq_cq(gd, &spec, &cq->gdma_cq);
	if (err)
		goto out;

	memset(&wq_spec, 0, sizeof(wq_spec));
	memset(&cq_spec, 0, sizeof(cq_spec));
	wq_spec.gdma_region = rxq->gdma_rq->mem_info.gdma_region;
	wq_spec.queue_size = rxq->gdma_rq->queue_size;

	cq_spec.gdma_region = cq->gdma_cq->mem_info.gdma_region;
	cq_spec.queue_size = cq->gdma_cq->queue_size;
	cq_spec.modr_ctx_id = 0;
	cq_spec.attached_eq = cq->gdma_cq->cq.parent->id;

	err = mana_create_wq_obj(apc, apc->port_handle, GDMA_RQ,
	    &wq_spec, &cq_spec, &rxq->rxobj);
	if (err)
		goto out;

	rxq->gdma_rq->id = wq_spec.queue_index;
	cq->gdma_cq->id = cq_spec.queue_index;

	rxq->gdma_rq->mem_info.gdma_region = GDMA_INVALID_DMA_REGION;
	cq->gdma_cq->mem_info.gdma_region = GDMA_INVALID_DMA_REGION;

	rxq->gdma_id = rxq->gdma_rq->id;
	cq->gdma_id = cq->gdma_cq->id;

	err = mana_push_wqe(rxq);
	if (err)
		goto out;

	if (cq->gdma_id >= gc->max_num_cqs)
		goto out;

	gc->cq_table[cq->gdma_id] = cq->gdma_cq;

	mana_gd_arm_cq(cq->gdma_cq);
out:
	if (!err)
		return rxq;

	if_printf(ndev, "Failed to create RXQ: err = %d\n", err);

	mana_destroy_rxq(apc, rxq, false);

	if (cq)
		mana_deinit_cq(apc, cq);

	return NULL;
}

static int
mana_add_rx_queues(struct mana_port_context *apc, struct ifnet *ndev)
{
	struct mana_rxq *rxq;
	int err = 0;
	int i;

	for (i = 0; i < apc->num_queues; i++) {
		rxq = mana_create_rxq(apc, i, &apc->eqs[i], ndev);
		if (!rxq) {
			err = ENOMEM;
			goto out;
		}

		// u64_stats_init(&rxq->stats.syncp);

		apc->rxqs[i] = rxq;
	}

	apc->default_rxobj = apc->rxqs[0]->rxobj;
out:
	return err;
}

static void
mana_destroy_vport(struct mana_port_context *apc)
{
	struct mana_rxq *rxq;
	uint32_t rxq_idx;

	for (rxq_idx = 0; rxq_idx < apc->num_queues; rxq_idx++) {
		rxq = apc->rxqs[rxq_idx];
		if (!rxq)
			continue;

		mana_destroy_rxq(apc, rxq, true);
		apc->rxqs[rxq_idx] = NULL;
	}

	mana_destroy_txq(apc);
}

static int
mana_create_vport(struct mana_port_context *apc, struct ifnet *net)
{
	struct gdma_dev *gd = apc->ac->gdma_dev;
	int err;

	apc->default_rxobj = INVALID_MANA_HANDLE;

	err = mana_cfg_vport(apc, gd->pdid, gd->doorbell);
	if (err)
		return err;

	return mana_create_txq(apc, net);
}


static void mana_rss_table_init(struct mana_port_context *apc)
{
	int i;

	for (i = 0; i < MANA_INDIRECT_TABLE_SIZE; i++)
		apc->indir_table[i] = i % apc->num_queues;
}

int mana_config_rss(struct mana_port_context *apc, enum TRI_STATE rx,
		    bool update_hash, bool update_tab)
{
	u32 queue_idx;
	int i;

	if (update_tab) {
		for (i = 0; i < MANA_INDIRECT_TABLE_SIZE; i++) {
			queue_idx = apc->indir_table[i];
			apc->rxobj_table[i] = apc->rxqs[queue_idx]->rxobj;
		}
	}

	return mana_cfg_vport_steering(apc, rx, true, update_hash, update_tab);
}

static int
mana_init_port(struct ifnet *ndev)
{
	struct mana_port_context *apc = if_getsoftc(ndev);
	uint32_t max_txq, max_rxq, max_queues;
	int port_idx = apc->port_idx;
	uint32_t num_indirect_entries;
	int err;

	err = mana_init_port_context(apc);
	if (err)
		return err;

	err = mana_query_vport_cfg(apc, port_idx, &max_txq, &max_rxq,
	    &num_indirect_entries);
	if (err) {
		if_printf(ndev, "Failed to query info for vPort 0\n");
		goto reset_apc;
	}

	max_queues = min_t(uint32_t, max_txq, max_rxq);
	if (apc->max_queues > max_queues)
		apc->max_queues = max_queues;

	if (apc->num_queues > apc->max_queues)
		apc->num_queues = apc->max_queues;

	// ether_addr_copy(ndev->dev_addr, apc->mac_addr);

	return 0;

reset_apc:
	bus_dma_tag_destroy(apc->rx_buf_tag);
	apc->rx_buf_tag = NULL;
	free(apc->rxqs, M_DEVBUF);
	apc->rxqs = NULL;
	return err;
}

int
mana_alloc_queues(struct ifnet *ndev)
{
	struct mana_port_context *apc = netdev_priv(ndev);
	struct gdma_dev *gd = apc->ac->gdma_dev;
	int err;

	err = mana_create_eq(apc);
	if (err)
		return err;

	err = mana_create_vport(apc, ndev);
	if (err)
		goto destroy_eq;

#if 0
	err = netif_set_real_num_tx_queues(ndev, apc->num_queues);
	if (err)
		goto destroy_vport;
#endif

	err = mana_add_rx_queues(apc, ndev);
	if (err)
		goto destroy_vport;

	apc->rss_state = apc->num_queues > 1 ? TRI_STATE_TRUE : TRI_STATE_FALSE;

#if 0
	err = netif_set_real_num_rx_queues(ndev, apc->num_queues);
	if (err)
		goto destroy_vport;
#endif

	mana_rss_table_init(apc);

	err = mana_config_rss(apc, TRI_STATE_TRUE, true, true);
	if (err)
		goto destroy_vport;

	return 0;

destroy_vport:
	mana_destroy_vport(apc);
destroy_eq:
	mana_destroy_eq(gd->gdma_context, apc);
	return err;
}

static int
mana_up(struct mana_port_context *apc)
{
#if 0
	int err;

	err = mana_alloc_queues(apc->ndev);
	if (err)
		return err;
#endif
	apc->port_is_up = true;

	/* Ensure port state updated before txq state */
	wmb();

#if 1
	if_link_state_change(apc->ndev, LINK_STATE_UP);
	if_setdrvflagbits(apc->ndev, IFF_DRV_RUNNING, IFF_DRV_OACTIVE);
#endif

	return 0;
}


static void
mana_init(void *arg)
{
	struct mana_port_context *apc = (struct mana_port_context *)arg;

	MANA_APC_LOCK_LOCK(apc);
	if (!apc->port_is_up) {
		mana_up(apc);
	}
	MANA_APC_LOCK_UNLOCK(apc);
}

static int
mana_dealloc_queues(struct ifnet *ndev)
{
#if 0
	struct mana_port_context *apc = netdev_priv(ndev);
	struct mana_txq *txq;
	int i, err;

	if (apc->port_is_up)
		return -EINVAL;

	/* No packet can be transmitted now since apc->port_is_up is false.
	 * There is still a tiny chance that mana_poll_tx_cq() can re-enable
	 * a txq because it may not timely see apc->port_is_up being cleared
	 * to false, but it doesn't matter since mana_start_xmit() drops any
	 * new packets due to apc->port_is_up being false.
	 *
	 * Drain all the in-flight TX packets
	 */
	for (i = 0; i < apc->num_queues; i++) {
		txq = &apc->tx_qp[i].txq;

		while (atomic_read(&txq->pending_sends) > 0)
			usleep_range(1000, 2000);
	}

	/* We're 100% sure the queues can no longer be woken up, because
	 * we're sure now mana_poll_tx_cq() can't be running.
	 */

	apc->rss_state = TRI_STATE_FALSE;
	err = mana_config_rss(apc, TRI_STATE_FALSE, false, false);
	if (err) {
		netdev_err(ndev, "Failed to disable vPort: %d\n", err);
		return err;
	}

	/* TODO: Implement RX fencing */
	ssleep(1);

	mana_destroy_vport(apc);

	mana_destroy_eq(apc->ac->gdma_dev->gdma_context, apc);
#endif

	return 0;
}

static int
mana_down(struct mana_port_context *apc)
{
	int err = 0;

	apc->port_st_save = apc->port_is_up;
	apc->port_is_up = false;

	/* Ensure port state updated before txq state */
	wmb();

	if (apc->port_st_save) {
		if_setdrvflagbits(apc->ndev, IFF_DRV_OACTIVE,
		    IFF_DRV_RUNNING);
		if_link_state_change(apc->ndev, LINK_STATE_DOWN);

		err = mana_dealloc_queues(apc->ndev);
	}

	return err;
}

int
mana_detach(struct ifnet *ndev)
{
	struct mana_port_context *apc = if_getsoftc(ndev);
	int err;

	ether_ifdetach(ndev);

	if (!apc)
		return 0;

	MANA_APC_LOCK_LOCK(apc);
	err = mana_down(apc);
	MANA_APC_LOCK_UNLOCK(apc);

	mana_cleanup_port_context(apc);

	MANA_APC_LOCK_DESTROY(apc);

	free(apc, M_DEVBUF);

	return err;
}

static int
mana_probe_port(struct mana_context *ac, int port_idx,
    struct ifnet **ndev_storage)
{
	struct gdma_context *gc = ac->gdma_dev->gdma_context;
	struct mana_port_context *apc;
	struct ifnet *ndev;
	int err;

	ndev = if_alloc_dev(IFT_ETHER, gc->dev);
	if (!ndev) {
		mana_trc_err(NULL, "Failed to allocate ifnet struct\n");
		return ENOMEM;
	}

	*ndev_storage = ndev;

	apc = malloc(sizeof(*apc), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!apc) {
		mana_trc_err(NULL, "Failed to allocate port context\n");
		err = ENOMEM;
		goto free_net;
	}

	apc->ac = ac;
	apc->ndev = ndev;
	apc->max_queues = gc->max_num_queues;
	apc->num_queues = min_t(unsigned int,
	    gc->max_num_queues, MANA_MAX_NUM_QUEUES);
	apc->port_handle = INVALID_MANA_HANDLE;
	apc->port_idx = port_idx;

	MANA_APC_LOCK_INIT(apc);

	/* XXX name */
	if_initname(ndev, device_get_name(gc->dev), port_idx);
	if_setdev(ndev,gc->dev);
	if_setsoftc(ndev, apc);

	if_setflags(ndev, IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST);
	if_setinitfn(ndev, mana_init);
	if_settransmitfn(ndev, mana_start_xmit);
	if_setqflushfn(ndev, mana_qflush);
	if_setioctlfn(ndev, mana_ioctl);
	if_setgetcounterfn(ndev, mana_get_counter);

	if_setmtu(ndev, ETHERMTU);
	if_setbaudrate(ndev, 0);

	// netif_carrier_off(ndev);

	mana_rss_key_fill(apc->hashkey, MANA_HASH_KEY_SIZE);

	err = mana_init_port(ndev);
	if (err)
		goto reset_apc;

#if 0
	ndev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	ndev->hw_features |= NETIF_F_RXCSUM;
	ndev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;
	ndev->hw_features |= NETIF_F_RXHASH;
	ndev->features = ndev->hw_features;
	ndev->vlan_features = 0;
#endif

	ndev->if_capabilities |= IFCAP_TXCSUM | IFCAP_TXCSUM_IPV6;
	ndev->if_capabilities |= IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6;
	ndev->if_capabilities |= IFCAP_TSO4 | IFCAP_TSO6;

	ndev->if_capabilities |= IFCAP_JUMBO_MTU;

	/* Enable all available capabilities by default. */
	ndev->if_capenable = ndev->if_capabilities;

#define MANA_TSO_MAXSEG_SZ	PAGE_SIZE

	/* TSO parameters */
	ndev->if_hw_tsomax = MAX_MBUF_FRAGS * MANA_TSO_MAXSEG_SZ -
	    (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN);
	ndev->if_hw_tsomaxsegcount = MAX_MBUF_FRAGS;
	ndev->if_hw_tsomaxsegsize = PAGE_SIZE;

	ifmedia_init(&apc->media, IFM_IMASK,
	    mana_ifmedia_change, mana_ifmedia_status);
	ifmedia_add(&apc->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&apc->media, IFM_ETHER | IFM_AUTO);

	ether_ifattach(ndev, apc->mac_addr);

	/* Tell the stack that the interface is not active */
	if_setdrvflagbits(ndev, IFF_DRV_OACTIVE, IFF_DRV_RUNNING);

	return 0;

reset_apc:
	free(apc, M_DEVBUF);
free_net:
	*ndev_storage = NULL;
	if_printf(ndev, "Failed to probe vPort %d: %d\n", port_idx, err);
	if_free(ndev);
	return err;
}

int mana_probe(struct gdma_dev *gd)
{
	struct gdma_context *gc = gd->gdma_context;
	device_t dev = gc->dev;
	struct mana_context *ac;
	int err;
	int i;

	device_printf(dev, "%s protocol version: %d.%d.%d\n", DEVICE_NAME,
		 MANA_MAJOR_VERSION, MANA_MINOR_VERSION, MANA_MICRO_VERSION);

	err = mana_gd_register_device(gd);
	if (err)
		return err;

	ac = malloc(sizeof(*ac), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!ac)
		return ENOMEM;

	ac->gdma_dev = gd;
	ac->num_ports = 1;
	gd->driver_data = ac;

	err = mana_query_device_cfg(ac, MANA_MAJOR_VERSION, MANA_MINOR_VERSION,
	    MANA_MICRO_VERSION, &ac->num_ports);
	if (err)
		goto out;

	if (ac->num_ports > MAX_PORTS_IN_MANA_DEV)
		ac->num_ports = MAX_PORTS_IN_MANA_DEV;

#if 1
	for (i = 0; i < ac->num_ports; i++) {
		err = mana_probe_port(ac, i, &ac->ports[i]);
		if (err)
			break;
	}
#endif
out:
	if (err)
		mana_remove(gd);

	return err;
}

void
mana_remove(struct gdma_dev *gd)
{
	struct gdma_context *gc = gd->gdma_context;
	struct mana_context *ac = gd->driver_data;
	device_t dev = gc->dev;
	struct ifnet *ndev;
	int i;

	for (i = 0; i < ac->num_ports; i++) {
		ndev = ac->ports[i];
		if (!ndev) {
			if (i == 0)
				device_printf(dev, "No net device to remove\n");
			goto out;
		}

		mana_detach(ndev);

		if_free(ndev);
	}
out:
	mana_gd_deregister_device(gd);
	gd->driver_data = NULL;
	gd->gdma_context = NULL;
	free(ac, M_DEVBUF);
}
