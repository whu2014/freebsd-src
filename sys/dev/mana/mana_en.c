
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

#if 0
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
	free(apc->rxqs, M_DEVBUF);
	apc->rxqs = NULL;
}

static int
mana_init_port_context(struct mana_port_context *apc)
{
	apc->rxqs = mallocarray(apc->num_queues, sizeof(struct mana_rxq *),
	    M_DEVBUF, M_WAITOK | M_ZERO);

	return (!apc->rxqs ? ENOMEM : 0);
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
	free(apc->rxqs, M_DEVBUF);
	apc->rxqs = NULL;
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

#if 0
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
