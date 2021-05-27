
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
#include <net/if_media.h>
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

int mana_probe(struct gdma_dev *gd)
{
	struct gdma_context *gc = gd->gdma_context;
	device_t dev = gc->dev;
	struct mana_context *ac;
	int err;
	// int i;

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

#if 0
	err = mana_query_device_cfg(ac, MANA_MAJOR_VERSION, MANA_MINOR_VERSION,
				    MANA_MICRO_VERSION, &ac->num_ports);
	if (err)
		goto out;

	if (ac->num_ports > MAX_PORTS_IN_MANA_DEV)
		ac->num_ports = MAX_PORTS_IN_MANA_DEV;

	for (i = 0; i < ac->num_ports; i++) {
		err = mana_probe_port(ac, i, &ac->ports[i]);
		if (err)
			break;
	}
out:
#endif
	if (err)
		mana_remove(gd);

	return err;
}

void
mana_remove(struct gdma_dev *gd)
{
	// struct gdma_context *gc = gd->gdma_context;
	struct mana_context *ac = gd->driver_data;
#if 0
	device_t dev = gc->dev;
	struct net_device *ndev;
	int i;

	for (i = 0; i < ac->num_ports; i++) {
		ndev = ac->ports[i];
		if (!ndev) {
			if (i == 0)
				dev_err(dev, "No net device to remove\n");
			goto out;
		}

		/* All cleanup actions should stay after rtnl_lock(), otherwise
		 * other functions may access partially cleaned up data.
		 */
		rtnl_lock();

		mana_detach(ndev, false);

		unregister_netdevice(ndev);

		rtnl_unlock();

		free_netdev(ndev);
	}
out:
#endif
	mana_gd_deregister_device(gd);
	gd->driver_data = NULL;
	gd->gdma_context = NULL;
	free(ac, M_DEVBUF);
}
