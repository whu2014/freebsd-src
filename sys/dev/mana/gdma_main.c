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
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rman.h>
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
#include <net/ethernet.h>
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

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "mana.h"

/*********************************************************
 *  Function prototypes
 *********************************************************/
static int	mana_gd_probe(device_t);
static int	mana_gd_attach(device_t);
static int	mana_gd_detach(device_t);
static struct resource *mana_gd_alloc_bar(device_t, int);
static void	mana_gd_init_registers(struct gdma_context *);
static void	mana_gd_free_pci_res(struct gdma_context *);
static inline uint32_t mana_gd_r32(struct gdma_context *, uint64_t);
static inline uint64_t mana_gd_r64(struct gdma_context *, uint64_t);
static int	 mana_gd_intr(void *);
static int	 mana_gd_setup_irqs(device_t);

// static char mana_version[] = DEVICE_NAME DRV_MODULE_NAME " v" DRV_MODULE_VERSION;

static mana_vendor_id_t mana_id_table[] = {
    { PCI_VENDOR_ID_MICROSOFT, PCI_DEV_ID_MANA_VF},
    /* Last entry */
    { 0, 0}
};

#if 1 /*whu */
static inline uint32_t
mana_gd_r32(struct gdma_context *g, uint64_t offset)
{
	uint32_t v = bus_space_read_4(g->gd_bus.bar0_t,
	    g->gd_bus.bar0_h, offset);
	rmb();
	return (v);
}

static inline uint64_t
mana_gd_r64(struct gdma_context *g, uint64_t offset)
{
	uint64_t v = bus_space_read_8(g->gd_bus.bar0_t,
	    g->gd_bus.bar0_h, offset);
	rmb();
	return (v);
}

/* XXX filter handler or intr handler? */
static int
mana_gd_intr(void *arg)
{
	struct gdma_irq_context *gic = arg;

	if (gic->handler)
		gic->handler(gic->arg);

	return (FILTER_HANDLED);
}

int
mana_gd_alloc_res_map(uint32_t res_avail,
    struct gdma_resource *r, const char *name)
{
	int n = howmany(res_avail , sizeof(unsigned long));

	r->map =
	    malloc(n * sizeof(unsigned long), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!r->map)
		return ENOMEM;

	r->size = res_avail;
	mtx_init(&r->lock_spin, name, NULL, MTX_SPIN);

	return (0);
}

void
mana_gd_free_res_map(struct gdma_resource *r)
{
	if (!r || !r->map)
		return;

	free(r->map, M_DEVBUF);
	r->map = NULL;
	r->size = 0;
}

static void
mana_gd_init_registers(struct gdma_context *gc)
{
	uint64_t bar0_va = rman_get_bushandle(gc->bar0);

	gc->db_page_size = mana_gd_r32(gc, GDMA_REG_DB_PAGE_SIZE) & 0xFFFF;

	gc->db_page_base =
	    (void *) (bar0_va + mana_gd_r64(gc, GDMA_REG_DB_PAGE_OFFSET));

	gc->shm_base =
	    (void *) (bar0_va + mana_gd_r64(gc, GDMA_REG_SHM_OFFSET));

	mana_trc_dbg(NULL, "db_page_size 0x%xx, db_page_base %p,"
		    " shm_base %p\n",
		    gc->db_page_size, gc->db_page_base, gc->shm_base);
}

static struct resource *
mana_gd_alloc_bar(device_t dev, int bar)
{
	struct resource *res = NULL;
	struct pci_map *pm;
	int rid, type;

	if (bar < 0 || bar > PCIR_MAX_BAR_0)
		goto alloc_bar_out;

	pm = pci_find_bar(dev, PCIR_BAR(bar));
	if (!pm)
		goto alloc_bar_out;

	if (PCI_BAR_IO(pm->pm_value))
		type = SYS_RES_IOPORT;
	else
		type = SYS_RES_MEMORY;
	if (type < 0)
		goto alloc_bar_out;

	rid = PCIR_BAR(bar);
	res = bus_alloc_resource_any(dev, type, &rid, RF_ACTIVE);
	if (res)
		mana_trc_dbg(NULL, "bar %d: rid 0x%x, type 0x%jx,"
		    " handle 0x%jx\n",
		    bar, rid, res->r_bustag, res->r_bushandle);

alloc_bar_out:
	return (res);
}

static void
mana_gd_free_pci_res(struct gdma_context *gc)
{
	if (!gc || gc->dev)
		return;

	if (gc->bar0 != NULL) {
		bus_release_resource(gc->dev, SYS_RES_MEMORY,
		    PCIR_BAR(GDMA_BAR0), gc->bar0);
	}

	if (gc->msix != NULL) {
		bus_release_resource(gc->dev, SYS_RES_MEMORY,
		    gc->msix_rid, gc->msix);
	}
}

static int
mana_gd_setup_irqs(device_t dev)
{
	unsigned int max_queues_per_port = mp_ncpus;
	struct gdma_context *gc = device_get_softc(dev);
	struct gdma_irq_context *gic;
	unsigned int max_irqs;
	int nvec;
	int rc, rcc, i;

	if (max_queues_per_port > MANA_MAX_NUM_QUEUES)
		max_queues_per_port = MANA_MAX_NUM_QUEUES;

	max_irqs = max_queues_per_port * MAX_PORTS_IN_MANA_DEV;

	/* Need 1 interrupt for the Hardware communication Channel (HWC) */
	max_irqs++;

	nvec = max_irqs;
	rc = pci_alloc_msix(dev, &nvec);
	if (unlikely(rc != 0)) {
		device_printf(dev,
		    "Failed to allocate MSIX, vectors %d, error: %d\n",
		    nvec, rc);
		rc = ENOSPC;
		goto err_setup_irq_alloc;
	}

	if (nvec != max_irqs) {
		if (nvec == 1) {
			device_printf(dev,
			    "Not enough number of MSI-x allocated: %d\n",
			    nvec);
			rc = ENOSPC;
			goto err_setup_irq_release;
		}
		device_printf(dev, "Allocated only %d MSI-x (%d requested)\n",
		    nvec, max_irqs);
	}

	gc->irq_contexts = malloc(nvec * sizeof(struct gdma_irq_context),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (!gc->irq_contexts) {
		rc = ENOMEM;
		goto err_setup_irq_release;
	}

	for (i = 0; i < nvec; i++) {
		gic = &gc->irq_contexts[i];
		gic->msix_e.entry = i;
		/* Vector starts from 1. */
		/* XXX if remapped, vector would be changed. */
		gic->msix_e.vector = i + 1;
		gic->handler = NULL;
		gic->arg = NULL;

		gic->res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
		    &gic->msix_e.vector, RF_ACTIVE | RF_SHAREABLE);
		if (unlikely(gic->res == NULL)) {
			rc = ENOMEM;
			device_printf(dev, "could not allocate resource "
			    "for irq vector %d\n", gic->msix_e.vector);
			goto err_setup_irq;
		}

		rc = bus_setup_intr(dev, gic->res,
		    INTR_TYPE_NET | INTR_MPSAFE, mana_gd_intr, NULL,
		    gic, &gic->cookie);
		if (unlikely(rc != 0)) {
			device_printf(dev, "failed to register interrupt "
			    "handler for irq %ju vector %d: error %d\n",
			    rman_get_start(gic->res), gic->msix_e.vector, rc);
			goto err_setup_irq;
		}
		gic->requested = true;

		mana_trc_dbg(NULL, "added msix vector %d irq %ju\n",
		    gic->msix_e.vector, rman_get_start(gic->res));
	}

	rc = mana_gd_alloc_res_map(nvec, &gc->msix_resource,
	    "gdma msix res lock");
	if (rc != 0) {
		device_printf(dev, "failed to allocate memory "
		    "for msix bitmap\n");
		goto err_setup_irq;
	}

	gc->max_num_msix = nvec;
	gc->num_msix_usable = nvec;

	mana_trc_dbg(NULL, "setup %d msix interrupts\n", nvec);

	return (0);

err_setup_irq:
	for (; i >= 0; i--) {
		gic = &gc->irq_contexts[i];
		rcc = 0;

		/*
		 * If gic->requested is true, we need to free both intr and
		 * resources.
		 */
		if (gic->requested)
			rcc = bus_teardown_intr(dev, gic->res, gic->cookie);
		if (unlikely(rcc != 0))
			device_printf(dev, "could not release "
			    "irq vector %d, error: %d\n",
			    gic->msix_e.vector, rcc);

		rcc = 0;
		if (gic->res != NULL) {
			rcc = bus_release_resource(dev, SYS_RES_IRQ,
			    gic->msix_e.vector, gic->res);
		}
		if (unlikely(rcc != 0))
			device_printf(dev, "dev has no parent while "
			    "releasing resource for irq vector %d\n",
			    gic->msix_e.vector);
		gic->requested = false;
		gic->res = NULL;
	}

	free(gc->irq_contexts, M_DEVBUF);
	gc->irq_contexts = NULL;
err_setup_irq_release:
	pci_release_msi(dev);
err_setup_irq_alloc:
	return (rc);
}
#else  /*whu*/
#endif /*whu*/

static int
mana_gd_probe(device_t dev)
{
	mana_vendor_id_t *ent;
	char		adapter_name[60];
	uint16_t	pci_vendor_id = 0;
	uint16_t	pci_device_id = 0;

	pci_vendor_id = pci_get_vendor(dev);
	pci_device_id = pci_get_device(dev);

	ent = mana_id_table;
	while (ent->vendor_id != 0) {
		if ((pci_vendor_id == ent->vendor_id) &&
		    (pci_device_id == ent->device_id)) {
			mana_trc_dbg(NULL, "vendor=%x device=%x\n",
			    pci_vendor_id, pci_device_id);

			sprintf(adapter_name, DEVICE_DESC);
			device_set_desc_copy(dev, adapter_name);
			return (BUS_PROBE_DEFAULT);
		}

		ent++;
	}

	return (ENXIO);
}

/**
 * mana_attach - Device Initialization Routine
 * @dev: device information struct
 *
 * Returns 0 on success, otherwise on failure.
 *
 * mana_attach initializes an adapter identified by a device structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int
mana_gd_attach(device_t dev)
{
	struct gdma_context *gc;
	int msix_rid;
	int rc;

	mana_trc_dbg(NULL, "mana_gd_attach called\n");

	gc = device_get_softc(dev);
	gc->dev = dev;

	pci_enable_io(dev, SYS_RES_IOPORT);
	pci_enable_io(dev, SYS_RES_MEMORY);

	pci_enable_busmaster(dev);

	gc->bar0 = mana_gd_alloc_bar(dev, GDMA_BAR0);
	if (unlikely(gc->bar0 == NULL)) {
		device_printf(dev,
		    "unable to allocate bus resource for bar0!\n");
		rc = ENOMEM;
		goto err_disable_dev;
	}

	/* Store bar0 tage and handle for quick access */
	gc->gd_bus.bar0_t = rman_get_bustag(gc->bar0);
	gc->gd_bus.bar0_h = rman_get_bushandle(gc->bar0);

	/* Map MSI-x vector table */
#if 1
	msix_rid = pci_msix_table_bar(dev);

	mana_trc_dbg(NULL, "msix_rid 0x%x\n", msix_rid);

	gc->msix = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &msix_rid, RF_ACTIVE);
	if (unlikely(gc->msix == NULL)) {
		device_printf(dev,
		    "unable to allocate bus resource for msix!\n");
		rc = ENOMEM;
		goto err_free_pci_res;
	}
	gc->msix_rid = msix_rid;
#endif

	if (unlikely(gc->gd_bus.bar0_h  == 0)) {
		device_printf(dev, "failed to map bar0!\n");
		rc = ENXIO;
		goto err_free_pci_res;
	}

	mana_gd_init_registers(gc);

	mana_smc_init(&gc->shm_channel, gc->dev, gc->shm_base);

	rc = mana_gd_setup_irqs(dev);
	if (rc)
		goto err_free_pci_res;

	return (0);

err_free_pci_res:
	mana_gd_free_pci_res(gc);
err_disable_dev:
	pci_disable_busmaster(dev);

	return(rc);
}

/**
 * mana_detach - Device Removal Routine
 * @pdev: device information struct
 *
 * mana_detach is called by the device subsystem to alert the driver
 * that it should release a PCI device.
 **/
static int
mana_gd_detach(device_t dev)
{
#if 1
	struct gdma_context *gc = device_get_softc(dev);
	mana_trc_dbg(NULL, "mana_gd_detach called\n");

	mana_gd_free_pci_res(gc);

	pci_disable_busmaster(dev);

	return (bus_generic_detach(dev));
#else
#endif
}


/*********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/

static device_method_t mana_methods[] = {
    /* Device interface */
    DEVMETHOD(device_probe, mana_gd_probe),
    DEVMETHOD(device_attach, mana_gd_attach),
    DEVMETHOD(device_detach, mana_gd_detach),
    DEVMETHOD_END
};

static driver_t mana_driver = {
    "mana", mana_methods, sizeof(struct gdma_context),
};

devclass_t mana_devclass;
DRIVER_MODULE(mana, pci, mana_driver, mana_devclass, 0, 0);
MODULE_PNP_INFO("U16:vendor;U16:device", pci, mana, mana_id_table,
    nitems(mana_id_table) - 1);
MODULE_DEPEND(mana, pci, 1, 1, 1);
MODULE_DEPEND(mana, ether, 1, 1, 1);

/*********************************************************************/
