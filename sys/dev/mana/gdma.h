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
 *
 * $FreeBSD$
 *
 */

#ifndef _GDMA_H
#define _GDMA_H

#include <sys/bus.h>
#include <sys/types.h>

#include "shm_channel.h"

struct gdma_resource {
	/* Protect the bitmap */
	struct mtx		lock_spin;

	/* The bitmap size in bits. */
	uint32_t		size;

	/* The bitmap tracks the resources. */
	unsigned long		*map;
};

#define GDMA_BAR0		0

#define GDMA_IRQNAME_SZ		40

struct gdma_bus {
	bus_space_handle_t	bar0_h;
	bus_space_tag_t		bar0_t;
};

struct gdma_msix_entry {
	int			entry;
	int			vector;
};

struct gdma_irq_context {
	struct gdma_msix_entry	msix_e;
	struct resource		*res;
	driver_filter_t		*handler;
	void			*arg;
	void			*cookie;
	bool			requested;
	int			cpu;
	char			name[GDMA_IRQNAME_SZ];
};

struct gdma_context {
	device_t		dev;

	struct gdma_bus		gd_bus;

	/* Per-vPort max number of queues */
	unsigned int		max_num_msix;
	unsigned int		num_msix_usable;
	struct gdma_resource	msix_resource;
	struct gdma_irq_context	*irq_contexts;

	struct resource		*bar0;
	struct resource		*msix;
	int			msix_rid;
	void __iomem		*shm_base;
	void __iomem		*db_page_base;
	uint32_t		db_page_size;

	/* Shared memory chanenl (used to bootstrap HWC) */
	struct shm_channel	shm_channel;
};

#define GDMA_REG_DB_PAGE_OFFSET	8
#define GDMA_REG_DB_PAGE_SIZE	0x10
#define GDMA_REG_SHM_OFFSET	0x18

int mana_gd_alloc_res_map(uint32_t res_avil, struct gdma_resource *r,
    const char *name);
void mana_gd_free_res_map(struct gdma_resource *r);
#endif /* _GDMA_H */
