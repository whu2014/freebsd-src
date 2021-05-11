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

/* Structures labeled with "HW DATA" are exchanged with the hardware. All of
 * them are naturally aligned and hence don't need __packed.
 */

#define BIT(n)			(1ULL << (n))

struct completion {
	unsigned int done;
	struct mtx lock;
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

enum gdma_request_type {
	GDMA_VERIFY_VF_DRIVER_VERSION	= 1,
	GDMA_QUERY_MAX_RESOURCES	= 2,
	GDMA_LIST_DEVICES		= 3,
	GDMA_REGISTER_DEVICE		= 4,
	GDMA_DEREGISTER_DEVICE		= 5,
	GDMA_GENERATE_TEST_EQE		= 10,
	GDMA_CREATE_QUEUE		= 12,
	GDMA_DISABLE_QUEUE		= 13,
	GDMA_CREATE_DMA_REGION		= 25,
	GDMA_DMA_REGION_ADD_PAGES	= 26,
	GDMA_DESTROY_DMA_REGION		= 27,
};

enum gdma_queue_type {
	GDMA_INVALID_QUEUE,
	GDMA_SQ,
	GDMA_RQ,
	GDMA_CQ,
	GDMA_EQ,
};

enum gdma_work_request_flags {
	GDMA_WR_NONE			= 0,
	GDMA_WR_OOB_IN_SGL		= BIT(0),
	GDMA_WR_PAD_BY_SGE0		= BIT(1),
};

enum gdma_eqe_type {
	GDMA_EQE_COMPLETION		= 3,
	GDMA_EQE_TEST_EVENT		= 64,
	GDMA_EQE_HWC_INIT_EQ_ID_DB	= 129,
	GDMA_EQE_HWC_INIT_DATA		= 130,
	GDMA_EQE_HWC_INIT_DONE		= 131,
};

enum {
	GDMA_DEVICE_NONE	= 0,
	GDMA_DEVICE_HWC		= 1,
	GDMA_DEVICE_MANA	= 2,
};


struct gdma_resource {
	/* Protect the bitmap */
	struct mtx		lock_spin;

	/* The bitmap size in bits. */
	uint32_t		size;

	/* The bitmap tracks the resources. */
	unsigned long		*map;
};

union gdma_doorbell_entry {
	uint64_t		as_uint64;

	struct {
		uint64_t id		: 24;
		uint64_t reserved	: 8;
		uint64_t tail_ptr	: 31;
		uint64_t arm		: 1;
	} cq;

	struct {
		uint64_t id		: 24;
		uint64_t wqe_cnt	: 8;
		uint64_t tail_ptr	: 32;
	} rq;

	struct {
		uint64_t id		: 24;
		uint64_t reserved	: 8;
		uint64_t tail_ptr	: 32;
	} sq;

	struct {
		uint64_t id		: 16;
		uint64_t reserved	: 16;
		uint64_t tail_ptr	: 31;
		uint64_t arm		: 1;
	} eq;
}; /* HW DATA */

struct gdma_msg_hdr {
	uint32_t	hdr_type;
	uint32_t	msg_type;
	uint16_t	msg_version;
	uint16_t	hwc_msg_id;
	uint32_t	msg_size;
}; /* HW DATA */

struct gdma_dev_id {
	union {
		struct {
			uint16_t type;
			uint16_t instance;
		};

		uint32_t as_uint32;
	};
}; /* HW DATA */

struct gdma_req_hdr {
	struct gdma_msg_hdr	req;
	struct gdma_msg_hdr	resp; /* The expected response */
	struct gdma_dev_id	dev_id;
	uint32_t		activity_id;
}; /* HW DATA */

struct gdma_resp_hdr {
	struct gdma_msg_hdr	response;
	struct gdma_dev_id	dev_id;
	uint32_t		activity_id;
	uint32_t		status;
	uint32_t		reserved;
}; /* HW DATA */

struct gdma_general_req {
	struct gdma_req_hdr	hdr;
}; /* HW DATA */

#define GDMA_MESSAGE_V1 1

struct gdma_general_resp {
	struct gdma_resp_hdr	hdr;
}; /* HW DATA */

#define GDMA_STANDARD_HEADER_TYPE	0

static inline void
mana_gd_init_req_hdr(struct gdma_req_hdr *hdr, uint32_t code,
    uint32_t req_size, uint32_t resp_size)
{
	hdr->req.hdr_type = GDMA_STANDARD_HEADER_TYPE;
	hdr->req.msg_type = code;
	hdr->req.msg_version = GDMA_MESSAGE_V1;
	hdr->req.msg_size = req_size;

	hdr->resp.hdr_type = GDMA_STANDARD_HEADER_TYPE;
	hdr->resp.msg_type = code;
	hdr->resp.msg_version = GDMA_MESSAGE_V1;
	hdr->resp.msg_size = resp_size;
}

/* The 16-byte struct is part of the GDMA work queue entry (WQE). */
struct gdma_sge {
	uint64_t		address;
	uint32_t		mem_key;
	uint32_t		size;
}; /* HW DATA */

struct gdma_wqe_request {
	struct gdma_sge		*sgl;
	uint32_t		num_sge;

	uint32_t		inline_oob_size;
	const void		*inline_oob_data;

	uint32_t		flags;
	uint32_t		client_data_unit;
};

enum gdma_page_type {
	GDMA_PAGE_TYPE_4K,
};

#define GDMA_INVALID_DMA_REGION		0

struct gdma_mem_info {
	device_t		 dev;

	vm_paddr_t		dma_handle;
	void			*virt_addr;
	uint64_t		length;

	/* Allocated by the PF driver */
	uint64_t		gdma_region;
};

#define REGISTER_ATB_MST_MKEY_LOWER_SIZE 8

struct gdma_dev {
	struct gdma_context	*gdma_context;

	struct gdma_dev_id	dev_id;

	uint32_t		pdid;
	uint32_t		doorbell;
	uint32_t		gpa_mkey;

	/* GDMA driver specific pointer */
	void			*driver_data;
};

#define MINIMUM_SUPPORTED_PAGE_SIZE PAGE_SIZE

#define GDMA_CQE_SIZE		64
#define GDMA_EQE_SIZE		16
#define GDMA_MAX_SQE_SIZE	512
#define GDMA_MAX_RQE_SIZE	256

#define GDMA_COMP_DATA_SIZE	0x3C

#define GDMA_EVENT_DATA_SIZE	0xC

/* The WQE size must be a multiple of the Basic Unit, which is 32 bytes. */
#define GDMA_WQE_BU_SIZE	32

#define INVALID_PDID		UINT_MAX
#define INVALID_DOORBELL	UINT_MAX
#define INVALID_MEM_KEY		UINT_MAX
#define INVALID_QUEUE_ID	UINT_MAX
#define INVALID_PCI_MSIX_INDEX  UINT_MAX

struct gdma_comp {
	uint32_t		cqe_data[GDMA_COMP_DATA_SIZE / 4];
	uint32_t		wq_num;
	bool			is_sq;
};

struct gdma_event {
	uint32_t		details[GDMA_EVENT_DATA_SIZE / 4];
	uint8_t			type;
};

struct gdma_queue;

#define CQE_POLLING_BUFFER	512

typedef void gdma_eq_callback(void *context, struct gdma_queue *q,
    struct gdma_event *e);

typedef void gdma_cq_callback(void *context, struct gdma_queue *q);

/* The 'head' is the producer index. For SQ/RQ, when the driver posts a WQE
 * (Note: the WQE size must be a multiple of the 32-byte Basic Unit), the
 * driver increases the 'head' in BUs rather than in bytes, and notifies
 * the HW of the updated head. For EQ/CQ, the driver uses the 'head' to track
 * the HW head, and increases the 'head' by 1 for every processed EQE/CQE.
 *
 * The 'tail' is the consumer index for SQ/RQ. After the CQE of the SQ/RQ is
 * processed, the driver increases the 'tail' to indicate that WQEs have
 * been consumed by the HW, so the driver can post new WQEs into the SQ/RQ.
 *
 * The driver doesn't use the 'tail' for EQ/CQ, because the driver ensures
 * that the EQ/CQ is big enough so they can't overflow, and the driver uses
 * the owner bits mechanism to detect if the queue has become empty.
 */
struct gdma_queue {
	struct gdma_dev		*gdma_dev;

	enum gdma_queue_type	type;
	uint32_t		id;

	struct gdma_mem_info	mem_info;

	void			*queue_mem_ptr;
	uint32_t		queue_size;

	bool			monitor_avl_buf;

	uint32_t		head;
	uint32_t		tail;

	/* Extra fields specific to EQ/CQ. */
	union {
		struct {
			bool			disable_needed;

			gdma_eq_callback	*callback;
			void			*context;

			unsigned int		msix_index;

			uint32_t		log2_throttle_limit;

#if 0 /*XXX */
			/* NAPI data */
			struct napi_struct napi;
			int			work_done;
			int			budget;
#endif
		} eq;

		struct {
			gdma_cq_callback	*callback;
			void			*context;

			/* For CQ/EQ relationship */
			struct gdma_queue	*parent;
		} cq;
	};
};

struct gdma_queue_spec {
	enum gdma_queue_type	type;
	bool			monitor_avl_buf;
	unsigned int		queue_size;

	/* Extra fields specific to EQ/CQ. */
	union {
		struct {
			gdma_eq_callback	*callback;
			void			*context;

			unsigned long		log2_throttle_limit;

			/* Only used by the MANA device. */
			struct ifnet		*ndev;
		} eq;

		struct {
			gdma_cq_callback	*callback;
			void			*context;

			struct			gdma_queue *parent_eq;

		} cq;
	};
};

struct mana_eq {
	struct gdma_queue	eq;
	struct gdma_comp	cqe_poll[CQE_POLLING_BUFFER];
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

	/* Protect eq_test_event and test_event_eq_id  */
	struct mtx		eq_test_event_mutex;
	struct completion	eq_test_event;
	uint32_t		test_event_eq_id;

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
