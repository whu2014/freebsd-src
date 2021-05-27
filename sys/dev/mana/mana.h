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

#ifndef _MANA_H
#define _MANA_H

#include <sys/types.h>
#include <sys/proc.h>

#include "gdma.h"
#include "hw_channel.h"


/* Microsoft Azure Network Adapter (MANA)'s definitions
 *
 * Structures labeled with "HW DATA" are exchanged with the hardware. All of
 * them are naturally aligned and hence don't need __packed.
 */
/* MANA protocol version */
#define MANA_MAJOR_VERSION	0
#define MANA_MINOR_VERSION	1
#define MANA_MICRO_VERSION	1

#define DRV_MODULE_NAME		"mana"

#ifndef DRV_MODULE_VERSION
#define DRV_MODULE_VERSION				\
	__XSTRING(MANA_MAJOR_VERSION) "."		\
	__XSTRING(MANA_MINOR_VERSION) "."		\
	__XSTRING(MANA_MICRO_VERSION)
#endif
#define DEVICE_NAME	"Microsoft Azure Network Adapter (MANA)"
#define DEVICE_DESC	"MANA adapter"

/*
 * Supported PCI vendor and devices IDs
 */
#ifndef PCI_VENDOR_ID_MICROSOFT
#define PCI_VENDOR_ID_MICROSOFT	0x1414
#endif

#define PCI_DEV_ID_MANA_VF	0x00ba

typedef struct _mana_vendor_id_t {
	uint16_t vendor_id;
	uint16_t device_id;
} mana_vendor_id_t;

#if 1 /*XXX */
#define MAX_PORTS_IN_MANA_DEV	1
#else
#define MAX_PORTS_IN_MANA_DEV	16
#endif

#define MANA_MAX_NUM_QUEUES	16

#endif /* _MANA_H */
