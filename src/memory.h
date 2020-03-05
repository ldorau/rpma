/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2020, Intel Corporation
 */

/*
 * memory.h -- internal definitions for librpma memory
 */
#ifndef RPMA_MEMORY_H
#define RPMA_MEMORY_H

#include "zone.h"

struct rpma_memory_local {
	void *ptr;
	size_t size;

	struct ibv_mr *mr;
	void *desc; /* local memory descriptor */
};

struct rpma_memory_remote {
	/* XXX version required */
	uint64_t raddr; /* remote memory base address */
	uint32_t rkey;	/* remote memory protection key */
	size_t size;
	uint64_t unused[1]; /* XXX */
};

typedef struct rpma_memory_remote rpma_memory_id_internal;

int rpma_memory_local_new_internal(struct rpma_zone *zone, void *ptr,
				   size_t size, int access,
				   struct rpma_memory_local **mem_ptr);

#endif /* memory.h */
