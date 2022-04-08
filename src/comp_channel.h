/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2022, Intel Corporation */

/*
 * comp_channel.h -- librpma completion channel related internal definitions
 */

#ifndef LIBRPMA_COMP_CHANNEL_H
#define LIBRPMA_COMP_CHANNEL_H

#include <infiniband/verbs.h>

#include "librpma.h"

struct rpma_comp_channel;

/*
 * ERRORS
 * rpma_comp_channel_new() can fail with the following errors:
 *
 * - RPMA_E_PROVIDER - ibv_create_comp_channel(3) failed with a provider error
 */
int rpma_comp_channel_new(struct ibv_context *ibv_ctx,
		struct rpma_comp_channel **channel_ptr);

/*
 * ERRORS
 * rpma_comp_channel_destroy() can fail with the following errors:
 *
 * - RPMA_E_PROVIDER - ibv_destroy_comp_channel(3) failed with a provider error
 */
int rpma_comp_channel_destroy(struct rpma_comp_channel *channel);

/*
 * ERRORS
 * rpma_comp_channel_get() cannot fail.
 */
struct ibv_comp_channel *rpma_comp_channel_get(
		const struct rpma_comp_channel *channel);


/*
 * ERRORS
 * rpma_comp_channel_get_fd() can fail with the following errors:
 *
 * - RPMA_E_INVAL - channel == NULL || fd == NULL
 */
int rpma_comp_channel_get_fd(const struct rpma_comp_channel *channel, int *fd);

#endif /* LIBRPMA_COMP_CHANNEL_H */
