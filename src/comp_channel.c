// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2022, Intel Corporation */

/*
 * comp_channel.c -- librpma completion channel related implementations
 */

#include <errno.h>
#include "comp_channel.h"
#include "log_internal.h"

/* internal librpma API */

struct rpma_comp_channel {
	struct ibv_comp_channel *channel;
};

/*
 * rpma_comp_channel_new -- create a completion channel
 *
 * ASSUMPTIONS
 * - ibv_ctx != NULL && channel_ptr != NULL
 */
int
rpma_comp_channel_new(struct ibv_context *ibv_ctx,
		struct rpma_comp_channel **channel_ptr)
{
	struct rpma_comp_channel *rpma_channel;

	rpma_channel = (struct rpma_comp_channel *)
				malloc(sizeof(struct rpma_comp_channel));
	if (rpma_channel == NULL)
		return RPMA_E_NOMEM;

	/* create a completion channel */
	struct ibv_comp_channel *channel = ibv_create_comp_channel(ibv_ctx);
	if (channel == NULL) {
		RPMA_LOG_ERROR_WITH_ERRNO(errno, "ibv_create_comp_channel()");
		free(rpma_channel);
		return RPMA_E_PROVIDER;
	}

	rpma_channel->channel = channel;
	*channel_ptr = rpma_channel;

	return 0;
}

/*
 * rpma_comp_channel_destroy -- destroy a completion channel
 *
 * ASSUMPTIONS
 * - channel != NULL
 */
int
rpma_comp_channel_destroy(struct rpma_comp_channel *channel)
{
	int ret = 0;

	errno = ibv_destroy_comp_channel(channel->channel);
	if (errno) {
		RPMA_LOG_ERROR_WITH_ERRNO(errno, "ibv_destroy_comp_channel()");
		ret = RPMA_E_PROVIDER;
	}

	free(channel);

	return ret;
}

/*
 * rpma_comp_channel_get -- get the channel member
 * from the rpma_comp_channel object
 *
 * ASSUMPTIONS
 * - channel != NULL
 */
struct ibv_comp_channel *
rpma_comp_channel_get(const struct rpma_comp_channel *channel)
{
	return channel->channel;
}

/*
 * rpma_comp_channel_get_fd -- get a file descriptor of the channel member
 * from the rpma_comp_channel object
 */
int
rpma_comp_channel_get_fd(const struct rpma_comp_channel *channel, int *fd)
{
	if (channel == NULL || fd == NULL)
		return RPMA_E_INVAL;

	*fd = channel->channel->fd;

	return 0;
}
