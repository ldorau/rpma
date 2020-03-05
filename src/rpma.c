/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019, Intel Corporation
 */

/*
 * rpma.c -- entry points for librpma
 */

#include "rpma.h"
#include "librpma.h"

int
rpma_connection_group_new(struct rpma_connection_group **group)
{
	return RPMA_E_NOSUPP;
}

int
rpma_connection_group_add(struct rpma_connection_group *group,
			  struct rpma_connection *conn)
{
	return RPMA_E_NOSUPP;
}

int
rpma_connection_group_remove(struct rpma_connection_group *group,
			     struct rpma_connection *conn)
{
	return RPMA_E_NOSUPP;
}

int
rpma_connection_group_enqueue(struct rpma_connection_group *group,
			      rpma_queue_func func, void *arg)
{
	return RPMA_E_NOSUPP;
}

int
rpma_connection_group_delete(struct rpma_connection_group **group)
{
	return RPMA_E_NOSUPP;
}
