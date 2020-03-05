/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2020, Intel Corporation
 */

/*
 * zone.h -- internal definitions for librpma zone
 */
#ifndef RPMA_ZONE_H
#define RPMA_ZONE_H

#include <infiniband/verbs.h>
#include <librpma.h>

struct rpma_zone {
	struct rdma_addrinfo *rai;

	struct rdma_event_channel *ec;
	int ec_epoll;

	struct ibv_context *device;
	struct ibv_pd *pd;

	struct rdma_cm_id *listen_id;
	struct rdma_cm_event *edata;

	void *uarg;
	uint64_t active_connections;
	struct ravl *connections;

	uint64_t waiting;

	rpma_on_connection_event_func on_connection_event_func;
	rpma_on_timeout_func on_timeout_func;
	int timeout;

	/* XXX should be rpma_connection specific? */
	size_t msg_size;
	uint64_t send_queue_length;
	uint64_t recv_queue_length;

	unsigned flags;
};

int rpma_zone_event_ack(struct rpma_zone *zone);
int rpma_zone_wait_connected(struct rpma_zone *zone,
			     struct rpma_connection *conn);

#endif /* zone.h */
