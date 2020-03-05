/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2020, Intel Corporation
 */

/*
 * dispatcher.h -- internal definitions for librpma dispatcher
 */
#ifndef RPMA_DISPATCHER_H
#define RPMA_DISPATCHER_H

#include "os_thread.h"
#include "sys/queue.h"

struct rpma_dispatcher_conn {
	RPMA_TAILQ_ENTRY(rpma_dispatcher_conn) next;

	struct rpma_connection *conn;
};

struct rpma_dispatcher_wc_entry {
	RPMA_TAILQ_ENTRY(rpma_dispatcher_wc_entry) next;

	struct rpma_connection *conn;
	struct ibv_wc wc;
};

struct rpma_dispatcher_func_entry {
	RPMA_TAILQ_ENTRY(rpma_dispatcher_func_entry) next;

	struct rpma_connection *conn;
	rpma_queue_func func;
	void *arg;
};

struct rpma_dispatcher {
	struct rpma_zone *zone;

	RPMA_TAILQ_HEAD(head_conn, rpma_dispatcher_conn) conn_set;

	uint64_t waiting;

	RPMA_TAILQ_HEAD(head_cq, rpma_dispatcher_wc_entry) queue_wce;

	os_mutex_t queue_func_mtx;
	RPMA_TAILQ_HEAD(head_fq, rpma_dispatcher_func_entry) queue_func;
};

int rpma_dispatcher_attach_connection(struct rpma_dispatcher *disp,
				      struct rpma_connection *conn);

int rpma_dispatcher_detach_connection(struct rpma_dispatcher *disp,
				      struct rpma_connection *conn);

int rpma_dispatch_break(struct rpma_dispatcher *disp);

int rpma_dispatcher_enqueue_cq_entry(struct rpma_dispatcher *disp,
				     struct rpma_connection *conn,
				     struct ibv_wc *wc);
int rpma_dispatcher_enqueue_func(struct rpma_dispatcher *disp,
				 struct rpma_connection *conn,
				 rpma_queue_func func, void *arg);

#endif /* dispatcher.h */
