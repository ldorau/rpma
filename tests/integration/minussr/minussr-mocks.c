// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2021, Intel Corporation */

/*
 * minussr-mocks.c -- Minimal User-Space Soft RoCE (minussr) mocks
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <rdma/rdma_cma.h>
#include <fcntl.h>

#include "minussr-trace.h"
#include "minussr-utils.h"

#define EVENT_CHANNEL_SR_CW \
	"/tmp/minussr-event-channel-server-read-client-write"
#define EVENT_CHANNEL_SW_CR \
	"/tmp/minussr-event-channel-server-write-client-read"

#define COMP_CHANNEL_SERVER \
	"/tmp/minussr-comp-channel-server"
#define COMP_CHANNEL_CLIENT \
	"/tmp/minussr-comp-channel-client"

#define MAX_CLIENTS 10

struct node_s {
	int index;
	struct ibv_context *ibv_context;
	struct ibv_qp *qp;
};

/* >>> Beginning of Global variables <<< */
static struct node_s Nodes[1 + MAX_CLIENTS];
/* >>> End of Global variables <<< */

/* >>> Beginning of Thread-Local Storage <<< */
/*
 * Node_index = 0 - server
 * Node_index > 0 - client number
 */
static __thread int Node_index;
static __thread struct ibv_context Verbs_ibv_context;
static __thread struct rdma_cm_id *rdma_default_id = NULL;
static __thread int Fd_evch_wr = 0;
/* >>> End of Thread-Local Storage <<< */

struct rqi_s {
	uint64_t wr_id;
	struct ibv_sge sge;
};

struct recv_queue_s {
	struct rqi_s *rq_items;
	int n_sges;
	int i_recv;
	int i_send;
};

/* QP context */
struct qp_ctx_s {
	struct recv_queue_s recv_queue;
};

/* CQ context */
struct cq_ctx_s {
	struct ibv_wc *wcs;
	int n_wcs;
	int i_write;
	int i_read;
};

/* mocks of OPs */
static int ibv_post_send_mock(struct ibv_qp *qp, struct ibv_send_wr *wr,
			struct ibv_send_wr **bad_wr);
static int ibv_post_recv_mock(struct ibv_qp *qp, struct ibv_recv_wr *wr,
			struct ibv_recv_wr **bad_wr);
static int ibv_req_notify_cq_mock(struct ibv_cq *cq, int solicited_only);
int ibv_poll_cq_mock(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc);

int
minussr_init(int iam_server)
{
	static int client_number = 0;

	memset(&Verbs_ibv_context, 0, sizeof(Verbs_ibv_context));

	if (iam_server) {
		/* the server */
		Node_index = 0;
	} else {
		/* a client */
		Node_index = ++client_number;
		if (client_number > MAX_CLIENTS) {
			fprintf(stderr,
				"FATAL ERROR: too many clients (> %i)",
				MAX_CLIENTS);
			exit(-1);
		}
	}

	/*
	 * 'cmd_fd' is used in those mocks as a node number:
	 *  = 0 - server
	 *  > 0 - client number
	 */
	Verbs_ibv_context.cmd_fd = Node_index;

	/*
	 * 'device' is not used in those mocks.
	 * It is set and used only for debugging,
	 * because it is the 1st field,
	 * so it is the best visible in gdb.
	 */
	Verbs_ibv_context.device =
		(struct ibv_device *)(uintptr_t)(Node_index);

	Verbs_ibv_context.ops.poll_cq = ibv_poll_cq_mock;
	Verbs_ibv_context.ops.post_send = ibv_post_send_mock;
	Verbs_ibv_context.ops.post_recv = ibv_post_recv_mock;
	Verbs_ibv_context.ops.req_notify_cq = ibv_req_notify_cq_mock;

	Nodes[Node_index].index = Node_index;
	Nodes[Node_index].ibv_context = &Verbs_ibv_context;

	return 0;
}

/*
 * ibv_req_notify_cq_mock -- ibv_req_notify_cq() mock
 */
static int
ibv_req_notify_cq_mock(struct ibv_cq *cq, int solicited_only)
{
	TRACE_RET(OP_PASS, -1);
	assert_int_equal(solicited_only, 0);
	return 0;
}

/*
 * ibv_create_cq -- ibv_create_cq() mock
 */
struct ibv_cq *
ibv_create_cq(struct ibv_context *context, int cqe, void *cq_context,
		struct ibv_comp_channel *channel, int comp_vector)
{
	TRACE_RET(OP_PASS, NULL);

	assert_int_equal(comp_vector, 0);

	struct ibv_cq *cq = calloc(1, sizeof(*cq));
	if (cq == NULL) {
		perror("calloc");
		return NULL;
	}

	struct cq_ctx_s *cq_ctx = calloc(1, sizeof(*cq_ctx));
	if (cq_ctx == NULL) {
		perror("calloc");
		goto err_free_cq;
	}

	cq_ctx->n_wcs = cqe;
	cq_ctx->wcs = calloc((size_t)cq_ctx->n_wcs, sizeof(*cq_ctx->wcs));
	if (cq_ctx->wcs == NULL) {
		perror("calloc");
		goto err_free_cq_queues;
	}

	cq->cq_context = cq_ctx;
	cq->channel = channel;
	cq->context = context;
	cq->cqe = cqe;

	return cq;

err_free_cq_queues:
	free(cq_ctx);

err_free_cq:
	free(cq);

	return NULL;
}

/*
 * ibv_destroy_cq -- ibv_destroy_cq() mock
 */
int
ibv_destroy_cq(struct ibv_cq *cq)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	struct cq_ctx_s *cq_ctx = (struct cq_ctx_s *)cq->cq_context;
	free(cq_ctx->wcs);
	free(cq_ctx);
	free(cq);

	return 0;
}

/*
 * ibv_create_comp_channel -- ibv_create_comp_channel() mock
 */
struct ibv_comp_channel *
ibv_create_comp_channel(struct ibv_context *context)
{
	TRACE_RET(OP_PASS, NULL);

	struct ibv_comp_channel *channel;
	channel = calloc(1, sizeof(*channel));
	if (channel == NULL) {
		return NULL;
	}

	int fd;
	switch (context->cmd_fd) {
	case 0: /* server */
		(void) mknod(COMP_CHANNEL_SERVER, S_IFIFO | 0640, 0);
		fd = open(COMP_CHANNEL_SERVER, O_RDWR);
		if (fd == -1) {
			perror("open");
			return NULL;
		}
		break;
	case 1: /* client #1 */
		(void) mknod(COMP_CHANNEL_CLIENT, S_IFIFO | 0640, 0);
		fd = open(COMP_CHANNEL_CLIENT, O_RDWR);
		if (fd == -1) {
			perror("open");
			return NULL;
		}
		break;
	default: /* client #>1 */
		log_err("too many clients (only one is allowed)");
		return NULL;
	}

	channel->context = context;
	channel->fd = fd;
	channel->refcnt = 0;

	return channel;
}

/*
 * ibv_destroy_comp_channel -- ibv_destroy_comp_channel() mock
 */
int
ibv_destroy_comp_channel(struct ibv_comp_channel *channel)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	free(channel);
	return 0;
}

/*
 * ibv_alloc_pd -- ibv_alloc_pd() mock
 */
struct ibv_pd *
ibv_alloc_pd(struct ibv_context *ibv_ctx)
{
	TRACE_RET(OP_PASS, NULL);

	struct ibv_pd *pd = calloc(1, sizeof(*pd));
	if (pd == NULL)
		return NULL;

	pd->context = ibv_ctx;

	return pd;
}

/*
 * ibv_dealloc_pd -- ibv_dealloc_pd() mock
 */
int
ibv_dealloc_pd(struct ibv_pd *pd)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	free(pd);

	return 0;
}

/*
 * ibv_get_cq_event -- ibv_get_cq_event() mock
 */
int
ibv_get_cq_event(struct ibv_comp_channel *channel, struct ibv_cq **cq,
		void **cq_context)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(cq);
	assert_non_null(cq_context);

	log_info("getting CQ event ..."); /* CQ pointer */

	ssize_t n_bytes = read(channel->fd, cq, sizeof(*cq));
	if ((size_t)n_bytes < sizeof(*cq)) {
		errno = EIO;
		return -1;
	}

	*cq_context = (*cq)->cq_context;

	return 0;
}

/*
 * ibv_ack_cq_events -- ibv_ack_cq_events() mock
 */
void
ibv_ack_cq_events(struct ibv_cq *cq, unsigned nevents)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	assert_int_equal(nevents, 1);
}

/*
 * ibv_query_device -- ibv_query_device() mock
 */
int
ibv_query_device(struct ibv_context *context,
		struct ibv_device_attr *device_attr)
{
	TRACE_RET(OP_PASS, -1);
	assert_non_null(device_attr);
	return 0;
}

#if defined(ibv_reg_mr)
/*
 * Since rdma-core v27.0-105-g5a750676
 * ibv_reg_mr() has been defined as a macro
 * in <infiniband/verbs.h>:
 *
 * https://github.com/linux-rdma/rdma-core/commit/5a750676e8312715100900c6336bbc98577e082b
 *
 * In order to mock the ibv_reg_mr() function
 * the `ibv_reg_mr` symbol has to be undefined first
 * and the additional ibv_reg_mr_iova2() function
 * has to be mocked, because it is called
 * by the 'ibv_reg_mr' macro.
 */
#undef ibv_reg_mr
/*
 * ibv_reg_mr_iova2 -- ibv_reg_mr_iova2() mock
 */
struct ibv_mr *
ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
			uint64_t iova, unsigned access)
{
	return ibv_reg_mr(pd, addr, length, (int)access);
}

#endif

/*
 * ibv_reg_mr -- ibv_reg_mr() mock
 */
struct ibv_mr *
ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length, int access)
{
	TRACE_RET(OP_PASS, NULL);

	struct ibv_mr *mr = calloc(1, sizeof(*mr));
	if (mr == NULL)
		return NULL;

	mr->addr = addr;
	mr->length = length;
	mr->pd = pd;
	mr->context = pd->context;

	return mr;
}

/*
 * ibv_dereg_mr -- a mock of ibv_dereg_mr()
 */
int
ibv_dereg_mr(struct ibv_mr *mr)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	free(mr);
	return 0;
}

/*
 * ibv_wc_status_str -- ibv_wc_status_str() mock
 */
const char *
ibv_wc_status_str(enum ibv_wc_status status)
{
	TRACE_RET(OP_ABORT, NULL);
	return "ibv_wc_status_str";
}

/*
 * rdma_accept -- rdma_accept() mock
 */
int
rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(conn_param);
	assert_int_equal(conn_param->responder_resources, RDMA_MAX_RESP_RES);
	assert_int_equal(conn_param->initiator_depth, RDMA_MAX_INIT_DEPTH);
	assert_int_equal(conn_param->flow_control, 1);
	assert_int_equal(conn_param->retry_count, 7); /* max 3-bit value */
	assert_int_equal(conn_param->rnr_retry_count, 7); /* max 3-bit value */

	struct rdma_cm_event *event = calloc(1, sizeof(*event));
	if (event == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* client is waiting for RDMA_CM_EVENT_ESTABLISHED */
	event->event = RDMA_CM_EVENT_ESTABLISHED;
	memcpy(&event->param.conn, conn_param, sizeof(struct rdma_conn_param));

	log_info("sending RDMA_CM_EVENT_ESTABLISHED ...");

	ssize_t n_bytes = write(Fd_evch_wr, event, sizeof(*event));
	if ((size_t)n_bytes < sizeof(*event)) {
		errno = EIO;
		return -1;
	}

	free(event);

	return 0;
}

/*
 * rdma_bind_addr -- rdma_bind_addr() mock
 * Note: CM ID is not modified.
 */
int
rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	TRACE_RET(OP_PASS, -1);

	/* rdma_bind_addr() is called on the server side */
	id->verbs = &Verbs_ibv_context;

	return 0;
}

/*
 * rdma_connect -- rdma_connect() mock
 */
int
rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(conn_param);
	assert_int_equal(conn_param->responder_resources, RDMA_MAX_RESP_RES);
	assert_int_equal(conn_param->initiator_depth, RDMA_MAX_INIT_DEPTH);
	assert_int_equal(conn_param->flow_control, 1);
	assert_int_equal(conn_param->retry_count, 7); /* max 3-bit value */
	assert_int_equal(conn_param->rnr_retry_count, 7); /* max 3-bit value */

	struct rdma_cm_event *event = calloc(1, sizeof(*event));
	if (event == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* server is waiting for RDMA_CM_EVENT_CONNECT_REQUEST */
	event->event = RDMA_CM_EVENT_CONNECT_REQUEST;
	memcpy(&event->param.conn, conn_param, sizeof(struct rdma_conn_param));

	log_info("sending RDMA_CM_EVENT_CONNECT_REQUEST ...");

	ssize_t n_bytes = write(Fd_evch_wr, event, sizeof(*event));
	if ((size_t)n_bytes < sizeof(*event)) {
		errno = EIO;
		return -1;
	}

	rdma_default_id = id;

	free(event);

	return 0;
}

/*
 * rdma_create_event_channel -- rdma_create_event_channel() mock
 */
struct rdma_event_channel *
rdma_create_event_channel(void)
{
	TRACE_RET(OP_PASS, NULL);

	struct rdma_event_channel *channel;
	channel = malloc(sizeof(*channel));
	if (channel == NULL) {
		perror("malloc");
		return NULL;
	}

	/* create FIFOs if they do not exist */
	(void) mknod(EVENT_CHANNEL_SR_CW, S_IFIFO | 0640, 0);
	(void) mknod(EVENT_CHANNEL_SW_CR, S_IFIFO | 0640, 0);

	int fd_sr_cw = open(EVENT_CHANNEL_SR_CW, O_RDWR);
	if (fd_sr_cw == -1) {
		perror("open");
		return NULL;
	}

	int fd_sw_cr = open(EVENT_CHANNEL_SW_CR, O_RDWR);
	if (fd_sw_cr == -1) {
		perror("open");
		return NULL;
	}

	if (Iam_server) {
		channel->fd = fd_sr_cw;
		Fd_evch_wr = fd_sw_cr;
	} else {
		channel->fd = fd_sw_cr;
		Fd_evch_wr = fd_sr_cw;
	}

	return channel;
}

/*
 * rdma_destroy_event_channel -- rdma_destroy_event_channel() mock
 */
void
rdma_destroy_event_channel(struct rdma_event_channel *channel)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	close(channel->fd);
	close(Fd_evch_wr);
	free(channel);
}

/*
 * rdma_create_id -- rdma_create_id() mock
 */
int
rdma_create_id(struct rdma_event_channel *channel,
		struct rdma_cm_id **id, void *context,
		enum rdma_port_space ps)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(id);
	assert_null(context);
	assert_int_equal(ps, RDMA_PS_TCP);

	struct rdma_cm_id *idp = calloc(1, sizeof(*idp));
	if (idp == NULL)
		return -1;

	idp->channel = channel;
	*id = idp;

	return 0;
}

/*
 * rdma_destroy_id -- rdma_destroy_id() mock
 */
int
rdma_destroy_id(struct rdma_cm_id *id)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

#define ID_FREED ((struct rdma_cm_id *)0x1)

	if (rdma_default_id == ID_FREED)
		return 0;

	free(id);

	if (rdma_default_id == id)
		rdma_default_id = ID_FREED;

	return 0;
}

/*
 * rdma_create_qp -- rdma_create_qp() mock
 */
int
rdma_create_qp(struct rdma_cm_id *id, struct ibv_pd *pd,
		struct ibv_qp_init_attr *qp_init_attr)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(qp_init_attr);
	assert_int_equal(qp_init_attr->qp_context, NULL);
	assert_int_equal(qp_init_attr->srq, NULL);
	assert_int_equal(qp_init_attr->qp_type, IBV_QPT_RC);
	assert_int_equal(qp_init_attr->sq_sig_all, 0);

	struct ibv_qp *qp = calloc(1, sizeof(*id->qp));
	if (qp == NULL) {
		perror("calloc");
		return -1;
	}

	struct qp_ctx_s *qp_ctx = calloc(1, sizeof(*qp_ctx));
	if (qp_ctx == NULL) {
		perror("calloc");
		free(qp);
		return -1;
	}

	qp_ctx->recv_queue.n_sges = (int)qp_init_attr->cap.max_recv_wr;
	qp_ctx->recv_queue.rq_items = calloc((size_t)qp_ctx->recv_queue.n_sges,
				sizeof(*qp_ctx->recv_queue.rq_items));
	if (qp_ctx->recv_queue.rq_items == NULL) {
		perror("calloc");
		free(qp_ctx);
		free(qp);
		return -1;
	}

	qp->qp_context = qp_ctx;
	qp->send_cq = qp_init_attr->send_cq;
	qp->recv_cq = qp_init_attr->recv_cq;
	qp->srq = qp_init_attr->srq;
	qp->qp_type = qp_init_attr->qp_type;
	qp->context = id->verbs;

	id->qp = qp;
	Nodes[Node_index].qp = qp;

	return 0;
}

/*
 * rdma_destroy_qp -- rdma_destroy_qp() mock
 */
void
rdma_destroy_qp(struct rdma_cm_id *id)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	if (id->qp->qp_context) {
		struct qp_ctx_s *qp_ctx = id->qp->qp_context;
		free(qp_ctx->recv_queue.rq_items);
		free(id->qp->qp_context);
	}

	free(id->qp);
	id->qp = NULL;
	Nodes[Node_index].qp = NULL;
}

/*
 * rdma_disconnect -- rdma_disconnect() mock
 */
int
rdma_disconnect(struct rdma_cm_id *id)
{
	TRACE_RET(OP_PASS, -1);

	struct rdma_cm_event *event = calloc(1, sizeof(*event));
	if (event == NULL) {
		errno = ENOMEM;
		return -1;
	}

	event->event = RDMA_CM_EVENT_DISCONNECTED;

	log_info("sending RDMA_CM_EVENT_DISCONNECTED ...");

	ssize_t n_bytes = write(Fd_evch_wr, event, sizeof(*event));
	if ((size_t)n_bytes < sizeof(*event)) {
		errno = EIO;
		return -1;
	}

	free(event);

	return 0;
}

/*
 * rdma_event_str -- rdma_event_str() mock
 */
const char *
rdma_event_str(enum rdma_cm_event_type event)
{
	TRACE_RET(OP_PASS, NULL);

	switch (event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		return "RDMA_CM_EVENT_ADDR_RESOLVED";
	case RDMA_CM_EVENT_ADDR_ERROR:
		return "RDMA_CM_EVENT_ADDR_ERROR";
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		return "RDMA_CM_EVENT_ROUTE_RESOLVED";
	case RDMA_CM_EVENT_ROUTE_ERROR:
		return "RDMA_CM_EVENT_ROUTE_ERROR";
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		return "RDMA_CM_EVENT_CONNECT_REQUEST";
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		return "RDMA_CM_EVENT_CONNECT_RESPONSE";
	case RDMA_CM_EVENT_CONNECT_ERROR:
		return "RDMA_CM_EVENT_CONNECT_ERROR";
	case RDMA_CM_EVENT_UNREACHABLE:
		return "RDMA_CM_EVENT_UNREACHABLE";
	case RDMA_CM_EVENT_REJECTED:
		return "RDMA_CM_EVENT_REJECTED";
	case RDMA_CM_EVENT_ESTABLISHED:
		return "RDMA_CM_EVENT_ESTABLISHED";
	case RDMA_CM_EVENT_DISCONNECTED:
		return "RDMA_CM_EVENT_DISCONNECTED";
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		return "RDMA_CM_EVENT_DEVICE_REMOVAL";
	case RDMA_CM_EVENT_MULTICAST_JOIN:
		return "RDMA_CM_EVENT_MULTICAST_JOIN";
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		return "RDMA_CM_EVENT_MULTICAST_ERROR";
	case RDMA_CM_EVENT_ADDR_CHANGE:
		return "RDMA_CM_EVENT_ADDR_CHANGE";
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		return "RDMA_CM_EVENT_TIMEWAIT_EXIT";
	};

	return "Unknown event";
}

/*
 * rdma_getaddrinfo -- rdma_getaddrinfo() mock
 */
#ifdef RDMA_GETADDRINFO_OLD_SIGNATURE
int
rdma_getaddrinfo(char *node, char *port,
		struct rdma_addrinfo *hints, struct rdma_addrinfo **res)
#else
int
rdma_getaddrinfo(const char *node, const char *port,
		const struct rdma_addrinfo *hints, struct rdma_addrinfo **res)
#endif
{
	TRACE_RET(OP_PASS, -1);

	struct rdma_addrinfo *buf = calloc(1, sizeof(*buf));
	if (port == NULL) {
		buf->ai_src_addr = NULL;
		buf->ai_dst_addr = NULL;
	} else {
		buf->ai_src_addr = calloc(1, sizeof(*buf->ai_src_addr));
		buf->ai_dst_addr = calloc(1, sizeof(*buf->ai_dst_addr));
	}

	buf->ai_flags = hints->ai_flags;
	*res = buf;

	return 0;
}

/*
 * rdma_freeaddrinfo -- rdma_freeaddrinfo() mock
 */
void
rdma_freeaddrinfo(struct rdma_addrinfo *res)
{
	TRACE_DO_NOT_FAIL(OP_PASS);
	free(res->ai_src_addr);
	free(res->ai_dst_addr);
	free(res);
}

/*
 * rdma_get_cm_event -- rdma_get_cm_event() mock
 */
int
rdma_get_cm_event(struct rdma_event_channel *channel,
		struct rdma_cm_event **event_ptr)
{
	TRACE_RET(OP_PASS, -1); /* XXX */

	assert_non_null(event_ptr);

	struct rdma_cm_event *event = calloc(1, sizeof(*event));
	if (event == NULL) {
		errno = ENOMEM;
		return -1;
	}

	log_info("reading from FIFO ...");

	ssize_t n_bytes = read(channel->fd, event, sizeof(*event));
	if ((size_t)n_bytes < sizeof(*event)) {
		errno = EIO;
		return -1;
	}

	/* set listening id */
	if (rdma_default_id == NULL) {
		log_err("rdma_default_id == NULL");
		errno = -1;
		return -1;
	}
	event->id = rdma_default_id;

	*event_ptr = event;

	return 0;
}

/*
 * rdma_ack_cm_event -- rdma_ack_cm_event() mock
 */
int
rdma_ack_cm_event(struct rdma_cm_event *event)
{
	TRACE_DO_NOT_FAIL(OP_PASS);

	if (Iam_server || event->event != RDMA_CM_EVENT_ESTABLISHED) {
		free(event);
		return 0;
	}

	/* client */
	log_info("sending RDMA_CM_EVENT_ESTABLISHED ...");

	ssize_t n_bytes = write(Fd_evch_wr, event, sizeof(*event));
	if ((size_t)n_bytes < sizeof(*event)) {
		errno = EIO;
		return -1;
	}

	free(event);

	return 0;
}

/*
 * rdma_listen -- rdma_listen() mock
 */
int
rdma_listen(struct rdma_cm_id *id, int backlog)
{
	TRACE_RET(OP_PASS, -1);

	assert_int_equal(backlog, 0);

	rdma_default_id = id;

	return 0;
}

/*
 * rdma_migrate_id -- rdma_migrate_id() mock
 */
int
rdma_migrate_id(struct rdma_cm_id *id, struct rdma_event_channel *channel)
{
	TRACE_RET(OP_PASS, -1);

	id->channel = channel;

	return 0;
}

/*
 * rdma_reject -- rdma_reject() mock
 */
int
rdma_reject(struct rdma_cm_id *id, const void *private_data,
		uint8_t private_data_len)
{
	TRACE_RET(OP_FAIL, -1);
	return -1;
}

/*
 * rdma_resolve_addr -- rdma_resolve_addr() mock
 */
int
rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		struct sockaddr *dst_addr, int timeout_ms)
{
	TRACE_RET(OP_PASS, -1);

	/* rdma_resolve_addr() is called on the client side */
	id->verbs = &Verbs_ibv_context;

	return 0;
}

/*
 * rdma_resolve_route -- rdma_resolve_route() mock
 */
int
rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms)
{
	TRACE_RET(OP_PASS, -1);
	return 0;
}

/*
 * util_send_CQ -- send completion
 */
static int
util_send_CQ(struct ibv_cq *cq, struct ibv_send_wr *wr, uint64_t wr_id,
		enum ibv_wc_opcode opcode, uint32_t byte_len)
{
	struct cq_ctx_s *cq_ctx;
	cq_ctx = (struct cq_ctx_s *)cq->cq_context;

	int new_write = (cq_ctx->i_write + 1) % cq_ctx->n_wcs;
	if (new_write == cq_ctx->i_read) {
		log_err("cannot send completion, CQ is full");
		return ENOBUFS;
	}

	/* set WC */
	struct ibv_wc *wc = &cq_ctx->wcs[cq_ctx->i_write];
	cq_ctx->i_write = new_write;

	/* new values */
	wc->wr_id = wr_id;
	wc->opcode = opcode;
	wc->byte_len = byte_len;

	/* copied values */
	wc->wc_flags = wr->send_flags;
	wc->imm_data = wr->imm_data;
	wc->status = IBV_WC_SUCCESS;

	/* send completion - it will be read in ibv_get_cq_event() */
	log_info("sending CQ completion ..."); /* = CQ pointer */
	ssize_t n_bytes = write(cq->channel->fd, &cq, sizeof(cq));
	if ((size_t)n_bytes < sizeof(cq)) {
		log_err("sending CQ completion failed");
		return EIO;
	}

	return 0;
}

/*
 * util_do_send_recv -- do send and finish receive
 */
static int
util_do_send_recv(struct ibv_send_wr *wr, enum ibv_wc_opcode opcode,
			uint32_t *byte_len)
{
	/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
	/* XXX valid only for only one client! XXX */
	/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

	/* get QP context of another node */
	int another_node = (Node_index + 1) % 2;
	struct ibv_qp *QP_AN = Nodes[another_node].qp;

	struct qp_ctx_s *qp_ctx = QP_AN->qp_context;
	struct recv_queue_s *recv_queue = &qp_ctx->recv_queue;
	if (recv_queue->i_send == recv_queue->i_recv) {
		log_err("RQ is empty!");
		return ENOBUFS;
	}

	struct rqi_s *rqi = &recv_queue->rq_items[recv_queue->i_send];
	recv_queue->i_send =
		(recv_queue->i_send + 1) % recv_queue->n_sges;

	assert_non_null(rqi->sge.addr);
	*byte_len = MIN(wr->sg_list->length, rqi->sge.length);
	memcpy((void *)rqi->sge.addr, (void *)wr->sg_list->addr,
		*byte_len);

	int ret;
	if ((ret = util_send_CQ(QP_AN->recv_cq, wr, rqi->wr_id,
				opcode, *byte_len)))
		return ret;

	return 0;
}

/*
 * ibv_post_send_mock -- mock of ibv_post_send()
 */
static int
ibv_post_send_mock(struct ibv_qp *qp, struct ibv_send_wr *wr,
			struct ibv_send_wr **bad_wr)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(qp);
	assert_non_null(wr);
	assert_null(wr->next);
	assert_non_null(wr->sg_list);
	assert_non_null(wr->sg_list->addr);
	assert_non_null(bad_wr);

	enum ibv_wc_opcode opcode;
	uint32_t byte_len;
	int ret;

	switch (wr->opcode) {
	case IBV_WR_RDMA_READ:
		opcode = IBV_WC_RDMA_READ;
		assert_non_null(wr->wr.rdma.remote_addr);
		memcpy((void *)wr->sg_list->addr,
			(void *)wr->wr.rdma.remote_addr, wr->sg_list->length);
		byte_len = wr->sg_list->length;
		break;
	case IBV_WR_RDMA_WRITE:
		opcode = IBV_WC_RDMA_WRITE;
		assert_non_null(wr->wr.rdma.remote_addr);
		memcpy((void *)wr->wr.rdma.remote_addr,
			(void *)wr->sg_list->addr, wr->sg_list->length);
		byte_len = wr->sg_list->length;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		opcode = IBV_WC_RDMA_WRITE;
		assert_non_null(wr->wr.rdma.remote_addr);
		memcpy((void *)wr->wr.rdma.remote_addr,
			(void *)wr->sg_list->addr, wr->sg_list->length);
		/* byte_len will be set by util_do_send_recv() */
		if ((ret = util_do_send_recv(wr, IBV_WC_RECV_RDMA_WITH_IMM,
						&byte_len)))
			return ret;
		break;
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		opcode = IBV_WC_SEND;
		/* byte_len will be set by util_do_send_recv() */
		if ((ret = util_do_send_recv(wr, IBV_WC_RECV, &byte_len)))
			return ret;
		break;
	default:
		log_err("unsupported opcode\n");
		return -1;
	}

	if ((wr->send_flags & IBV_SEND_SIGNALED) == 0) {
		/* RPMA_F_COMPLETION_ON_ERROR */
		return 0;
	}

	/* RPMA_F_COMPLETION_ALWAYS */
	return util_send_CQ(qp->send_cq, wr, wr->wr_id, opcode, byte_len);
}

/*
 * ibv_poll_cq_mock -- ibv_poll_cq() mock
 */
int
ibv_poll_cq_mock(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	TRACE_RET(OP_PASS, -1);

	assert_int_equal(num_entries, 1);
	assert_non_null(wc);

	struct cq_ctx_s *cq_ctx = (struct cq_ctx_s *)cq->cq_context;

	if (cq_ctx->i_read == cq_ctx->i_write) {
		log_err("CQ is empty");
		return 0;
	}

	struct ibv_wc *cq_wc = &cq_ctx->wcs[cq_ctx->i_read];
	cq_ctx->i_read = (cq_ctx->i_read + 1) % cq_ctx->n_wcs;

	memcpy(wc, cq_wc, sizeof(*wc));

	return num_entries;
}

/*
 * ibv_post_recv_mock -- mock of ibv_post_recv()
 */
static int
ibv_post_recv_mock(struct ibv_qp *qp, struct ibv_recv_wr *wr,
			struct ibv_recv_wr **bad_wr)
{
	TRACE_RET(OP_PASS, -1);

	assert_non_null(qp);
	assert_non_null(wr);
	assert_null(wr->next);
	assert_non_null(wr->sg_list);
	assert_non_null(wr->sg_list->addr);
	assert_non_null(bad_wr);

	struct qp_ctx_s *qp_ctx = qp->qp_context;
	struct recv_queue_s *recv_queue = &qp_ctx->recv_queue;

	int new_recv = (recv_queue->i_recv + 1) % recv_queue->n_sges;
	if (new_recv == recv_queue->i_send) {
		log_err("RQ is full");
		return ENOBUFS;
	}

	struct rqi_s *rqi = &recv_queue->rq_items[recv_queue->i_recv];
	recv_queue->i_recv = new_recv;

	rqi->wr_id = wr->wr_id;
	memcpy(&rqi->sge, wr->sg_list, sizeof(rqi->sge));

	return 0;
}
