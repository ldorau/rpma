// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2022, Fujitsu */

/*
 * server.c -- a server of the messages-ping-pong-with-srq example
 *
 * Please see README.md for a detailed description of this example.
 */

#include <inttypes.h>
#include <librpma.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "common-conn.h"

#define USAGE_STR	"usage: %s <server_address> <port> [<num_clients>]\n"
#define MSG_SIZE	sizeof(uint64_t)
#define I_M_DONE	(uint64_t)UINT64_MAX
#define CLIENT_MAX	10

struct connect_context {
	struct rpma_conn *conn;
	struct rpma_cq *cq;
	uint32_t qp_num;
};

static struct connect_context conn_ctxs[CLIENT_MAX];
static int num_clients;

static int
find_connection(uint32_t qp_num)
{
	int i;

	if (num_clients == 1)
		return 0;

	for (i = 0; i < num_clients; ++i)
		if (conn_ctxs[i].qp_num == qp_num)
			return i;

	(void) fprintf(stderr, "Unable to find the connection[qp#%d]\n", qp_num);
	return -1;
}

int
main(int argc, char *argv[])
{
	/* validate parameters */
	if (argc < 3) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_INFO);

	/* read common parameters */
	char *addr = argv[1];
	char *port = argv[2];
	int ret;

	num_clients = argv[3] ? strtoul(argv[3], NULL, 10) : 1;

	/* prepare memory */
	struct rpma_mr_local *recv_mr, *send_mr;
	size_t size = MSG_SIZE * (size_t)num_clients;
	uint64_t *recv = malloc_aligned(size);
	if (recv == NULL)
		return -1;

	uint64_t *send = malloc_aligned(size);
	if (send == NULL) {
		ret = -1;
		goto err_free_recv;
	}

	/* RPMA resources */
	struct rpma_peer *peer = NULL;
	struct rpma_srq *srq = NULL;
	struct rpma_conn_cfg *cfg = NULL;
	struct rpma_ep *ep = NULL;
	struct rpma_cq *rcq = NULL;
	int i, index, offset, num_got, total_cnt = 0;
	uint64_t *recv_ptr = NULL;
	struct ibv_wc wc[CLIENT_MAX];

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	if ((ret = server_peer_via_address(addr, &peer)))
		goto err_free_send;

	/* create a shared RQ object */
	if ((ret = rpma_srq_new(peer, NULL, &srq)))
		goto err_peer_delete;

	/* create a new connection configuration */
	if ((ret = rpma_conn_cfg_new(&cfg)))
		goto err_srq_delete;

	/* set the shared RQ object for the connection configuration */
	if ((ret = rpma_conn_cfg_set_srq(cfg, srq)))
		goto err_conn_cfg_delete;

	/* start a listening endpoint at addr:port */
	if ((ret = rpma_ep_listen(peer, addr, port, &ep)))
		goto err_conn_cfg_delete;

	/* register the memory */
	if ((ret = rpma_mr_reg(peer, recv, size, RPMA_MR_USAGE_RECV, &recv_mr)))
		goto err_ep_shutdown;

	if ((ret = rpma_mr_reg(peer, send, size, RPMA_MR_USAGE_SEND, &send_mr)))
		goto err_recv_mr_dereg;

	for (offset = 0; offset < num_clients; ++offset) {
		/*
		 * put an initial receive for each connection to be prepared for
		 * the first message of the client's ping-pong.
		 */
		if ((ret = rpma_srq_recv(srq, recv_mr, (size_t)offset, MSG_SIZE, recv + offset)))
			goto err_send_mr_dereg;
	}

	/*
	 * In loops, wait for an incoming connection request,
	 * accept it and wait for its establishment.
	 */
	for (i = 0; i < num_clients; ++i)
		if ((ret = server_accept_connection(ep, cfg, NULL, &conn_ctxs[i].conn)))
			goto err_conn_disconnect;

	/* get the qp_num of each connection */
	for (i = 0; i < num_clients; ++i)
		if ((ret = rpma_conn_get_qp_num(conn_ctxs[i].conn, &conn_ctxs[i].qp_num)))
			goto err_conn_disconnect;

	/* get the receive CQ of rpma_srq object */
	if ((ret = rpma_srq_get_rcq(srq, &rcq)))
		goto err_conn_disconnect;

	do {
		/* wait for the completion to be ready */
		if ((ret = rpma_cq_wait(rcq)))
			break;

		if ((ret = rpma_cq_get_wc(rcq, num_clients, wc, &num_got)))
			break;

		/* validate received completions */
		for (i = 0; i < num_got; ++i) {
			if (wc[i].status != IBV_WC_SUCCESS) {
				(void) fprintf(stderr, "rpma_srq_recv() failed: %s\n",
						ibv_wc_status_str(wc[i].status));
				ret = -1;
				break;
			}

			if (wc[i].opcode != IBV_WC_RECV) {
				(void) fprintf(stderr,
						"received unexpected wc.opcode value (%d != %d)\n",
						wc[i].opcode, IBV_WC_RECV);
				ret = -1;
				break;
			}

			index = find_connection(wc[i].qp_num);
			if (index == -1) {
				ret = -1;
				break;
			}

			offset = wc[i].wr_id - (uint64_t)recv;
			recv_ptr = (uint64_t *)wc[i].wr_id;
			if (*recv_ptr == I_M_DONE) {
				total_cnt++;
				continue;
			}

			(void) printf("Value received: %" PRIu64 " from the conection[qp#%d]\n",
					*recv_ptr, conn_ctxs[index].qp_num);

			/* prepare a receive for the client's request */
			if ((ret = rpma_srq_recv(srq, recv_mr, (size_t)offset,
					MSG_SIZE, recv_ptr))) {
				ret = -1;
				break;
			}

			*(send + index) = *recv_ptr + 1;

			(void) printf("Value sent: %" PRIu64 " from the conection[qp#%d]\n",
					*(send + index), conn_ctxs[index].qp_num);

			/* send a message to the client */
			if ((ret = rpma_send(conn_ctxs[index].conn, send_mr, (size_t)index,
					MSG_SIZE, RPMA_F_COMPLETION_ON_ERROR, NULL))) {
				ret = -1;
				break;
			}
		}
	} while (!ret && total_cnt < num_clients);

	if (total_cnt != num_clients) {
		(void) fprintf(stderr, "Unable to receive data from all conections\n");
		ret = -1;
	}

err_conn_disconnect:
	/* disconnect all remaining client's */
	for (i = 0; i < num_clients; ++i) {
		if (conn_ctxs[i].conn == NULL)
			continue;

		(void) rpma_conn_disconnect(conn_ctxs[i].conn);
		(void) rpma_conn_delete(&conn_ctxs[i].conn);
	}

err_send_mr_dereg:
	ret |= rpma_mr_dereg(&send_mr);

err_recv_mr_dereg:
	ret |= rpma_mr_dereg(&recv_mr);

err_ep_shutdown:
	ret |= rpma_ep_shutdown(&ep);

err_conn_cfg_delete:
	ret |= rpma_conn_cfg_delete(&cfg);

err_srq_delete:
	ret |= rpma_srq_delete(&srq);

err_peer_delete:
	/* delete the peer object */
	ret |= rpma_peer_delete(&peer);

err_free_send:
	free(send);

err_free_recv:
	free(recv);

	return ret ? -1 : 0;
}
