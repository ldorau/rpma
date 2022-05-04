// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021, Intel Corporation */

/*
 * server_rpma_recv.c -- implementation of rpma_recv-specific functions for common server
 *                        of multi-connection MT tests
 */

#include "server_rpma_common.h"

/*
 * client_completion_event_handle -- callback on completion is ready
 */
void
client_completion_event_handle(struct custom_event *ce)
{
	struct client_res *clnt = (struct client_res *)ce->arg;
	const struct server_res *svr = clnt->svr;

	/* wait for the completion to be ready */
	int ret = rpma_cq_wait(clnt->cq);
	if (ret) {
		/* no completion is ready - continue */
		if (ret == RPMA_E_NO_COMPLETION)
			return;

		/* another error occurred - disconnect */
		(void) rpma_conn_disconnect(clnt->conn);
		return;
	}

	/* get next completion */
	struct ibv_wc wc;
	ret = rpma_cq_get_wc(clnt->cq, 1, &wc, NULL);
	if (ret) {
		/* no completion is ready - continue */
		if (ret == RPMA_E_NO_COMPLETION)
			return;

		/* another error occurred - disconnect */
		(void) rpma_conn_disconnect(clnt->conn);
		return;
	}

	/* validate received completion */
	if (wc.status != IBV_WC_SUCCESS) {
		SERVER_ERR_MSG("rpma_send() failed");
		SERVER_ERR_MSG(ibv_wc_status_str(wc.status));
		(void) rpma_conn_disconnect(clnt->conn);
		return;
	}

	if (wc.opcode != IBV_WC_SEND) {
		SERVER_ERR_MSG("received unexpected wc.opcode value");
		(void) rpma_conn_disconnect(clnt->conn);
		return;
	}

	/* post an RDMA recv operation */
	ret = rpma_send(clnt->conn, svr->mr_local_ptr, 0, svr->mr_local_size,
				RPMA_F_COMPLETION_ALWAYS, NULL);
	if (ret)
		SERVER_RPMA_ERR("rpma_send() failed", ret);
}

/*
 * client_is_ready_handle -- callback on connection is established
 */
void
client_is_ready_handle(struct client_res *clnt)
{
	const struct server_res *svr = clnt->svr;

	/* post an RDMA recv operation */
	int ret = rpma_send(clnt->conn, svr->mr_local_ptr, 0, svr->mr_local_size,
				RPMA_F_COMPLETION_ALWAYS, NULL);
	if (ret)
		SERVER_RPMA_ERR("rpma_send() failed", ret);
}
