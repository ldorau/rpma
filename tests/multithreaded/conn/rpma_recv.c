// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2022, Intel Corporation */

/*
 * rpma_recv.c -- rpma_recv multithreaded test
 */

#include <librpma.h>
#include "mtt.h"
#include "rpma_common.h"

/*
 * thread -- main function of rpma_recv multithreaded test
 */
void
thread(unsigned id, void *prestate, void *state, struct mtt_result *result)
{
	struct thread_state *ts = (struct thread_state *)state;

	/* zero the destination memory */
	memset(ts->local_ptr, 0, ts->mr_local_size);

	/* post an RDMA receive operation */
	int ret = rpma_recv(ts->conn, ts->mr_local_ptr, 0, ts->mr_local_size, (void *)WR_ID_RECV);
	if (ret) {
		MTT_ERR_MSG(result, "rpma_recv() failed", ret);
		return;
	}

	ret = wait_and_validate_completion(ts->cq, IBV_WC_RECV, WR_ID_RECV, result);
	if (ret)
		return;

	if (strncmp(ts->local_ptr, STRING_TO_READ_RECV, LEN_STRING_TO_READ_RECV) != 0) {
		MTT_ERR_MSG(result, "received string mismatch", -1);
		fprintf(stderr, "\n>>>%s<<<\n", (char *)ts->local_ptr);
		fprintf(stderr,   ">>>%s<<<\n", STRING_TO_READ_RECV);
	}
}
