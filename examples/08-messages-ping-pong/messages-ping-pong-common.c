// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2022, Intel Corporation */

/*
 * messages-ping-pong-common.c -- a common definitions for the 08 example
 */

#include <librpma.h>
#include <inttypes.h>

#include "messages-ping-pong-common.h"

int
get_wc_and_validate(struct rpma_cq *cq, uint64_t *recv,
		int *send_cmpl, int *recv_cmpl)
{
	struct ibv_wc wc[2];
	int ret;
	int num_entries_got;

	if ((ret = rpma_cq_wait(cq)))
		return ret;

	if ((ret = rpma_cq_get_wc(cq, 2, wc, &num_entries_got))) {
		if (ret == RPMA_E_NO_COMPLETION)
			ret = 0;
		return ret;
	}

	for (int i = 0; i < num_entries_got; i++) {
		if (wc[i].status != IBV_WC_SUCCESS) {
			char *func = (wc->opcode == IBV_WC_SEND)?
				"send" : "recv";
			(void) fprintf(stderr,
				"rpma_%s() failed: %s\n", func,
				ibv_wc_status_str(wc->status));
			return -1;
		}

		if (wc[i].opcode == IBV_WC_SEND) {
			*send_cmpl = 1;
		} else if (wc[i].opcode == IBV_WC_RECV) {
			if (wc[i].wr_id != (uintptr_t)recv ||
					wc[i].byte_len != MSG_SIZE) {
				(void) fprintf(stderr,
					"received completion is not as expected (0x%"
					PRIXPTR " != 0x%" PRIXPTR
					" [wc[i].wr_id] || %" PRIu32
					" != %ld [wc[i].byte_len])\n",
					wc[i].wr_id, (uintptr_t)recv,
					wc[i].byte_len, MSG_SIZE);
				return -1;
			}
			*recv_cmpl = 1;
		}
	}

	return 0;
}
