// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2022, Intel Corporation */

/*
 * receive-completion-queue-common.c -- a common declarations for the 12 example
 */

#include <librpma.h>
#include <inttypes.h>

#include "receive-completion-queue-common.h"

int
get_wc_and_validate(struct rpma_conn *conn, struct rpma_cq *cq,
		enum ibv_wc_opcode opcode, char *func_name)
{
	struct ibv_wc wc;
	int ret;

	struct rpma_cq *cq_got = NULL;
	if ((ret = rpma_conn_wait(conn, &cq_got))) {
		(void) fprintf(stderr, "error: rpma_conn_wait() failed: %s\n",
				rpma_err_2str(ret));
		return ret;
	}

	if (cq_got != cq) {
		(void) fprintf(stderr, "error: got unexpected CQ\n");
		return ret;
	}

	if ((ret = rpma_cq_get_wc(cq, 1, &wc, NULL)))
		return ret;

	if (wc.status != IBV_WC_SUCCESS) {
		(void) fprintf(stderr, "%s failed: %s\n",
			func_name, ibv_wc_status_str(wc.status));
		return -1;
	}

	if (wc.opcode != opcode) {
		(void) fprintf(stderr, "unexpected wc.opcode value "
			"(0x%" PRIXPTR " != 0x%" PRIXPTR ")\n",
			(uintptr_t)wc.opcode, (uintptr_t)opcode);
		return -1;
	}
	return 0;
}
