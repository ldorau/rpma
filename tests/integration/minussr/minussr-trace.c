// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2021, Intel Corporation */

/*
 * minussr-trace.c -- Minimal User-Space Soft RoCE (minussr) tracing API
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "minussr-trace.h"


/* >>> Beginning of Thread-Local Storage <<< */
__thread int Iam_server = 0;
__thread pid_t My_TID = 0;
__thread const char *My_name = NULL;
__thread int Fail_at_trace = 0;
/* >>> End of Thread-Local Storage <<< */

void
set_tls_vars(int is_client, int fail_at_trace)
{
	My_TID = gettid();

	if (fail_at_trace > 0)
		Fail_at_trace = fail_at_trace;

	if (is_client) {
		Iam_server = 0;
		My_name = "client";
	} else {
		Iam_server = 1;
		My_name = "server";
	}

	minussr_init(Iam_server);
}

int
trace(const char *func, int op, long ret, int flags, int n_called)
{
	static __thread int _n_func_trace = 0;

	if (Iam_server)
		fprintf(stderr, "[server] # ");
	else
		fprintf(stderr, "[client] - ");

	if (CAN_FAIL(flags))
		_n_func_trace++;

	if (Fail_at_trace) {
		fprintf(stderr, "[#%i] ", _n_func_trace);
		if (CAN_FAIL(flags) && (Fail_at_trace == _n_func_trace))
			fprintf(stderr, "FORCED TO FAIL: ");
	}

	switch (op) {
	case OP_PASS:
		if (n_called > 1)
			fprintf(stderr, "%s(%i)\n", func, n_called);
		else
			fprintf(stderr, "%s()\n", func);
		break;
	case OP_FAIL:
		if (IS_VOID(flags))
			fprintf(stderr, "%s() RETURN \n", func);
		else
			fprintf(stderr, "%s() RETURN %li \n", func, ret);
		goto fail;
	case OP_ABORT: /* function is NOT IMPLEMENTED yet */
		fprintf(stderr, "%s() NOT IMPLEMENTED yet \n", func);
		exit(-1);
	}

	if (CAN_FAIL(flags) &&
	    Fail_at_trace && (Fail_at_trace == _n_func_trace))
		goto fail;

	return 0;

fail:
	errno = -1;
	return -1;
}
