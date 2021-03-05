/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2021, Intel Corporation */

/*
 * minussr-trace.h -- Minimal User-Space Soft RoCE (minussr) tracing API header
 */

#define OP_PASS			0
#define OP_FAIL			1
#define OP_ABORT		2

#define FLAG_IS_VOID		1
#define FLAG_CAN_FAIL		2

#define FLAG_IS_SET(flags, f)	((flags & f) == f)
#define IS_VOID(flags)		FLAG_IS_SET(flags, FLAG_IS_VOID)
#define CAN_FAIL(flags)		FLAG_IS_SET(flags, FLAG_CAN_FAIL)

#define NONE			0 /* 'none' value used in void functions */

#define TRACE_DO_NOT_FAIL(op) \
do { \
	static __thread int _n_called = 0; \
	_n_called++; \
	((void) trace(__func__, op, NONE, FLAG_IS_VOID, _n_called)); \
} while (0)

/* ret - value returned if (op == OP_FAIL) */
#define TRACE_RET(op, ret) \
do { \
	static __thread int _n_called = 0; \
	_n_called++; \
	if (trace(__func__, op, (long)ret, FLAG_CAN_FAIL, _n_called)) \
		return ret; \
} while (0)

#define TRACE_VOID(op) \
do { \
	static __thread int _n_called = 0; \
	_n_called++; \
	if (trace(__func__, op, NONE, FLAG_CAN_FAIL | FLAG_IS_VOID, \
	    _n_called)) \
		return; \
} while (0)

#define log_err(msg) \
	fprintf(stderr, "[%s] ERROR: %s(): %s\n", My_name, __func__, msg);

#define log_info(msg) \
	fprintf(stderr, "[%s] %s(): %s\n", My_name, __func__, msg);

/* >>> Beginning of Thread-Local Storage <<< */
extern __thread int Iam_server;
extern __thread pid_t My_TID;
extern __thread const char *My_name;
extern __thread int Fail_at_trace;
/* >>> End of Thread-Local Storage <<< */

extern int minussr_init(int iam_server);
void set_tls_vars(int is_client, int fail_at_trace);
int trace(const char *func, int op, long ret, int flags, int n_called);
