// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021, Intel Corporation */

/*
 * minussr-main.c -- Minimal User-Space Soft RoCE (minussr) framework
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <rdma/rdma_cma.h>

#include "librpma.h"
#include "minussr-trace.h"

#define SERVER		0
#define CLIENT		1

#define ARGC		4
#define MOCK_ADDR	"192.168.0.0"
#define MOCK_PORT	"7204"
#define MOCK_SEED	"1234"

int client_main(int argc, char *argv[]);
int server_main(int argc, char *argv[]);

struct pthread_args {
	int is_client;
	int argc;
	char **argv;
	int ret;
	int fail_at_trace;
};

static char *argvs[][ARGC] = {
	{"server", MOCK_ADDR, MOCK_PORT, ""},
	{"client", MOCK_ADDR, MOCK_PORT, MOCK_SEED},
};

static struct pthread_args threads_args[] = {
	{SERVER, ARGC, argvs[SERVER], 0, 0},
	{CLIENT, ARGC, argvs[CLIENT], 0, 0},
};

static void *thread_main(void *arg)
{
	struct pthread_args *args = (struct pthread_args *)arg;

	set_tls_vars(args->is_client, args->fail_at_trace);

	if (args->is_client) {
		printf("\n>>> Starting CLIENT (%i) <<<<\n\n", My_TID);
		args->ret = client_main(args->argc, args->argv);
	} else {
		printf("\n>>> Starting SERVER (%i) <<<<\n\n", My_TID);
		args->ret = server_main(args->argc, args->argv);
	}

	return NULL;
}

int
main(int argc, char *argv[])
{
	int ret = 0;

	if (argc >= 2) {
		int fail_at_trace = atoi(argv[1]);
		/*
		 * fail_at_trace > 0 - is for the server
		 * fail_at_trace < 0 - is for the client
		 */
		if (fail_at_trace > 0)
			threads_args[SERVER].fail_at_trace = fail_at_trace;
		else if (fail_at_trace < 0)
			threads_args[CLIENT].fail_at_trace = -fail_at_trace;
	}

	pthread_t *threads = calloc(2, sizeof(*threads));
	if (threads == NULL) {
		perror("malloc");
		return -1;
	}

	/* run the server */
	ret = pthread_create(&threads[SERVER], NULL, thread_main,
		&threads_args[SERVER]);
	if (ret) {
		fprintf(stderr, "Cannot start the server thread\n");
		goto err_free_threads;
	}

	sleep(1);

	/* run the client */
	ret = pthread_create(&threads[CLIENT], NULL, thread_main,
		&threads_args[CLIENT]);
	if (ret) {
		fprintf(stderr, "Cannot start the client thread\n");
		goto err_join_server;
	}

	(void) pthread_join(threads[CLIENT], NULL);
err_join_server:
	(void) pthread_join(threads[SERVER], NULL);

	printf("\n\n");
	ret = threads_args[SERVER].ret;
	fprintf(stderr, "Server's exit status: %s (%i)\n",
			rpma_err_2str(ret), ret);
	ret = threads_args[CLIENT].ret;
	fprintf(stderr, "Client's exit status: %s (%i)\n",
			rpma_err_2str(ret), ret);
	printf("\n\n");

err_free_threads:
	free(threads);

	return ret;
}
