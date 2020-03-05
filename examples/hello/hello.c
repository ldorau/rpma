/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2020, Intel Corporation
 */

/*
 * hello.c -- hello world for librpma
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libpmem.h>
#include <librpma.h>

#define LANG_NON (0)

enum lang_t { en, es };

static const char *hello_str[] = {
	[en] = "Hello world!",
	[es] = "¡Hola Mundo!"
};

#define LANG_NUM (sizeof(hello_str) / sizeof(hello_str[0]))

#define STR_SIZE 100

struct hello_t {
	enum lang_t lang;
	char str[STR_SIZE];
	uint64_t valid;
};

#define HELLO_SIZE (sizeof(struct hello_t))

#define TYPE_SERVER ('s')
#define TYPE_CLIENT ('c')

struct base_t {
	const char *addr;
	const char *service;
	const char *file; /* applicable to server only */
	char type;
	void *specific;

	struct rpma_zone *zone;
	struct rpma_dispatcher *disp;
	struct rpma_connection *conn;
};

struct server_t {
	struct hello_t *ptr;
	size_t total_size;

	struct rpma_memory_local *mem;
	struct rpma_memory_id id;
};

struct msg_t {
	struct rpma_memory_id id;
	uint64_t init_required;
};

struct client_t {
	pthread_t thread; /* dispatcher thread */
	uint64_t running;

	struct {
		struct hello_t *ptr;
		struct rpma_memory_local *mem;
	} local;

	struct {
		struct rpma_memory_id id;
		struct rpma_memory_remote *mem;
	} remote;
};

static inline void
write_hello_str(struct hello_t *hello, enum lang_t lang)
{
	hello->lang = lang;
	strncpy(hello->str, hello_str[hello->lang], STR_SIZE);
	hello->valid = 1;
}

static int
hello_init(struct rpma_connection *conn, void *uarg)
{
	struct client_t *clnt = uarg;
	write_hello_str(clnt->local.ptr, en);

	printf("write message to the target...\n");
	rpma_connection_write(conn, clnt->remote.mem, 0, clnt->local.mem, 0,
				HELLO_SIZE);
	rpma_connection_commit(conn);

	rpma_connection_dispatch_break(conn);

	rpma_connection_disconnect(conn);

	return 0;
}

static int
hello_revisit(struct rpma_connection *conn, void *uarg)
{
	struct client_t *clnt = uarg;
	printf("read message from the target...\n");
	rpma_connection_read(conn, clnt->local.mem, 0, clnt->remote.mem, 0,
				HELLO_SIZE);

	struct hello_t *hello = clnt->local.ptr;

	printf("translating...\n");
	enum lang_t lang = (enum lang_t)((hello->lang + 1) % LANG_NUM);
	write_hello_str(hello, lang);
	printf("%s\n", hello->str);

	printf("write message to the target...\n");
	rpma_connection_write(conn, clnt->remote.mem, 0, clnt->local.mem, 0,
				HELLO_SIZE);
	rpma_connection_commit(conn);

	rpma_connection_dispatch_break(conn);

	rpma_connection_disconnect(conn);

	return 0;
}

static int
on_connection_recv(struct rpma_connection *conn, void *ptr, size_t length)
{
	struct base_t *b = NULL;
	int ret = rpma_connection_get_custom_data(conn, (void **)&b);
	if (ret)
		return ret;

	struct client_t *clnt = b->specific;

	struct msg_t *msg = ptr;
	clnt->remote.id = msg->id;
	rpma_memory_remote_new(b->zone, &msg->id, &clnt->remote.mem);

	if (msg->init_required)
		rpma_connection_enqueue(b->conn, hello_init, clnt);
	else
		rpma_connection_enqueue(b->conn, hello_revisit, clnt);

	return 0;
}

static int
send_msg(struct rpma_connection *conn, void *arg)
{
	struct base_t *b = NULL;
	int ret = rpma_connection_get_custom_data(conn, (void **)&b);
	if (ret)
		return ret;

	assert(b != NULL);
	struct server_t *svr = b->specific;

	struct msg_t *msg;
	rpma_msg_get_ptr(conn, (void **)&msg);

	memcpy(&msg->id, &svr->id, sizeof(svr->id));
	if (!svr->ptr->valid)
		msg->init_required = 1;

	rpma_connection_send(conn, msg);

	rpma_connection_dispatch_break(conn);

	return 0;
}

#define TIMEOUT_TIME (15000) /* 15s */

#define TIMEOUT_COUNT_MAX 4

static int
on_timeout(struct rpma_zone *zone, void *uarg)
{
	static int count = 0;
	printf("RPMA zone connection timeout %d\n", count);

	if (count == TIMEOUT_COUNT_MAX)
		rpma_zone_wait_break(zone);

	++count;

	return 0;
}

static int
on_connection_event(struct rpma_zone *zone, uint64_t event,
		    struct rpma_connection *conn, void *uarg)
{
	struct base_t *b = uarg;
	int ret = 0;

	switch (event) {
		case RPMA_CONNECTION_EVENT_INCOMING:
			/* accept the incoming connection */
			rpma_connection_new(zone, &b->conn);
			rpma_connection_set_custom_data(b->conn, (void *)b);
			rpma_connection_accept(b->conn);
			rpma_connection_attach(b->conn, b->disp);

			/* stop waiting for timeout */
			rpma_zone_unregister_on_timeout(zone);

			/* send the message */
			rpma_connection_enqueue(b->conn, send_msg, NULL);
			rpma_dispatch(b->disp); /* XXX single run */
			break;

		case RPMA_CONNECTION_EVENT_OUTGOING:
			/* establish the outgoing connection */
			rpma_connection_new(zone, &b->conn);
			rpma_connection_set_custom_data(b->conn, (void *)b);
			ret = rpma_connection_establish(b->conn);
			if (ret) {
				rpma_connection_delete(&b->conn);
				return ret;
			}
			rpma_connection_attach(b->conn, b->disp);

			/* stop waiting for timeout */
			rpma_zone_unregister_on_timeout(zone);

			/* register transmission callback */
			rpma_connection_register_on_recv(b->conn,
				on_connection_recv);
			rpma_dispatch(b->disp); /* XXX single run */
			break;

		case RPMA_CONNECTION_EVENT_DISCONNECT:
			rpma_connection_detach(b->conn);
			rpma_connection_delete(&b->conn);

			if (b->type == TYPE_CLIENT)
				rpma_zone_wait_break(zone);
			else
				rpma_zone_register_on_timeout(zone, on_timeout,
					TIMEOUT_TIME);

			break;
		default:
			return RPMA_E_UNHANDLED_EVENT;
	}

	return 0;
}

static int
remote_init(struct base_t *b)
{
	struct rpma_config *cfg;
	rpma_config_new(&cfg);
	rpma_config_set_addr(cfg, b->addr);
	rpma_config_set_service(cfg, b->service);
	rpma_config_set_send_queue_length(cfg, 1);
	rpma_config_set_recv_queue_length(cfg, 1);
	rpma_config_set_msg_size(cfg, sizeof(struct msg_t));
	rpma_config_set_queue_alloc_funcs(cfg, malloc, free);

	if (b->type == TYPE_SERVER)
		rpma_config_set_flags(cfg, RPMA_CONFIG_IS_SERVER);

	int ret = rpma_zone_new(cfg, &b->zone);
	rpma_config_delete(&cfg);

	if (!b->zone) {
		fprintf(stderr, "Cannot create an RPMA zone: %d\n", ret);
		return ret;
	}

	rpma_zone_register_on_connection_event(b->zone, on_connection_event);
	rpma_zone_register_on_timeout(b->zone, on_timeout, TIMEOUT_TIME);

	rpma_dispatcher_new(b->zone, &b->disp);

	struct client_t *clnt;
	struct server_t *svr;

	switch (b->type) {
		case TYPE_CLIENT:
			clnt = b->specific;
			rpma_memory_local_new(
				b->zone, clnt->local.ptr, HELLO_SIZE,
				RPMA_MR_WRITE_SRC | RPMA_MR_READ_DST,
				&clnt->local.mem);
			break;
		case TYPE_SERVER:
			svr = b->specific;
			rpma_memory_local_new(b->zone, svr->ptr, HELLO_SIZE,
				RPMA_MR_WRITE_DST | RPMA_MR_READ_SRC,
				&svr->mem);
			rpma_memory_local_get_id(svr->mem, &svr->id);
	}

	return 0;
}

static void
remote_fini(struct base_t *b)
{
	struct client_t *clnt;
	struct server_t *svr;

	switch (b->type) {
		case TYPE_CLIENT:
			clnt = b->specific;

			clnt->running = 0; /* XXX atomic */

			rpma_memory_local_delete(&clnt->local.mem);
			break;
		case TYPE_SERVER:
			svr = b->specific;
			rpma_memory_local_delete(&svr->mem);
	}

	rpma_dispatcher_delete(&b->disp);
	rpma_zone_delete(&b->zone);
}

static void
parse_args(int argc, char *argv[], struct base_t *b)
{
	if (argc < 4)
		goto err_usage;

	b->type = argv[1][0];
	b->addr = argv[2];
	b->service = argv[3];

	switch (b->type) {
		case TYPE_CLIENT:
			break;
		case TYPE_SERVER:
			if (argc < 5)
				goto err_usage;

			b->file = argv[4];
			break;
		default:
			goto err_usage;
	}

	return;

err_usage:
	fprintf(stderr,
		"usage:\n"
		"\t%s c <addr> <service>\n"
		"\t%s s <addr> <service> <file>\n",
		argv[0], argv[0]);
	exit(1);
}

static void *
alloc_memory()
{
	long pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		perror("sysconf");
		exit(1);
	}

	/* allocate a page size aligned local memory pool */
	void *mem;
	int ret = posix_memalign(&mem, pagesize, HELLO_SIZE);
	if (ret) {
		fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
		exit(1);
	}

	return mem;
}

static void
mem_init(struct base_t *b)
{
	struct client_t *clnt;
	struct server_t *svr;

	switch (b->type) {
		case TYPE_CLIENT:
			clnt = calloc(1, sizeof(struct client_t));
			clnt->local.ptr = alloc_memory();
			b->specific = clnt;
			break;
		case TYPE_SERVER:
			svr = calloc(1, sizeof(struct server_t));

			/* try creating a memory pool */
			size_t len = HELLO_SIZE;
			int flags = PMEM_FILE_CREATE;
			mode_t mode = 0666;
			svr->ptr = pmem_map_file(b->file, len, flags, mode,
						&svr->total_size, NULL);
			if (!svr->ptr) {
				assert(errno == EEXIST);

				/* try opening a memory pool */
				len = 0;
				flags = 0;
				svr->ptr =
					pmem_map_file(b->file, len, flags, 0,
							&svr->total_size, NULL);
			}

			assert(svr->ptr != NULL);
			b->specific = svr;
	}
}

static void
mem_fini(struct base_t *b)
{
	struct client_t *clnt;
	struct server_t *svr;

	switch (b->type) {
		case TYPE_CLIENT:
			clnt = b->specific;
			free(clnt->local.ptr);
			break;
		case TYPE_SERVER:
			svr = b->specific;
			pmem_unmap(svr->ptr, svr->total_size);
			break;
	}

	free(b->specific);
}

int
main(int argc, char *argv[])
{
	int ret = 0;

	struct base_t base;
	memset(&base, 0, sizeof(base));

	parse_args(argc, argv, &base);

	mem_init(&base);
	ret = remote_init(&base);
	if (ret)
		goto err_remote_init;

	ret = rpma_zone_wait_connections(base.zone, &base);

	if (ret)
		fprintf(stderr, "hello: %s\n", strerror(ret));

err_remote_init:
	remote_fini(&base);
	mem_fini(&base);

	return ret;
}
