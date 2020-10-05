/* obtain an IBV context for a remote IP address */
rpma_utils_get_ibv_context(addr, RPMA_UTIL_IBV_CONTEXT_REMOTE, &dev);

/* create a new peer object */
rpma_peer_new(dev, &peer);

	/* allocate a memory */
	malloc_aligned(KILOBYTE);

	/* register the memory */
	rpma_mr_reg(peer, dst_ptr, KILOBYTE, RPMA_MR_USAGE_READ_DST, &dst_mr);

/* create a connection request */
rpma_conn_req_new(peer, addr, port, NULL, &req);

/* connect the connection request and obtain the connection object */
rpma_conn_req_connect(&req, &pdata, &conn);

/* wait for the connection to establish */
rpma_conn_next_event(conn, &conn_event);
if (ret) {
	goto err_conn_delete;
} else if (conn_event != RPMA_CONN_ESTABLISHED) {
	fprintf(stderr,
			"rpma_conn_next_event returned an unexpected event\n");
	goto err_conn_delete;
}

/* here you can use the newly established connection */
rpma_conn_get_private_data(conn, &pdata);

	/* Create a remote memory registration structure from the received descriptor. */
	rpma_mr_remote_from_descriptor(&dst_data->descriptors[0], dst_data->mr_desc_size, &src_mr);

	/* get the remote memory region size */
	rpma_mr_remote_get_size(src_mr, &src_size);

	/* post an RDMA read operation */
	rpma_read(conn, dst_mr, 0, src_mr, 0, src_size, RPMA_F_COMPLETION_ALWAYS, NULL);

	/* wait for the completion to be ready */
	rpma_conn_completion_wait(conn);

	/* wait for a completion of the RDMA read */
	rpma_conn_completion_get(conn, &cmpl);
	if (cmpl.op != RPMA_OP_READ) {
		fprintf(stderr);
	} else if (cmpl.op_status == IBV_WC_SUCCESS) {
		fprintf(stdout, "Read a message: %s\n", (char *)dst_ptr);
	}

/* wait for the connection to being closed */
rpma_conn_next_event(conn, &conn_event);

	/* delete the remote memory region's structure */
	rpma_mr_remote_delete(&src_mr);

/* disconnect the connection */
rpma_conn_disconnect(conn);

	/* deregister the memory region */
	rpma_mr_dereg(&dst_mr);

/* delete the connection object */
rpma_conn_delete(&conn);

/* delete the peer object */
rpma_peer_delete(&peer);
