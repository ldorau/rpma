/* obtain an IBV context for a remote IP address */
rpma_utils_get_ibv_context(addr, RPMA_UTIL_IBV_CONTEXT_REMOTE, &dev);

/* create a new peer object */
rpma_peer_new(dev, &peer);

	/* allocate a memory */
	malloc_aligned(KILOBYTE);

	/* register the memory */
	rpma_mr_reg(peer, mr_ptr, mr_size, RPMA_MR_USAGE_READ_SRC, &mr);

	/* get size of the memory region's descriptor */
	rpma_mr_get_descriptor_size(mr, &mr_desc_size);

	/* get the memory region's descriptor */
	rpma_mr_get_descriptor(mr, &data.descriptors[0]);

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

/* wait for the connection to being closed */
rpma_conn_next_event(conn, &conn_event);
if (!ret && conn_event != RPMA_CONN_CLOSED) {
	fprintf(stderr, "rpma_conn_next_event returned an unexptected event\n");
}

/* disconnect the connection */
rpma_conn_disconnect(conn);

	/* deregister the memory region */
	rpma_mr_dereg(&dst_mr);

/* delete the connection object */
rpma_conn_delete(&conn);

/* delete the peer object */
rpma_peer_delete(&peer);
