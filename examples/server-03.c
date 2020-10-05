/* obtain an IBV context for a local IP address */
rpma_utils_get_ibv_context(addr, RPMA_UTIL_IBV_CONTEXT_LOCAL, &dev);

/* create a new peer object */
rpma_peer_new(dev, &peer);

/* create a new endpoint object */
rpma_ep_listen(peer, addr, port, &ep);

	/* register the memory */
	rpma_mr_reg(peer, dst_ptr, dst_size, RPMA_MR_USAGE_READ_DST, &dst_mr);

/* obtain an incoming connection request */
rpma_ep_next_conn_req(ep, NULL, &req);

/* connect / accept the connection request and obtain the connection object */
rpma_conn_req_connect(&req, &pdata, &conn);

/* wait for the connection to being establish */
rpma_conn_next_event(conn, &conn_event);
if (ret) {
	goto err_conn_delete;
} else if (conn_event != RPMA_CONN_ESTABLISHED) {
	fprintf(stderr,
			"rpma_conn_next_event returned an unexpected event\n");
	goto err_conn_delete;
}

	/* obtain the remote memory description */
	rpma_conn_get_private_data(conn, &pdata);
	rpma_mr_remote_from_descriptor(&src_data->descriptors[0], src_data->mr_desc_size, &src_mr);

	rpma_read(conn, dst_mr, dst_offset, src_mr, src_data->data_offset, KILOBYTE, RPMA_F_COMPLETION_ALWAYS, NULL);

	/* wait for the completion to be ready */
	rpma_conn_completion_wait(conn);
	rpma_conn_completion_get(conn, &cmpl);

	if (cmpl.op != RPMA_OP_READ)
		fprintf(stderr)
	if (cmpl.op_status != IBV_WC_SUCCESS)
		fprintf(stderr, "rpma_read failed with %d\n", cmpl.op_status);

/* disconnect the connection */
rpma_conn_disconnect(conn);

/* wait for the connection to being closed */
rpma_conn_next_event(conn, &conn_event);




/* delete the connection object */
rpma_conn_delete(&conn);

	/* deregister the memory region */
	(void) rpma_mr_dereg(&mr);

/* shutdown the endpoint */
rpma_ep_shutdown(&ep);

/* delete the peer object */
rpma_peer_delete(&peer);
