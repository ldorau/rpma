/* obtain an IBV context for a local IP address */
rpma_utils_get_ibv_context(addr, RPMA_UTIL_IBV_CONTEXT_LOCAL, &dev);

/* create a new peer object */
rpma_peer_new(dev, &peer);

/* create a new endpoint object */
rpma_ep_listen(peer, addr, port, &ep);

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

/* here you can use the newly established connection */
rpma_conn_get_private_data(conn, &pdata);

/* disconnect the connection */
rpma_conn_disconnect(conn);

/* wait for the connection to being closed */
rpma_conn_next_event(conn, &conn_event);




/* delete the connection object */
rpma_conn_delete(&conn);

/* shutdown the endpoint */
rpma_ep_shutdown(&ep);

/* delete the peer object */
rpma_peer_delete(&peer);
