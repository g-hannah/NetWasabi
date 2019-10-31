#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "buffer.h"
#include "connection.h"
#include "http.h"
#include "webreaper.h"

int
send_head_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	update_operation_status("Sending HEAD request to server");

	check_host(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"HEAD %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			conn->full_url, HTTP_VERSION,
			HTTP_USER_AGENT,
			conn->host,
			HTTP_EOH_SENTINEL);

	buf_append(wbuf, tmp_cbuf);

	check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	status_code = http_status_code_int(rbuf);

	return status_code;

	fail_free_bufs:
	if (tmp_cbuf)
	{
		free(tmp_cbuf);
		tmp_cbuf = NULL;
	}

	fail:
	return rv;
}

int
send_get_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	update_operation_status("Sending GET request to server");

	check_host(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			conn->full_url, HTTP_VERSION,
			HTTP_USER_AGENT,
			conn->host,
			HTTP_EOH_SENTINEL);

	buf_append(wbuf, tmp_cbuf);

	check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	status_code = http_status_code_int(rbuf);

	return status_code;

	fail_free_bufs:
	if (tmp_cbuf)
	{
		free(tmp_cbuf);
		tmp_cbuf = NULL;
	}

	fail:
	return rv;
}

int
do_request(connection_t *conn)
{
	assert(conn);

	int status_code = 0;
	int rv;

	/*
	 * Save bandwidth: send HEAD first.
	 */
	resend_head:
	status_code = send_head_request(conn);

	update_status_code(status_code);

	switch(status_code)
	{
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_FOUND:
		case HTTP_SEE_OTHER:
			rv = __handle301(conn);

			if (HTTP_IS_XDOMAIN == (unsigned int)rv)
				return rv;
			else
			if (rv < 0)
				return -1;
/*
 * Check here too because 301 may send different
 * spelling (upper-case vs lower-case... etc)
 */
			if (local_archive_exists(conn->full_url))
				return HTTP_ALREADY_EXISTS;
			goto resend_head;
			break;
		case HTTP_OK:
			break;
		default:
			return status_code;
	}

	if (connection_closed(conn))
	{
		//fprintf(stdout, "%s%sRemote peer closed connection%s\n", COL_RED, ACTION_DONE_STR, COL_END);
		//__show_response_header(&conn->read_buf);
		update_operation_status("Remove peer closed connection");
		reconnect(conn);
	}

	status_code &= ~status_code;
	status_code = send_get_request(conn);

	update_status_code(status_code);

	return status_code;
}
