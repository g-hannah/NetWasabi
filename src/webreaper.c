#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "buffer.h"
#include "http.h"
#include "misc.h"
#include "webreaper.h"

int
do_request(struct http_t *http)
{
	assert(http);

	int status_code = 0;
	int rv;

	/*
	 * Save bandwidth: send HEAD first.
	 */
	resend_head:
	status_code = http_send_request(http, HTTP_HEAD);

	update_status_code(status_code);

	if (HTTP_OK != status_code)
		return status_code;

	if (local_archive_already_exists(http->full_url))
		return HTTP_ALREADY_EXISTS;

	if (http_connection_closed(http))
	{
		//fprintf(stdout, "%s%sRemote peer closed connection%s\n", COL_RED, ACTION_DONE_STR, COL_END);
		//__show_response_header(&http_rbuf(http));
		update_operation_status("Remote peer closed connection");
		http_reconnect(http);
	}

	status_code &= ~status_code;
	status_code = http_send_request(http, HTTP_GET);

	update_status_code(status_code);

	return status_code;
}
