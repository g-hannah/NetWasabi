#include <errno.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "cache.h"
#include "connection.h"
#include "http.h"
#include "webreaper.h"


/**
 * reap - reap http links from the website to crawl
 * @hostname: the domain name of the target website
 */
int
reap(const char *hostname)
{
	connection_t conn;
	
	if (open_connection(&conn, 1) < 0)
		goto fail;

	http_send_request(&conn, HTTP_HEAD, hostname);
	http_recv_response(&conn);

	return 0;

	fail:
	return -1;
}
