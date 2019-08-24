#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"

wr_cache_ctor_type wr_cache_http_link_ctor
{
	http_link_t *http_link = (http_link_t *)cptr;
	http_link->url = calloc(HTTP_URL_MAX, 1);

	memset(http_link->url, 0, HTTP_URL_MAX);
}

int
http_status_code_int(buf_t *buf)
{
	assert(buf);

	char *p = buf->data;
	char *q = NULL;
	char *tail = buf->buf_tail;
	char *head = buf->buf_head;
	static char code_str[16];
	size_t data_len = buf->data_len;

	/*
	 * HTTP/1.1 200 OK\r\n
	 */

	if (!buf_integrity(buf))
		return -1;

	p = memchr(head, 0x20, (tail - head));
	if (!p)
		return -1;

	++p;

	q = memchr(p, 0x20, (tail - p));
	if (!q)
		return -1;

	strncpy(code_str, p, (q - p));
	code_str[q - p] = 0;

	return atoi(code_str);
}

void
http_status_code_string(int code)
{
	switch(code)
	{
		case HTTP_OK:
			return "OK";
			break;
		case HTTP_MOVED_PERMANENTLY:
			return "Moved permanently";
			break;
		case HTTP_FOUND:
			return "Found";
			break;
		case HTTP_SEE_OTHER:
			return "See other";
			break;
		case HTTP_BAD_REQUEST:
			return "Bad request";
			break;
		case HTTP_UNAUTHORISED:
			return "Unauthorised";
			break;
		case HTTP_FORBIDDEN:
			return "Forbidden";
			break;
		case HTTP_NOT_FOUND:
			return "Not found";
			break;
		case HTTP_INTERNAL_ERROR:
			return "Internal server error";
			break;
		case HTTP_BAD_GATEWAY:
			return "Bad gateway";
			break;
		case HTTP_SERVICE_UNAV:
			return "Service unavailable";
			break;
		default:
			return "Unknown http status code";
	}
}

int
http_set_cookies(buf_t *buf, http_state_t *http_state)
{
	assert(buf);

	char	*p = buf->data;
	char	*q = NULL;
	char	*tail = buf->tail;
	size_t	cookie_len;
	char	**cookies = NULL;
	int nrcookies;

	if (!buf_integrity(buf))
		return -1;

	while ((q = strstr(p, "Set-Cookie")))
	{
		q += strlen("Set-Cookie");
		p = q;
		q = memchr(p, 0x0d, (tail - p));
		if (!q)
			return -1;

		cookie_len = (q - p);

		cookies = http_state->http_cookies;
		nrcookies = http_nr_cookies(http_state);

		if (!http_nr_cookies(http_state))
		{
			cookies = wr_calloc(1, sizeof(char *));
			if (!cookies)	
				return -1;

			cookies[nrcookies] = wr_calloc(cookie_len+1, 1);
			strncpy(cookies[nrcookies], p, cookie_len);
			cookies[nrcookies][cookie_len] = 0;
			http_inc_cookies(http_state);
		}
		else
		{
			cookies = wr_realloc(cookies, ((nrcookies + 1) * sizeof(char *)));
			if (!cookies)
				return -1;

			cookies[nrcookies] = wr_calloc(cookie_len+1, 1);
			strncpy(cookies[nrcookies], p, cookie_len);
			cookies[nrcookies][cookie_len] = 0;
			http_inc_cookies(http_state);
		}
	}
}

int
http_response_header(buf_t *buf)
{
	assert(buf);

	char	*p = buf->data;
	char	*q = NULL;

	if (!buf_integrity(buf))
		return -1;

	q = strstr(p, "\r\n\r\n");

	if (!q)
		return -1;
}
