#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"
#include "cache.h"
#include "connection.h"
#include "http.h"
#include "malloc.h"
#include "webreaper.h"

/**
 * wr_cache_http_cookie_ctor - initialise object for the cookie cache
 * @hh: pointer to the object in the cache
 *  -- called in wr_cache_create()
 */
int
wr_cache_http_cookie_ctor(void *hh)
{
	http_header_t *ch = (http_header_t *)hh;
	clear_struct(ch);

	ch->name = wr_calloc(HTTP_HNAME_MAX+1, 1);
	ch->value = wr_calloc(HTTP_COOKIE_MAX+1, 1);

	if (!ch->name || !ch->value)
		return -1;

	return 0;
}

/**
 * wr_cache_http_cookie_dtor - return object back to initialised state in cache
 * @hh: pointer to object in cache
 * -- called in wr_cache_dealloc()
 */
void
wr_cache_http_cookie_dtor(void *hh)
{
	assert(hh);

	http_header_t *ch = (http_header_t *)hh;

	memset(ch->name, 0, ch->nlen);
	memset(ch->value, 0, ch->vlen);

	ch->nlen = ch->vlen = 0;

	return 0;
}

int
wr_cache_http_link_ctor(void *http_link)
{
	http_link_t *hl = (http_link_t *)http_link;
	clear_struct(hl);

	hl->url = wr_calloc(HTTP_URL_MAX+1, 1);

	if (!hl->url)
		return -1;

	memset(hl->url, 0, HTTP_URL_MAX+1);
	return 0;
}

void
wr_cache_http_link_dtor(void *http_link)
{
	assert(http_link);

	http_link_t *hl = (http_link_t *)http_link;

	if (hl->url)
	{
		free(hl->url);
		hl->url = NULL;
	}

	clear_struct(hl);
	return;
}

#define USER_AGENT "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0"

int
http_build_request_header(connection_t *conn, const char *http_verb, const char *target)
{
	assert(conn);
	assert(http_verb);
	assert(target);

	buf_t *buf = &conn->write_buf;
	buf_t tbuf;
	static char header_buf[4096];

	buf_init(&tbuf, HTTP_URL_MAX);

	if (strncmp("http", conn->host, 4))
	{
		buf_append(&tbuf, "http://");
		buf_append(&tbuf, conn->host);
	}
	else
		buf_append(&tbuf, conn->host);

	if (*(tbuf.buf_tail - 1) == '/')
		buf_snip(&tbuf, 1);

	sprintf(header_buf,
			"%s %s/%s HTTP/1.1\r\n"
			"Accept: */*\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			http_verb, tbuf.buf_head, target,
			USER_AGENT,
			tbuf.buf_head);

	buf_append(buf, header_buf);

	buf_destroy(&tbuf);

	return 0;
}

int
http_send_request(connection_t *conn)
{
	assert(conn);

	buf_t *buf = &conn->write_buf;

	if (conn_using_tls(conn))
	{
		if (buf_write_tls(conn_tls(conn), buf) == -1)
			goto fail;
	}
	else
	{
		if (buf_write_socket(conn_socket(conn), buf) == -1)
			goto fail;
	}

	return 0;

	fail:
	return -1;
}

int
http_recv_response(connection_t *conn)
{
	assert(conn);

	if (conn_using_tls(conn))
		buf_read_tls(conn->ssl, &conn->read_buf);
	else
		buf_read_socket(conn->sock, &conn->read_buf);

	return 0;
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
	//size_t data_len = buf->data_len;

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

const char *
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
	char	*tail = buf->buf_tail;
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

	return 0;
}

ssize_t
http_response_header(buf_t *buf)
{
	assert(buf);

	char	*p = buf->data;
	char	*q = NULL;

	if (!buf_integrity(buf))
		return -1;

	q = strstr(p, HTTP_EOH_SENTINEL);

	if (!q)
		return -1;

	return (q - p);
}

char *
http_parse_host(char *url, char *host)
{
	char *p = url;
	char *q;
	size_t url_len = strlen(url);
	char *endp = (url + url_len);

	if (!strncmp("http", url, 4))
	{
		p = memchr(url, '/', url_len);
		p += 2;

		q = memchr(p, '/', endp - p);

		if (!q)
			q = endp;

		strncpy(host, p, (q - p));
		host[q - p] = 0;
	}
	else
	{
		q = memchr(p, '/', endp - p);

		if (!q)
			q = endp;

		strncpy(host, p, q - p);
		host[q - p] = 0;
	}

	return host;
}

char *
http_parse_page(char *url, char *page)
{
	char *q;
	size_t url_len = strlen(url);
	char *endp = (url + url_len);

	q = endp;

	while (*q != 0x2f && q > (url + 1))
		--q;

	if (q == url)
		return NULL;
	else
	if (q == endp)
		return NULL;

	++q;

	strncpy(page, q, (endp - q));
	page[endp - q] = 0;

	return page;
}

int
http_check_header(buf_t *buf, const char *name)
{
	assert(buf);
	assert(name);

	if (strstr(buf, name))
		return 1;
	else
		return 0;
}

/**
 * http_get_header - find and return a line in an HTTP header
 * @buf: the buffer containing the HTTP header
 * @name: the name of the header (e.g., "Set-Cookie")
 */
char *
http_get_header(buf_t *buf, const char *name, http_header_t *hh, off_t whence, off_t *ret_off)
{
	assert(buf);
	assert(name);
	assert(hh);
	assert(ret_off);

	off_t whence = whence;
	size_t nlen;
	size_t vlen;
	char *check_from = buf->buf_head + whence;
	char *tail = buf->buf_tail;
	char *p;
	char *q;
	char *hend;

	p = strstr(check_from, name);

	*ret_off = (off_t)(p - buf->buf_head);

	if (!p)
		return NULL;

	hend = strstr(check_from, HTTP_EOH_SENTINEL);
	if (!hend)
	{
		fprintf(stderr,
				"http_get_header: failed to find end of header sentinel\n");
		errno = EPROTO;
		goto out_clear_ret;
	}

	q = memchr(p, ':', (tail - p));
	if (!q)
		return NULL;

	strncpy(hh->name, p, (q - p));
	hh->name[q - p] = 0;
	hh->nlen = (q - p);

	p = (q + 2);
	if (*(p-1) != 0x20)
		--p;

	q = memchr(p, 0x0d, (tail - p));
	if (!q)
		goto out_clear_ret;

	strncpy(hh->value, p, (q - p));
	hh->value[q - p] = 0;
	hh->vlen = (q - p);

	return hh->value;

	out_clear_ret:
	memset(hh->name, 0, hh->nsize);
	memset(hh->value, 0, hh->vsize);
	hh->nlen = 0;
	hh->vlen = 0;

	fail:
	return NULL;
}

int
http_append_header(buf_t *buf, const char *header)
{
	assert(buf);
	assert(header);

	char *p;
	char *head = buf->buf_head;
	size_t header_len = strlen(header);

	p = strstr(head, HTTP_EOH_SENTINEL);

	if (!p)
	{
		fprintf(stderr,
				"http_append_header: failed to find end of header sentinel\n");
		errno = EPROTO;
		return -1;
	}

	p += 2;

	buf_shift(buf, (off_t)(p - head), header_len);
	strncpy(p, header, header_len);

	return 0;
}

int
http_state_add_cookies(http_state_t *state, char *cookies)
{
	assert(state);

	int i;
	int nr_cookies = state->nr_cookies;

	if (nr_cookies)
	{
		for (i = 0; i < nr_cookies; ++i)
			free(state->cookies[i]);

		free(state->cookies);
	}
}
