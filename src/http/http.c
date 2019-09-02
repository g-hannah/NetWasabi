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
	ch->nsize = HTTP_HNAME_MAX+1;
	ch->vsize = HTTP_COOKIE_MAX+1;

	assert(ch->name);
	assert(ch->value);

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
	buf_append(&tbuf, conn->host);

	if (*(tbuf.buf_tail - 1) == '/')
		buf_snip(&tbuf, 1);

/*
 * RFC 7230:
 *
 * HTTP-message = start-line
 *                *( header-field CRLF )
 *                CRLF
 *                [ message body ]
 *
 * start-line = request-line / status-line
 *
 * request-line = method SP request-target SP HTTP-version CRLF
 *
 * Reasons that a server returns a 400 Bad Request:
 *
 * Illegal whitespace between start-line and the first header-field
 * Illegal whitespace between field-name and ":"
 * Usage of deprecated obs-fold rule
 *
 * In the case of an invalid request line, a server can either
 * send a 400 Bad Request or a 301 Moved Permanently with the
 * correct encoding present in the Location header.
 */
	sprintf(header_buf,
			"%s %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Accept: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			http_verb, target, HTTP_VERSION,
			HTTP_USER_AGENT,
			HTTP_ACCEPT,
			tbuf.buf_head,
			HTTP_EOH_SENTINEL);

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

	char *p = NULL;
	size_t clen;
	size_t header_len;
	size_t deduct;

	while (!p)
	{
		if (option_set(OPT_USE_TLS))
			buf_read_tls(conn->ssl, &conn->read_buf, 256);
		else
			buf_read_socket(conn->sock, &conn->read_buf, 256);

		p = strstr(conn->read_buf.buf_head, HTTP_EOH_SENTINEL);
	}

	p += strlen(HTTP_EOH_SENTINEL);

	http_header_t *content_len = (http_header_t *)wr_cache_alloc(http_hcache);
	assert(content_len);
	assert(wr_cache_obj_used(http_hcache, (void *)content_len));

	if (http_fetch_header(&conn->read_buf, "Content-Length", content_len, (off_t)0))
	{
		clen = strtoul(content_len->value, NULL, 0);
		header_len = (p - conn->read_buf.buf_head);
		deduct = (conn->read_buf.data_len - header_len);

		clen -= deduct;
	}
	else
	{
		clen = 0;
	}

	if (option_set(OPT_USE_TLS))
		buf_read_tls(conn->ssl, &conn->read_buf, clen);
	else
		buf_read_socket(conn->sock, &conn->read_buf, clen);

	wr_cache_dealloc(http_hcache, content_len);

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
		case HTTP_REQUEST_TIMEOUT:
			return "Request timeout";
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

#if 0
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
#endif

ssize_t
http_response_header_len(buf_t *buf)
{
	assert(buf);

	char	*p = buf->data;
	char	*q = NULL;

	if (!buf_integrity(buf))
		return -1;

	q = strstr(p, HTTP_EOH_SENTINEL);

	if (!q)
		return -1;

	q += strlen(HTTP_EOH_SENTINEL);

	return (q - p);
}

char *
http_parse_host(char *url, char *host)
{
	char *p = url;
	//char *q;
	size_t url_len = strlen(url);
	char *endp = (url + url_len);

	p = url;

	if (!strncmp("http:", url, strlen("http:")))
		p += strlen("http://");
	else
	if (!strncmp("https:", url, strlen("https:")))
		p += strlen("https://");

	endp = memchr(p, '/', ((url + url_len) - p));
	if (!endp)
		endp = url + url_len;

	strncpy(host, p, endp - p);
	host[endp - p] = 0;

	return host;
}

char *
http_parse_page(char *url, char *page)
{
	char *p;
	char *q;
	size_t url_len = strlen(url);
	char *endp = (url + url_len);

	p = url;
	q = endp;

	if (*(endp - 1) == '/')
	{
		--endp;
		*endp = 0;
	}

	if (!strncmp("http:", url, 5))
		p += strlen("http://");
	else
	if (!strncmp("https:", url, 6))
		p += strlen("https://");

	q = memchr(p, '/', (endp - p));

	if (!q)
	{
		strncpy(page, "/", 1);
		page[1] = 0;
		return page;
	}

	strncpy(page, q, (endp - q));
	page[endp - q] = 0;

	return page;
}

/**
 * http_check_header - check existence of header
 * @buf: buffer containing header
 * @name: name of the header
 * @off: the offset from within the header to start search
 * @ret_off: offset where header found returned here
 */
int
http_check_header(buf_t *buf, const char *name, off_t off, off_t *ret_off)
{
	assert(buf);
	assert(name);

	char *check_from = buf->buf_head + off;
	char *p;

	if ((p = strstr(check_from, name)))
	{
		*ret_off = (off_t)(p - buf->buf_head);
		return 1;
	}
	else
	{
		return 0;
	}
}

/**
 * http_get_header - find and return a line in an HTTP header
 * @buf: the buffer containing the HTTP header
 * @name: the name of the header (e.g., "Set-Cookie")
 */
char *
http_fetch_header(buf_t *buf, const char *name, http_header_t *hh, off_t whence)
{
	assert(buf);
	assert(name);
	assert(hh);
	assert(hh->name);
	assert(hh->value);

	char *check_from = buf->buf_head + whence;
	char *tail = buf->buf_tail;
	char *p;
	char *q;
	char *hend;

	p = strstr(check_from, name);

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

	if (!strncmp("Set-Cookie", p, q - p))
	{
		size_t _nlen = strlen("Cookie");
		strncpy(hh->name, "Cookie", _nlen);
		hh->name[_nlen] = 0;
		hh->nlen = _nlen;;
	}
	else
	{
		strncpy(hh->name, p, (q - p));
		hh->name[q - p] = 0;
		hh->nlen = (q - p);
	}

	p = (q + 2);
	if (*(p-1) != ' ')
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

	//fail:
	return NULL;
}

int
http_append_header(buf_t *buf, http_header_t *hh)
{
	assert(buf);
	assert(hh);

	char *p;
	char *head = buf->buf_head;

	p = strstr(head, HTTP_EOH_SENTINEL);

	if (!p)
	{
		fprintf(stderr,
				"http_append_header: failed to find end of header sentinel\n");
		errno = EPROTO;
		return -1;
	}

	p += 2;

	buf_t tmp;

	buf_init(&tmp, HTTP_COOKIE_MAX+strlen("Cookie: "));
	buf_append(&tmp, hh->name);
	buf_append(&tmp, ": ");
	buf_append(&tmp, hh->value);
	buf_append(&tmp, "\r\n");

	buf_shift(buf, (off_t)(p - head), tmp.data_len);

	strncpy(p, tmp.buf_head, tmp.data_len);

	buf_destroy(&tmp);

	return 0;
}

int
http_parse_header(buf_t *buf, wr_cache_t *cachep)
{
	assert(buf);
	assert(cachep);

	http_header_t *hp;
	char *p;
	char *savep;
	char *line;
	char *tail = buf->buf_tail;
	char *head = buf->buf_head;
	size_t len;

	p = head;

	while (p < tail)
	{
		savep = p;

		line = memchr(savep, 0x0d, tail - savep);

		if (!line)
			break;

		p = memchr(savep, ':', line - savep);

		if (!p)
			break;

		hp = (http_header_t *)wr_cache_alloc(cachep);
		assert(wr_cache_obj_used(cachep, (void *)hp));

		len = (p - savep);
		strncpy(hp->name, savep, len);
		hp->name[len] = 0;
		hp->nlen = len;

		++p;

		while ((*p == ' ' || *p == '\t') && p < tail)
			++p;

		if (p == tail)
			break;

		savep = p;

		len = (line - p);
		strncpy(hp->value, p, len);
		hp->value[len] = 0;
		hp->vlen = len;

		while ((*p == 0x0a || *p == 0x0d) && p < tail)
			++p;

		if (p == tail)
			break;
	}

	return 0;
}

#if 0
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
#endif
