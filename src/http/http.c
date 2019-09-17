#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "connection.h"
#include "http.h"
#include "malloc.h"
#include "webreaper.h"

struct http_vars
{
	size_t header_len;
	size_t content_len;
	int is_chunked;
};

/**
 * wr_cache_http_cookie_ctor - initialise object for the cookie cache
 * @hh: pointer to the object in the cache
 *  -- called in wr_cache_create()
 */
int
wr_cache_http_header_ctor(void *hh)
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
wr_cache_http_header_dtor(void *hh)
{
	assert(hh);

	http_header_t *ch = (http_header_t *)hh;

	memset(ch->name, 0, ch->nlen);
	memset(ch->value, 0, ch->vlen);

	ch->nlen = ch->vlen = 0;
}

#define TIME_STRING_MAX 64

int
http_cookie_ctor(void *cookie)
{
	struct http_cookie_t *c = (struct http_cookie_t *)cookie;
	clear_struct(c);

	if (!(c->data = wr_calloc(HTTP_COOKIE_MAX+1, 1)))
		goto fail;

	if (!(c->domain = wr_calloc(HTTP_URL_MAX+1, 1)))
		goto fail;

	if (!(c->path = wr_calloc(HTTP_URL_MAX+1, 1)))
		goto fail;

	if (!(c->expires = wr_calloc(TIME_STRING_MAX+1, 1)))
		goto fail;

	c->data_len = 0;
	c->domain_len = 0;
	c->path_len = 0;
	c->expires_len = 0;
	c->expires_ts = 0;

	return 0;

	fail:
	return -1;
}

void
http_cookie_dtor(void *cookie)
{
	struct http_cookie_t *c = (struct http_cookie_t *)cookie;

	if (c->data)
		free(c->data);

	if (c->domain)
		free(c->domain);

	if (c->path)
		free(c->path);

	if (c->expires)
		free(c->expires);

	clear_struct(c);

	return;
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
	buf_t tmp;
	static char header_buf[4096];

	buf_init(&tmp, HTTP_URL_MAX);

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

	if (!strcmp("HEAD", http_verb))
	{
		buf_append(&tmp, "https://");
		buf_append(&tmp, conn->host);
		buf_append(&tmp, conn->page);

		sprintf(header_buf,
			"HEAD %s HTTP/%s\r\n"
			"Host: %s\r\n"
			"User-Agent: %s%s",
			tmp.buf_head, HTTP_VERSION,
			conn->host,
			HTTP_USER_AGENT, HTTP_EOH_SENTINEL);
	}
	else
	{
		buf_append(&tmp, conn->host);

		if (*(tmp.buf_tail - 1) == '/')
			buf_snip(&tmp, 1);

		sprintf(header_buf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Accept: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			target, HTTP_VERSION,
			HTTP_USER_AGENT,
			HTTP_ACCEPT,
			tmp.buf_head,
			HTTP_EOH_SENTINEL);
	}

	buf_append(buf, header_buf);
	buf_destroy(&tmp);

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
		{
			fprintf(stderr, "http_send_request: failed to write to SSL socket (%s)\n", strerror(errno));
			goto fail;
		}
	}
	else
	{
		if (buf_write_socket(conn_socket(conn), buf) == -1)
		{
			fprintf(stderr, "http_send_request: failed to write to socket (%s)\n", strerror(errno));
			goto fail;
		}
	}

	return 0;

	fail:
	return -1;
}

#define HTTP_SMALL_READ_BLOCK 256

static char *
__http_read_until_eoh(connection_t *conn)
{
	assert(conn);

	ssize_t n;
	char *p = NULL;
	buf_t *buf = &conn->read_buf;

	while (!p)
	{
		if (option_set(OPT_USE_TLS))
			n = buf_read_tls(conn->ssl, buf, HTTP_SMALL_READ_BLOCK);
		else
			n = buf_read_socket(conn->sock, buf, HTTP_SMALL_READ_BLOCK);

		if (!n)
			continue;
		else
		if (n < 0)
			return NULL;
		else
			p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);
	}

	return p;
}

#ifdef DEBUG
static void
__dump_buf(buf_t *buf)
{
	assert(buf);

	int fd = -1;

	fd = open("./DUMPED_BUF.LOG", O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	
	if (fd != -1)
	{
		buf_write_fd(fd, buf);
		sync();
		close(fd);
		fd = -1;
	}

	return;
}
#endif

static size_t
__http_do_chunked_recv(connection_t *conn)
{
	assert(conn);

#define HTTP_MAX_CHUNK_STR 20

	char *p;
	char *e;
	char *t;
	char *chunk_start;
	char *__next_size;
	off_t chunk_offset;
	buf_t *buf = &conn->read_buf;
	size_t chunk_size;
	size_t save_size;
	size_t overread;
	size_t total;
	ssize_t bytes_read;
	static char tmp[HTTP_MAX_CHUNK_STR];

	p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);

	if (!p)
	{
		fprintf(stderr, "__http_do_chunked_recv: failed to find end of header sentinel\n");
		return -1;
	}

	p += strlen(HTTP_EOH_SENTINEL);

	t = p;
	SKIP_CRNL(p);

	if (p - t)
	{
		buf_collapse(buf, (off_t)(t - buf->buf_head), (p - t));
		p = t;
	}

	while (1)
	{
		e = memchr(p, 0x0d, HTTP_MAX_CHUNK_STR);

		if (!e)
		{
			fprintf(stderr, "__http_do_chunked_recv: failed to find next carriage return\n");

#ifdef DEBUG
			int i;

			__dump_buf(buf);

			p -= 32;

			for (i = 0; i < 64; ++i)
				fprintf(stderr, "%02hhx ", p[i]);

			putchar(0x0a);

			fprintf(stderr, "%.*s\n", (int)64, p);

			fprintf(stderr,
					"BUF_SIZE=%lu bytes\n"
					"END - DATA = %lu bytes\n"
					"TAIL - HEAD = %lu bytes\n"
					"HEAD @ %p\n"
					"TAIL @ %p\n"
					"END @ %p\n",
					buf->buf_size,
					(buf->buf_end - buf->data),
					(buf->buf_tail - buf->buf_head),
					buf->buf_head,
					buf->buf_tail,
					buf->buf_end);
#endif

			return -1;
		}

		strncpy(tmp, p, (e - p));
		tmp[e - p] = 0;

		chunk_size = strtoul(tmp, NULL, 16);

#ifdef DEBUG
		fprintf(stderr, "%sCHUNK SIZE=%lu BYTES%s\n", COL_ORANGE, chunk_size, COL_END);
#endif

		if (!chunk_size)
		{
			--p;
			buf_collapse(buf, (off_t)(p - buf->buf_head), (buf->buf_tail - p));
			break;
		}

		save_size = chunk_size;

		SKIP_CRNL(e);

		buf_collapse(buf, (off_t)(p - buf->buf_head), (e - p));
		e = p;

		chunk_start = e;

		overread = (buf->buf_tail - e);

		if (overread >= chunk_size)
		{
			p = (e + save_size);

			t = p;
			SKIP_CRNL(p);

			if (p - t)
			{
				buf_collapse(buf, (off_t)(t - buf->buf_head), (p - t));
				p = t;
			}

			continue;
		}
		else
		{
			chunk_size -= overread;
		}

		total = 0;

/*
 * Our buffer data could be copied to a new location
 * on the heap with a realloc in buf_extend(). So
 * save the offset of chunk_start from start of buffer.
 * Restore pointer after receiving data.
 */
		chunk_offset = (chunk_start - buf->buf_head);

		while (1)
		{
			if (total >= chunk_size)
				break;

			if (option_set(OPT_USE_TLS))
				bytes_read = buf_read_tls(conn->ssl, buf, chunk_size);
			else
				bytes_read = buf_read_socket(conn->sock, buf, chunk_size);

			if (bytes_read < 0)
				return -1;
			else
			if (!bytes_read)
				continue;
			else
				total += bytes_read;
		}


		/*
		 * Read some extra data to get next chunk size.
		 */
		total = 0;

		/*
		 * Point at where next size string will be.
		 */
		__next_size = (buf->buf_head + chunk_offset + save_size + 2);

		while (1)
		{
			if (option_set(OPT_USE_TLS))
				bytes_read = buf_read_tls(conn->ssl, buf, (HTTP_MAX_CHUNK_STR - total));
			else
				bytes_read = buf_read_socket(conn->sock, buf, (HTTP_MAX_CHUNK_STR - total));

			if (bytes_read < 0)
				return -1;
			else
			if (!bytes_read)
				continue;
			else
			{
				total += (size_t)bytes_read;

				__next_size = (buf->buf_head + chunk_offset + save_size + 2);

				assert(*(__next_size - 2) == '\r');
					
				if (!memchr(__next_size, '\r', 64))
					continue;
				else
				{

					assert(*__next_size != '\r');
					assert(*(__next_size - 2) == '\r');

					char *crnl = memchr(__next_size, '\r', 64);

					if (!crnl)
					{
						continue;
					}

					assert(*crnl == 0x0d);
					assert(__next_size != crnl);
					assert(crnl > __next_size);
					break;
				}
			}
		}

		chunk_start = (buf->buf_head + chunk_offset);

		p = (chunk_start + save_size);

		t = p;
		SKIP_CRNL(p);

		if (p - t)
		{
			buf_collapse(buf, (off_t)(t - buf->buf_head), (p - t));
			p = t;
		}
	}

	return 0;
}

/**
 * http_recv_response - receive HTTP response.
 * @conn: connection context
 */
int
http_recv_response(connection_t *conn)
{
	assert(conn);

	char *p = NULL;
	size_t clen;
	size_t overread;
	ssize_t bytes;
	http_header_t *content_len = NULL;
	http_header_t *transfer_enc = NULL;
	buf_t *buf = &conn->read_buf;

	content_len = (http_header_t *)wr_cache_alloc(http_hcache);
	transfer_enc = (http_header_t *)wr_cache_alloc(http_hcache);

	if (!content_len || !transfer_enc)
		goto fail;

	p = __http_read_until_eoh(conn);

	if (!p)
	{
		fprintf(stderr, "http_recv_response: failed to find end of header sentinel\n");
		goto out_dealloc;
	}

	p += strlen(HTTP_EOH_SENTINEL);

	if (strstr(conn->write_buf.buf_head, "HEAD"))
	{
		buf_collapse(&conn->read_buf, (off_t)(p - conn->read_buf.buf_head), (conn->read_buf.buf_tail - p));
		return 0;
	}

	if (http_fetch_header(&conn->read_buf, "Transfer-Encoding", transfer_enc, (off_t)0))
	{
		if (!strncmp("chunked", transfer_enc->value, transfer_enc->vlen))
		{
#ifdef DEBUG
			printf("Transfer-Encoding = chunked\n");
#endif
			if (__http_do_chunked_recv(conn) == -1)
				goto out_dealloc;
		}
	}
	else
	if (http_fetch_header(buf, "Content-Length", content_len, (off_t)0))
	{
		clen = strtoul(content_len->value, NULL, 0);

		overread = (buf->buf_tail - p);

		if (overread < clen)
		{
			clen -= overread;

			while (clen)
			{
				if (option_set(OPT_USE_TLS))
					bytes = buf_read_tls(conn->ssl, buf, clen);
				else
					bytes = buf_read_socket(conn->sock, buf, clen);

				if (bytes < 0)
					goto out_dealloc;
				else
				if (!bytes)
					continue;	
				else
					clen -= bytes;
			}
		}
	}
	else
	{
		clen = 0;

		read_again:

		bytes = 0;
		p = NULL;

		if (option_set(OPT_USE_TLS))
			bytes = buf_read_tls(conn->ssl, &conn->read_buf, clen);
		else
			bytes = buf_read_socket(conn->sock, &conn->read_buf, clen);

		if (bytes < 0)
			goto out_dealloc;

		p = strstr(conn->read_buf.buf_head, "</body");

		if (!p)
		{
			goto read_again;
		}
	}

	assert(conn->read_buf.magic == BUFFER_MAGIC);
	wr_cache_dealloc(http_hcache, (void *)content_len);
	wr_cache_dealloc(http_hcache, (void *)transfer_enc);

	return 0;

	out_dealloc:
	wr_cache_dealloc(http_hcache, (void *)content_len);
	wr_cache_dealloc(http_hcache, (void *)transfer_enc);

	fail:
	return -1;
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
	char *p;
	size_t url_len = strlen(url);
	char *endp;

	host[0] = 0;

	p = url;

	if (!strncmp("http", url, 4))
		p += strlen("http://");

	while (*p == '/')
		++p;

	endp = memchr(p, '/', ((url + url_len) - p));

	if (!endp)
		endp = url + url_len;

	strncpy(host, p, endp - p);
	host[endp - p] = 0;

	printf("host=%s\n", host);

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

	if (!strncmp("http", url, 4))
		p += strlen("http://");

	while (*p == '/')
		++p;

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
