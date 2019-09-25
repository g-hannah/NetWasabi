#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
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

static struct sigaction oact;
static struct sigaction nact;
static sigjmp_buf TIMEOUT;

static void
__http_handle_timeout(int signo)
{
	siglongjmp(TIMEOUT, 1);
}

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

	if (!(ch->name = wr_calloc(HTTP_HNAME_MAX+1, 1)))
		goto fail;

	if (!(ch->value = wr_calloc(HTTP_COOKIE_MAX+1, 1)))
		goto fail;

	ch->nsize = HTTP_HNAME_MAX+1;
	ch->vsize = HTTP_COOKIE_MAX+1;

	assert(ch->name);
	assert(ch->value);

	return 0;

	fail:
	return -1;
}

/**
 * wr_cache_http_cookie_dtor - free memory in http_header_t cache object
 * @hh: pointer to object in cache
 */
void
wr_cache_http_header_dtor(void *hh)
{
	assert(hh);

	http_header_t *ch = (http_header_t *)hh;

	if (ch->name)
		free(ch->name);
	if (ch->value)
		free(ch->value);

	clear_struct(ch);

	return;
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

	hl->left = NULL;
	hl->right = NULL;

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

	if (option_set(OPT_USE_TLS))
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
#define MAX_WAIT_TIME 12

static int
__http_read_until_eoh(connection_t *conn, char **p)
{
	assert(conn);

	ssize_t n;
	buf_t *buf = &conn->read_buf;

	clear_struct(&oact);
	clear_struct(&nact);
	nact.sa_flags = 0;
	nact.sa_handler = __http_handle_timeout;
	sigemptyset(&nact.sa_mask);

	if (sigaction(SIGALRM, &nact, &oact) < 0)
	{
		fprintf(stderr, "__http_read_until_eoh: failed to set signal handler for SIGALRM\n");
		return -1;
	}

	if (sigsetjmp(TIMEOUT, 1) != 0)
	{
		fprintf(stderr, "%s%sTimed out waiting for HTTP response from server%s\n", COL_RED, ACTION_DONE_STR, COL_END);
		sigaction(SIGALRM, &oact, NULL);
		return FL_OPERATION_TIMEOUT;
	}

	alarm(MAX_WAIT_TIME);
	while (!(*p))
	{
		if (option_set(OPT_USE_TLS))
			n = buf_read_tls(conn->ssl, buf, HTTP_SMALL_READ_BLOCK);
		else
			n = buf_read_socket(conn->sock, buf, HTTP_SMALL_READ_BLOCK);

		if (n == -1)
			return -1;

		switch(n)
		{
			case 0:
				continue;
				break;
			default:
				*p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);
				//fprintf(stderr, "*p == %p\n", *p);
				if (*p)
					goto out;
		}
	}

	out:
	alarm(0);

	assert(!strncmp(HTTP_EOH_SENTINEL, *p, strlen(HTTP_EOH_SENTINEL)));
	*p += strlen(HTTP_EOH_SENTINEL);

	sigaction(SIGALRM, &oact, NULL);
	return 0;
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

static ssize_t
__read_bytes(connection_t *conn, size_t toread)
{
	assert(conn);
	assert(toread > 0);

	ssize_t n;
	SSL *ssl = conn->ssl;
	int sock = conn->sock;
	size_t r = toread;
	buf_t *buf = &conn->read_buf;

	while (r)
	{
		if (option_set(OPT_USE_TLS))
			n = buf_read_tls(ssl, buf, r);
		else
			n = buf_read_socket(sock, buf, r);

		if (n < 0)
			return -1;
		else
		if (!n)
			continue;
		else
			r -= n;
	}

	return toread;
}

#define HTTP_MAX_CHUNK_STR 10

static void
__http_read_until_next_chunk_size(connection_t *conn, buf_t *buf, char **cur_pos)
{
	assert(conn);
	assert(buf);
	assert(cur_pos);
	assert(buf_integrity(buf));

	off_t cur_pos_off = (*cur_pos - buf->buf_head);
	char *q;
	char *tail = buf->buf_tail;

	if (*cur_pos < tail)
	{
		if (**cur_pos == 0x0d)
		{
			while ((**cur_pos == 0x0d || **cur_pos == 0x0a) && *cur_pos < tail)
				++(*cur_pos);

			if (*cur_pos != tail)
			{
				q = *cur_pos;

				while (*q != 0x0d && q < tail)
					++q;

				if (q != tail)
				{
					*cur_pos -= 2;
					return;
				}
			}
		}
	}

	__read_bytes(conn, 2);
	*cur_pos = (buf->buf_head + cur_pos_off);
	tail = buf->buf_tail;
	*cur_pos += 2;
	cur_pos_off += 2;

	while (1)
	{
		__read_bytes(conn, 1);
		tail = buf->buf_tail;
		*cur_pos = (buf->buf_head + cur_pos_off);
		q = memchr(*cur_pos, 0x0a, (tail - *cur_pos));
		if (q)
		{
			*cur_pos -= 2; /* point it back to START_OF_CHUNK_DATA + CHUNK_SIZE */
			break;
		}
	}

	return;
}

static size_t
__http_do_chunked_recv(connection_t *conn)
{
	assert(conn);

	char *p;
	char *e;
	off_t chunk_offset;
	buf_t *buf = &conn->read_buf;
	size_t chunk_size;
	size_t save_size;
	size_t overread;
	size_t range;
	char *t;
	static char tmp[HTTP_MAX_CHUNK_STR];
#ifdef DEBUG
	int chunk_nr = 0;
#endif

	p = HTTP_EOH(buf);

	while (!p)
	{
		__read_bytes(conn, 1);
		p = HTTP_EOH(buf);
	}

	if (!p)
	{
		fprintf(stderr, "__http_do_chunked_recv: failed to find end of header sentinel\n");
		return -1;
	}

	__http_read_until_next_chunk_size(conn, buf, &p);

	while (1)
	{
		t = p;
		SKIP_CRNL(p);

		range = (p - t);
		if (range)
		{
			buf_collapse(buf, (off_t)(t - buf->buf_head), range);
			p = t;
		}

#ifdef DEBUG
		++chunk_nr;
		fprintf(stderr, "Chunk #%d\n", chunk_nr);
		SKIP_CRNL(p);
#endif

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

		e += 2; /* Skip the \r\n do NOT use SKIP_CRNL(); chunk data could start with these bytes */

		buf_collapse(buf, (off_t)(p - buf->buf_head), (e - p));
		e = p;

		chunk_offset = (e - buf->buf_head);

		overread = (buf->buf_tail - e);

		if (overread >= chunk_size)
		{
			p = (e + save_size);
			__http_read_until_next_chunk_size(conn, buf, &p);
		}
		else
		{
			chunk_size -= overread;
		}

		__read_bytes(conn, chunk_size);

		p = (buf->buf_head + chunk_offset + save_size);
		__http_read_until_next_chunk_size(conn, buf, &p);

#if 0
/*
 * BS=BUF_START ; CS=CHUNK_START ; CE=CHUNK_END ; b=byte
 *
 * |BSbbbbbbbbbbCSbbbbbbbbbbbbbbbbbbbbbbbbbCE\r\n5a8\r\n......
 *                                               ^
 *                                             __next_size
 * This is absolutey where __next_size should be pointing after
 * the below... Something is very wrong if the assertions fail.
 *
 * EDIT:
 * Assertion *(__next_size - 2) == '\r' was failing in a certain
 * case after the final chunk, jumping forward from buf_head
 * chunk_offset + save_size + 2, was pointing ONE byte past the
 * 30 byte: 0d0a0d0a300d0a
 *                    ^
 * To solve this, don't jump forward the extra 2 bytes, and then
 * use SKIP_CRNL to land on the start of the next size string.
 *
 */
#endif
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
	int rv;
	http_header_t *content_len = NULL;
	http_header_t *transfer_enc = NULL;
	buf_t *buf = &conn->read_buf;

	content_len = (http_header_t *)wr_cache_alloc(http_hcache, &content_len);

	if (!content_len)
		goto fail;

	transfer_enc = (http_header_t *)wr_cache_alloc(http_hcache, &transfer_enc);

	if (!transfer_enc)
		goto fail_dealloc;

	rv = __http_read_until_eoh(conn, &p);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail_dealloc;

	if (!p)
	{
		fprintf(stderr, "http_recv_response: failed to find end of header sentinel\n");
		goto fail_dealloc;
	}

/*
 * \r\n\r\nBBBBBBB...
 *         ^
 *         p
 */

	if (strstr(conn->write_buf.buf_head, "HEAD"))
		goto out_dealloc;

	if (http_fetch_header(&conn->read_buf, "Transfer-Encoding", transfer_enc, (off_t)0))
	{
		if (!strncmp("chunked", transfer_enc->value, transfer_enc->vlen))
		{
			if (__http_do_chunked_recv(conn) == -1)
				goto fail_dealloc;

			goto out_dealloc;
		}
	}

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

				rv = bytes;

				if (rv < 0)
					goto fail_dealloc;
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
		read_again:

		bytes = 0;
		p = NULL;

		if (option_set(OPT_USE_TLS))
			bytes = buf_read_tls(conn->ssl, buf, 0);
		else
			bytes = buf_read_socket(conn->sock, buf, 0);

		rv = bytes;

		if (rv < 0)
			goto fail_dealloc;

		p = strstr(buf->buf_head, "</body");

		if (!p)
		{
			goto read_again;
		}
	}

	out_dealloc:
	assert(conn->read_buf.magic == BUFFER_MAGIC);

	wr_cache_dealloc(http_hcache, (void *)content_len, &content_len);
	wr_cache_dealloc(http_hcache, (void *)transfer_enc, &transfer_enc);

	return 0;

	fail_dealloc:
	if (content_len)
	{
		wr_cache_dealloc(http_hcache, (void *)content_len, &content_len);
	}

	if (transfer_enc)
	{
		wr_cache_dealloc(http_hcache, (void *)transfer_enc, &transfer_enc);
	}

	fail:
	return rv;
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

	if ((q - p) >= 16)
		return -1;

	strncpy(code_str, p, (q - p));
	code_str[q - p] = 0;

	return atoi(code_str);
}

const char *
http_status_code_string(int code)
{
	static char code_string[64];

	switch((unsigned int)code)
	{
		case HTTP_OK:
			sprintf(code_string, "%s%u OK%s", COL_DARKGREEN, HTTP_OK, COL_END);
			//return "200 OK";
			break;
		case HTTP_MOVED_PERMANENTLY:
			sprintf(code_string, "%s%u Moved Permanently%s", COL_ORANGE, HTTP_MOVED_PERMANENTLY, COL_END);
			//return "301 Moved permanently";
			break;
		case HTTP_FOUND:
			sprintf(code_string, "%s%u Found%s", COL_ORANGE, HTTP_FOUND, COL_END);
			//return "302 Found";
			break;
		case HTTP_BAD_REQUEST:
			sprintf(code_string, "%s%u Bad Request%s", COL_RED, HTTP_BAD_REQUEST, COL_END);
			//return "400 Bad request";
			break;
		case HTTP_UNAUTHORISED:
			sprintf(code_string, "%s%u Unauthorised%s", COL_RED, HTTP_UNAUTHORISED, COL_END);
			//return "401 Unauthorised";
			break;
		case HTTP_FORBIDDEN:
			sprintf(code_string, "%s%u Forbidden%s", COL_RED, HTTP_FORBIDDEN, COL_END);
			return code_string;
			//return "403 Forbidden";
			break;
		case HTTP_NOT_FOUND:
			sprintf(code_string, "%s%u Not Found%s", COL_RED, HTTP_NOT_FOUND, COL_END);
			//return "404 Not found";
			break;
		case HTTP_METHOD_NOT_ALLOWED:
			sprintf(code_string, "%s%u Method Not Allowed%s", COL_RED, HTTP_METHOD_NOT_ALLOWED, COL_END);
			break;
		case HTTP_REQUEST_TIMEOUT:
			sprintf(code_string, "%s%u Request Timeout%s", COL_RED, HTTP_REQUEST_TIMEOUT, COL_END);
			//return "408 Request timeout";
			break;
		case HTTP_INTERNAL_ERROR:
			sprintf(code_string, "%s%u Internal Server Error%s", COL_RED, HTTP_INTERNAL_ERROR, COL_END);
			//return "500 Internal server error";
			break;
		case HTTP_BAD_GATEWAY:
			sprintf(code_string, "%s%u Bad Gateway%s", COL_RED, HTTP_BAD_GATEWAY, COL_END);
			//return "502 Bad gateway";
			break;
		case HTTP_SERVICE_UNAV:
			sprintf(code_string, "%s%u Service Unavailable%s", COL_RED, HTTP_SERVICE_UNAV, COL_END);
			//return "503 Service unavailable";
			break;
		case HTTP_GATEWAY_TIMEOUT:
			sprintf(code_string, "%s%u Gateway Timeout%s", COL_RED, HTTP_GATEWAY_TIMEOUT, COL_END);
			//return "504 Gateway timeout";
			break;
		case HTTP_ALREADY_EXISTS:
			sprintf(code_string, "%s%u Local Found%s", COL_DARKGREEN, HTTP_ALREADY_EXISTS, COL_END);
			//return "0xdeadbeef Local copy already exists";
			break;
		case HTTP_IS_XDOMAIN:
			sprintf(code_string, "%s%u Is XDomain%s", COL_RED, HTTP_IS_XDOMAIN, COL_END);
			break;
		default:
			sprintf(code_string, "%sUnknown HTTP Status Code (%u)%s", COL_RED, code, COL_END);
			//return "Unknown http status code";
	}

	return code_string;
}

ssize_t
http_response_header_len(buf_t *buf)
{
	assert(buf);

	char	*p;

	if (!buf_integrity(buf))
		return -1;

	p = HTTP_EOH(buf);

	return (p - buf->buf_head);
}

char *
http_parse_host(char *url, char *host)
{
	char *p;
	size_t url_len = strlen(url);
	char *endp;

	host[0] = 0;

	p = url;
	url_len = strlen(url);

	if (!strncmp("http:", url, 5) || !strncmp("https:", url, 6))
	{
		p += strlen("http://");
	}

	while (*p == '/')
		++p;

	endp = memchr(p, ':', ((url + url_len) - p));

/*
 * Sometimes, a server may send a 301 with a location header
 * that includes the port (https://website.com:443/page).
 * However, some pages (such as wiki pages), have a colon
 * in the page name (https://wiki.website.com/wiki/page_name:more_name)
 * So actually check to see if there is a port number. If not,
 * use the '/' as the delimitation.
 */

	if (endp)
	{
		if (strncmp("80", endp+1, 2) && strncmp("443", endp+1, 3))
			endp = NULL;
	}

	if (!endp)
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

	page[0] = 0;

	if (!url_len)
		return NULL;

	if (!strncmp("http:", url, 5) || !strncmp("https:", url, 6))
	{
		if (url_len < httplen || url_len < httpslen)
			return NULL;

		p += strlen("http://");
	}

	if (!TRAILING_SLASH)
	{
		if (*(endp - 1) == '/')
		{
			--endp;
			*endp = 0;
		}
	}

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
	char *tail = buf->buf_tail;

	if ((p = strstr(check_from, name)))
	{
		if (p < tail)
		{
			*ret_off = (off_t)(p - buf->buf_head);
			return 1;
		}
	}

	return 0;
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
	char *eoh = HTTP_EOH(buf);
	char *eol;
	char *p;
	char *q;

	hh->name[0] = 0;
	hh->value[0] = 0;
	hh->nlen = 0;
	hh->vlen = 0;

	if (!eoh)
	{
		fprintf(stderr, "http_get_header: failed to find end of header\n");
		errno = EPROTO;
		return NULL;
	}

	p = strstr(check_from, name);

	if (!p || p > eoh)
		return NULL;

	eol = memchr(p, '\r', (tail - p));

	if (!eol)
		return NULL;

	q = memchr(p, ':', (eol - p));

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

	p = (q + 1);

	while (*p == ' ' && p < eol)
		++p;

	hh->vlen = (eol - p);
	strncpy(hh->value, p, hh->vlen);
	hh->value[hh->vlen] = 0;

	return hh->value;
}

int
http_append_header(buf_t *buf, http_header_t *hh)
{
	assert(buf);
	assert(hh);

	char *p;
	char *head = buf->buf_head;
	char *eoh = HTTP_EOH(buf);
	off_t poff;

	if (!eoh)
	{
		fprintf(stderr, "http_append_header: failed to find end of header\n");
		errno = EPROTO;
		return -1;
	}

	p = (eoh - 2);

	buf_t tmp;

	assert(hh->vlen < HTTP_COOKIE_MAX);

	buf_init(&tmp, HTTP_COOKIE_MAX + strlen(hh->name) + 2);
	buf_append(&tmp, hh->name);
	buf_append(&tmp, ": ");
	buf_append(&tmp, hh->value);
	buf_append(&tmp, "\r\n");

	poff = (p - buf->buf_head);
	buf_shift(buf, (off_t)(p - head), tmp.data_len);
	p = (buf->buf_head + poff);

	strncpy(p, tmp.buf_head, tmp.data_len);

	buf_destroy(&tmp);

	return 0;
}
