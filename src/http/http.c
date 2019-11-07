#include <assert.h>
#include <arpa/inet.h>
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
#include "http.h"
#include "malloc.h"
#include "webreaper.h"

#define HTTP_SMALL_READ_BLOCK 64
#define HTTP_MAX_WAIT_TIME 6

FILE *logfp;

#define LOG_FILE "./http_debug_log.txt"

#ifdef DEBUG
int _DEBUG = 1;
#else
int _DEBUG = 0;
#endif

static void
_log(char *fmt, ...)
{
	va_list args;

	if (!_DEBUG)
		return;

	va_start(args, fmt);
	vfprintf(logfp, fmt, args);

	va_end(args);

	return;
}

/*
 * User gets struct http_t which does not
 * include the caches.
 */
struct __http_t
{
	char *host;
	char *page;
	char *full_url;
	char *primary_host;

	struct conn conn;
#if 0
	{
		int sock;
		SSL *ssl;
		buf_t read_buf;
		buf_t write_buf;
		char *host_ipv4;
		SSL_CTX *ssl_ctx;
	} conn;
#endif

	wr_cache_t *headers;
	wr_cache_t *cookies;
	http_header_t *__ptr;
};

static struct sigaction oact;
static struct sigaction nact;
static sigjmp_buf TIMEOUT;

static void
__ctor __http_init(void)
{
#ifdef DEBUG
	logfp = fdopen(open(LOG_FILE, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR), "r+");
#endif
	return;
}

static void
__dtor __http_fini(void)
{
#ifdef DEBUG
	fclose(logfp);
	logfp = NULL;
#endif
	return;
}

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
http_header_cache_ctor(void *hh)
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
http_header_cache_dtor(void *hh)
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

#if 0
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
#endif

int
http_link_cache_ctor(void *http_link)
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
http_link_cache_dtor(void *http_link)
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

#ifdef DEBUG
static void
__http_print_request_hdr(struct http_t *http)
{
	char *eoh = HTTP_EOH(&http_wbuf(http));

	if (!eoh)
	{
		fprintf(stderr, "__http_print_request_hdr: failed to find end of header\n");
		return;
	}

	fprintf(stderr, "%s%.*s%s", COL_RED, (int)(eoh - http_wbuf(http).buf_head), http_wbuf(http).buf_head, COL_END);

	return;
}

static void
__http_print_response_hdr(struct http_t *http)
{
	char *eoh = HTTP_EOH(&http_rbuf(http));

	if (!eoh)
	{
		fprintf(stderr, "__http_print_response_hdr: failed to find end of header\n");
		return;
	}

	fprintf(stderr, "%s%.*s%s", COL_RED, (int)(eoh - http_rbuf(http).buf_head), http_rbuf(http).buf_head, COL_END);

	return;
}
#endif

/**
 * __http_check_cookies - check for Set-Cookie header fields in response header
 *			and clear all old cookies if there are new ones specified.
 *
 * @buf: the receive buffer
 * @http: the HTTP object containing the cookie object cache
 */
static int
__http_check_cookies(struct http_t *http)
{
	assert(http);

	buf_t *buf = &http_rbuf(http);
	struct __http_t *__http = (struct __http_t *)http;

	if (strstr(buf->buf_head, "Set-Cookie"))
	{
		off_t off = 0;

		wr_cache_clear_all(__http->cookies);

		while (http_check_header(buf, "Set-Cookie", off, &off))
		{
			if (!(__http->__ptr = (http_header_t *)wr_cache_alloc(__http->cookies, &__http->__ptr)))
			{
				fprintf(stderr, "__http_check_cookies: failed to allocate HTTP header cache object\n");
				goto fail;
			}

			if (!(http_fetch_header(buf, "Set-Cookie", __http->__ptr, off)))
			{
				fprintf(stderr, "__http_check_cookies: failed to extract Set-Cookie header field\n");
				goto fail_dealloc;
			}

			++off;
		}
	}

	return 0;

	fail_dealloc:
	wr_cache_clear_all(__http->cookies);

	fail:
	return -1;
}

int
http_build_request_header(struct http_t *http, const char *http_verb)
{
	assert(http);
	assert(http_verb);

	buf_t *buf = &http_wbuf(http);
	buf_t tmp;
	static char header_buf[4096];

	buf_init(&tmp, HTTP_URL_MAX);
	buf_clear(buf);

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
		buf_append(&tmp, http->host);
		buf_append(&tmp, http->page);

		sprintf(header_buf,
			"HEAD %s HTTP/%s\r\n"
			"Host: %s\r\n"
			"User-Agent: %s%s",
			tmp.buf_head, HTTP_VERSION,
			http->host,
			HTTP_USER_AGENT, HTTP_EOH_SENTINEL);
	}
	else
	{
		buf_append(&tmp, http->host);

		if (*(tmp.buf_tail - 1) == '/')
			buf_snip(&tmp, 1);

		sprintf(header_buf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Accept: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			http->full_url, HTTP_VERSION,
			HTTP_USER_AGENT,
			HTTP_ACCEPT,
			tmp.buf_head,
			HTTP_EOH_SENTINEL);
	}

	buf_append(buf, header_buf);

	int __nr_cookies = wr_cache_nr_used(((struct __http_t *)http)->cookies);

	if (__nr_cookies)
	{
		struct http_header_t *__c = (struct http_header_t *)((struct __http_t *)http)->cookies->cache;
		int i;

		for (i = 0; i < __nr_cookies; ++i)
		{
			http_append_header(buf, __c);
			++__c;
		}
	}

	buf_destroy(&tmp);

	return 0;
}

int
http_send_request(struct http_t *http, const char *http_verb)
{
	assert(http);

	buf_t *buf = &http_wbuf(http);

	http_build_request_header(http, http_verb);
	_log("Built %s request header\n", http_verb);

#ifdef DEBUG
	__http_print_request_hdr(http);
#endif

	if (option_set(OPT_USE_TLS))
	{
		if (buf_write_tls(http_tls(http), buf) == -1)
		{
			fprintf(stderr, "http_send_request: failed to write to SSL socket (%s)\n", strerror(errno));
			goto fail;
		}
	}
	else
	{
		if (buf_write_socket(http_socket(http), buf) == -1)
		{
			fprintf(stderr, "http_send_request: failed to write to socket (%s)\n", strerror(errno));
			goto fail;
		}
	}

	_log("Returning 0 from %s\n", __func__);
	return 0;

	fail:
	return -1;
}


static int
__http_read_until_eoh(struct http_t *http, char **p)
{
	assert(http);

	ssize_t n;
	int is_http = 0;
	buf_t *buf = &http_rbuf(http);

	clear_struct(&oact);
	clear_struct(&nact);
	nact.sa_flags = 0;
	nact.sa_handler = __http_handle_timeout;
	sigemptyset(&nact.sa_mask);

	update_operation_status("Getting HTTP response header");

	if (sigaction(SIGALRM, &nact, &oact) < 0)
	{
		fprintf(stderr, "__http_read_until_eoh: failed to set signal handler for SIGALRM\n");
		return -1;
	}

	if (sigsetjmp(TIMEOUT, 1) != 0)
	{
		update_operation_status("Timed out waiting for response from server");
		sigaction(SIGALRM, &oact, NULL);
		return HTTP_OPERATION_TIMEOUT;
	}

	_log("Reading in small blocks until getting HTTP response header\n");
	alarm(HTTP_MAX_WAIT_TIME);
	while (!(*p))
	{
		if (option_set(OPT_USE_TLS))
			n = buf_read_tls(http_tls(http), buf, HTTP_SMALL_READ_BLOCK);
		else
			n = buf_read_socket(http_socket(http), buf, HTTP_SMALL_READ_BLOCK);

		if (n == -1)
			return -1;

		switch(n)
		{
			case 0:
				continue;
				break;
			default:
				if (!strstr(buf->buf_head, "HTTP/") && strncmp("\r\n", buf->buf_head, 2))
					goto out;
				*p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);
				if (*p)
				{
					is_http = 1;
					goto out;
				}
		}
	}

	out:
	alarm(0);

	if (is_http)
	{
		assert(!strncmp(HTTP_EOH_SENTINEL, *p, strlen(HTTP_EOH_SENTINEL)));
		*p += strlen(HTTP_EOH_SENTINEL);
	}

	sigaction(SIGALRM, &oact, NULL);
	_log("Returning 0 from %s\n", __func__);
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
__read_bytes(struct http_t *http, size_t toread)
{
	assert(http);
	assert(toread > 0);

	ssize_t n;
	size_t r = toread;
	buf_t *buf = &http_rbuf(http);

	while (r)
	{
		if (option_set(OPT_USE_TLS))
			n = buf_read_tls(http_tls(http), buf, r);
		else
			n = buf_read_socket(http_socket(http), buf, r);

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
__http_read_until_next_chunk_size(struct http_t *http, buf_t *buf, char **cur_pos)
{
	assert(http);
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

	__read_bytes(http, 2);
	*cur_pos = (buf->buf_head + cur_pos_off);
	tail = buf->buf_tail;
	*cur_pos += 2;
	cur_pos_off += 2;

	while (1)
	{
		__read_bytes(http, 1);
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
__http_do_chunked_recv(struct http_t *http)
{
	assert(http);

	char *p;
	char *e;
	off_t chunk_offset;
	buf_t *buf = &http_rbuf(http);
	size_t chunk_size;
	size_t save_size;
	size_t overread;
	size_t range;
	char *t;
	static char tmp[HTTP_MAX_CHUNK_STR];
#ifdef DEBUG
	int chunk_nr = 0;
#endif

	_log("Doing chunked transfer\n");
	p = HTTP_EOH(buf);

	while (!p)
	{
		__read_bytes(http, 1);
		p = HTTP_EOH(buf);
	}

	if (!p)
	{
		fprintf(stderr, "__http_do_chunked_recv: failed to find end of header sentinel\n");
		return -1;
	}

	__http_read_until_next_chunk_size(http, buf, &p);

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

			_log("Failed to find next chunk size\n");
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

#if 0
/*
 * XXX: Protect the wrctx struct with a lock
 */
		STATS_ADD_BYTES(wrctx, save_size);
		update_bytes(total_bytes(wrctx));
#endif

		e += 2; /* Skip the \r\n do NOT use SKIP_CRNL(); chunk data could start with these bytes */

		buf_collapse(buf, (off_t)(p - buf->buf_head), (e - p));
		e = p;

		chunk_offset = (e - buf->buf_head);

		overread = (buf->buf_tail - e);

		if (overread >= chunk_size)
		{
			p = (e + save_size);
			__http_read_until_next_chunk_size(http, buf, &p);
		}
		else
		{
			chunk_size -= overread;
		}

		__read_bytes(http, chunk_size);

		p = (buf->buf_head + chunk_offset + save_size);
		__http_read_until_next_chunk_size(http, buf, &p);

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

	_log("Returning 0 from %s\n", __func__);
	return 0;
}

static int
__http_set_new_location(struct http_t *http)
{
	assert(http);

	struct __http_t *__http = (struct __http_t *)http;

	http_header_t *location = NULL;

	if (!(location = (http_header_t *)wr_cache_alloc(__http->headers, &location)))
	{
		fprintf(stderr, "__http_set_new_location: failed to obtain HTTP header cache object\n");
		goto fail_dealloc;
	}

	if (!http_fetch_header(&http_rbuf(http), "Location", location, (off_t)0))
	{
		fprintf(stderr, "__http_set_new_location: failed to find HTTP header field \"Location\"\n");
		goto fail_dealloc;
	}

	update_operation_status("Got location header");

	assert(location->vlen < HTTP_URL_MAX);
	strcpy(__http->full_url, location->value);

	if (!http_parse_host(location->value, http->host))
	{
		fprintf(stderr, "__http_set_new_location: failed to parse host from URL\n");
		goto fail_dealloc;
	}

	if (!http_parse_page(location->value, http->page))
	{
		fprintf(stderr, "__http_set_new_location: failed to parse page from URL\n");
		goto fail_dealloc;
	}

	wr_cache_dealloc(__http->headers, location, &location);

	_log("Got Location header field \"%s\"\n", __http->full_url);
	return 0;

	fail_dealloc:
	wr_cache_dealloc(__http->headers, location, &location);

	return -1;
}

static void
http_set_sock_non_blocking(struct http_t *http)
{
	int sock_flags = fcntl(http->conn.sock, F_GETFL);

	if (!(sock_flags & O_NONBLOCK))
	{
		sock_flags |= O_NONBLOCK;
		fcntl(http->conn.sock, F_SETFL, sock_flags);

		http->conn.sock_nonblocking = 1;

		return;
	}

	return;
}

static void
http_set_ssl_non_blocking(struct http_t *http)
{
	int rsock = SSL_get_rfd(http->conn.ssl);
	int flags = fcntl(rsock, F_GETFL);

	if (!(flags & O_NONBLOCK))
	{
		flags |= O_NONBLOCK;
		fcntl(rsock, F_SETFL, flags);

		http->conn.ssl_nonblocking = 1;

		return;
	}

	return;
}

/**
 * http_recv_response - receive HTTP response.
 * @conn: connection context
 */
int
http_recv_response(struct http_t *http)
{
	assert(http);

	char *p = NULL;
	size_t clen;
	size_t overread;
	ssize_t bytes;
	int rv;
	int http_status_code;
	struct __http_t *__http = (struct __http_t *)http;
	http_header_t *content_len = NULL;
	http_header_t *transfer_enc = NULL;
	buf_t *buf = &http_rbuf(http);
	char *http_red_url = NULL; /* URL that was redirected with 3xx code */

	update_operation_status("Receiving data from server");

	if (!http->conn.sock_nonblocking)
		http_set_sock_non_blocking(http);
	if (!http->conn.ssl_nonblocking)
		http_set_ssl_non_blocking(http);

	content_len = (http_header_t *)wr_cache_alloc(__http->headers, &content_len);

	if (!content_len)
		goto fail;

	transfer_enc = (http_header_t *)wr_cache_alloc(__http->headers, &transfer_enc);

	if (!transfer_enc)
		goto fail_dealloc;

	__retry:
	rv = __http_read_until_eoh(http, &p);

	if (rv < 0 || HTTP_OPERATION_TIMEOUT == rv)
		goto fail_dealloc;

#ifdef DEBUG
	__http_print_response_hdr(http);
#endif

	__http_check_cookies(http);

	http_status_code = http_status_code_int(buf);

	switch((unsigned int)http_status_code)
	{
		case HTTP_FOUND:
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_SEE_OTHER:
			update_operation_status("Getting location header");
/*
 * Save the URL that was redirected. Once we get the new URL and obtain
 * a response to our GET request, copy that 'old' URL back into our
 * HTTP object header. That way, if we archive the page using the old
 * URL, we can avoid requesting it again in the future when we come
 * across that URL within another page.
 */
			http_red_url = strdup(http->full_url);
			if (__http_set_new_location(http) < 0)
				goto fail_dealloc;

			buf_clear(&http_rbuf(http));
			buf_clear(&http_wbuf(http));

			update_operation_status("Sending GET request");
			if (http_send_request(http, HTTP_GET) < 0)
			{
				fprintf(stderr, "http_recv_response: failed to resend HTTP request after \"%s\" response\n", http_status_code_string(http_status_code));
				goto fail_dealloc;
			}

			_log("Old url: %s ; new url: %s\n", http_red_url, http->full_url);
			strcpy(http->full_url, http_red_url);
			free(http_red_url);

			goto __retry;
			break;
		default:
			break;
	}

	if (!p)
	{
		//fprintf(stderr, "http_recv_response: failed to find end of header sentinel\n");
		goto out_dealloc;
	}

/*
 * \r\n\r\nBBBBBBB...
 *         ^
 *         p
 */

	if (strstr(http_wbuf(http).buf_head, "HEAD"))
		goto out_dealloc;

	if (http_fetch_header(&http_rbuf(http), "Transfer-Encoding", transfer_enc, (off_t)0))
	{
		if (!strncmp("chunked", transfer_enc->value, transfer_enc->vlen))
		{
			if (__http_do_chunked_recv(http) == -1)
				goto fail_dealloc;

			goto out_dealloc;
		}
	}

	if (http_fetch_header(buf, "Content-Length", content_len, (off_t)0))
	{
		clen = strtoul(content_len->value, NULL, 0);

		overread = (buf->buf_tail - p);

#if 0
		STATS_ADD_BYTES(wrctx, clen);
		update_bytes(total_bytes(wrctx));
#endif

		if (overread < clen)
		{
			clen -= overread;

			while (clen)
			{
				if (option_set(OPT_USE_TLS))
					bytes = buf_read_tls(http_tls(http), buf, clen);
				else
					bytes = buf_read_socket(http_socket(http), buf, clen);

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
			bytes = buf_read_tls(http_tls(http), buf, 0);
		else
			bytes = buf_read_socket(http_socket(http), buf, 0);

		rv = bytes;

		if (rv < 0)
			goto fail_dealloc;

#if 0
		STATS_ADD_BYTES(wrctx, rv);
		update_bytes(total_bytes(wrctx));
#endif

		p = strstr(buf->buf_head, "</body");

		if (!p)
		{
			goto read_again;
		}
	}

	out_dealloc:
	wr_cache_dealloc(__http->headers, (void *)content_len, &content_len);
	wr_cache_dealloc(__http->headers, (void *)transfer_enc, &transfer_enc);

	return 0;

	fail_dealloc:
	_log("Failed in %s\n", __func__);
	if (content_len)
	{
		wr_cache_dealloc(__http->headers, (void *)content_len, &content_len);
	}

	if (transfer_enc)
	{
		wr_cache_dealloc(__http->headers, (void *)transfer_enc, &transfer_enc);
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
		case HTTP_SEE_OTHER:
			sprintf(code_string, "%s%u See Other%s", COL_ORANGE, HTTP_SEE_OTHER, COL_END);
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

#if 0
	if (!keep_trailing_slash(wrctx))
	{
		if (*(endp - 1) == '/')
		{
			--endp;
			*endp = 0;
		}
	}
#endif

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

void
http_check_host(struct http_t *http)
{
	assert(http);

	static char old_host[HTTP_HNAME_MAX];
	struct __http_t *__http = (struct __http_t *)http;

	if (!http->full_url[0])
		return;

	assert(strlen(http->host) < HTTP_HNAME_MAX);
	strcpy(old_host, http->host);
	http_parse_host(http->full_url, http->host);

	if (strcmp(http->host, old_host))
	{
		if (wr_cache_nr_used(__http->cookies) > 0)
			wr_cache_clear_all(__http->cookies);

		update_operation_status("Changing host: %s ==> %s", old_host, http->host);
		http_reconnect(http);
	}

	return;
}

int
http_connection_closed(struct http_t *http)
{
	assert(http);

	http_header_t *connection;
	buf_t *buf = &http_rbuf(http);
	int rv = 0;
	struct __http_t *__http = (struct __http_t *)http;

	//fprintf(stderr, "allocating header obj in CONNECTION @ %p\n", &connection);

	connection = wr_cache_alloc(__http->headers, &connection);
	assert(connection);

	http_fetch_header(buf, "Connection", connection, (off_t)0);

	if (connection->value[0])
	{
		if (!strcasecmp("close", connection->value))
			rv = 1;
	}

	//fprintf(stderr, "deallocting header obj CONNECTION @ %p\n", &connection);

	wr_cache_dealloc(__http->headers, connection, &connection);
	return rv;
}

static int __http_obj_cnt = 0;
static char __http_cache_name[64];

static int
__http_init_obj(struct __http_t *__http)
{
	sprintf(__http_cache_name, "http_header_cache%d", __http_obj_cnt);

	if (!(__http->headers = wr_cache_create(
			__http_cache_name,
			sizeof(http_header_t),
			0,
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "__http_init_obj: failed to create cache for HTTP header objects\n");
		goto fail;
	}

	_log("Created header cache %s\n", __http_cache_name);

	sprintf(__http_cache_name, "http_cookie_cache%d", __http_obj_cnt);
	if (!(__http->cookies = wr_cache_create(
			__http_cache_name,
			sizeof(http_header_t),
			0,
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "__http_init_obj: failed to create cache for HTTP cookie objects\n");
		goto fail_destroy_cache;
	}

	_log("Created coookies cache %s\n", __http_cache_name);

	__http->host = calloc(HTTP_HOST_MAX+1, 1);
	__http->conn.host_ipv4 = calloc(__HTTP_ALIGN_SIZE(INET_ADDRSTRLEN+1), 1);
	__http->primary_host = calloc(HTTP_HOST_MAX+1, 1);
	__http->page = calloc(HTTP_URL_MAX+1, 1);
	__http->full_url = calloc(HTTP_URL_MAX+1, 1);

	if (buf_init(&__http->conn.read_buf, HTTP_DEFAULT_READ_BUF_SIZE) < 0)
	{
		fprintf(stderr, "__http_init_obj: failed to initialise read buf\n");
		goto fail_destroy_cache;
	}

	if (buf_init(&__http->conn.write_buf, HTTP_DEFAULT_WRITE_BUF_SIZE) < 0)
	{
		fprintf(stderr, "__http_init_obj: failed to initialise write buf\n");
		goto fail_release_mem;
	}

	assert(__http->host);
	assert(__http->conn.host_ipv4);
	assert(__http->primary_host);
	assert(__http->page);
	assert(__http->full_url);

	++__http_obj_cnt;

	_log("Initialised HTTP object fields. #objs = %d\n", __http_obj_cnt);

	return 0;

	fail_release_mem:
	buf_destroy(&__http->conn.read_buf);

	fail_destroy_cache:
	wr_cache_destroy(__http->headers);

	fail:
	return -1;
}

struct http_t *
http_new(void)
{
	struct __http_t *__http = malloc(sizeof(struct __http_t));

	if (!__http)
	{
		fprintf(stderr, "http_new: failed to allocate memory for new HTTP object\n");
		goto fail;
	}

	if (__http_init_obj(__http) < 0)
	{
		fprintf(stderr, "http_new: failed to initialise HTTP object\n");
		goto fail;
	}

	_log("Created HTTP object @ %p\n", __http);
	return (struct http_t *)__http;

	fail:
	return NULL;
}

void
http_delete(struct http_t *http)
{
	assert(http);

	struct __http_t *__http = (struct __http_t *)http;

	free(__http->host);
	free(__http->primary_host);
	free(__http->conn.host_ipv4);
	free(__http->page);
	free(__http->full_url);

	wr_cache_clear_all(__http->headers);
	wr_cache_destroy(__http->headers);

	wr_cache_clear_all(__http->cookies);
	wr_cache_destroy(__http->cookies);

	buf_destroy(&__http->conn.read_buf);
	buf_destroy(&__http->conn.write_buf);

	_log("Deleted HTTP object\n");

	return;
}
