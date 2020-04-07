#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "netwasabi.h"

/*
 * TODO
 *
 * Gracefully handle 3xx/4xx/5xx codes.
 * (follow redirects automatically)
 *
 * Make the dead link and redirected link caches
 * shareable among threads.
 *
 * Upgrade to handle HTTP 2.0
 *
 * Embed HTTP_methods structure within HTTP object
 * which will allow us to be dynamic and use various
 * versions of the HTTP protocol.
 *
 * Decouple this file and the netwasabi header
 * because we want the internals of this module
 * to be opaque and therefore reusable elsewhere.
 *
 * Create a hash bucket data structure for header
 * fields so that it will be easy to consult
 * whatever we are interested in later.
 * (At the moment, we just search within the
 * header each time we wish to know a value
 * and save it temporarily in a struct).
 */

#define HTTP_VERSION_1_0 0x10000000u
#define HTTP_VERSION_1_1 0x10100000u
#define HTTP_VERSION_2_0 0x20000000u
#define HTTP_DEFAULT_VERSION HTTP_VERSION_1_1

/*
 * Definitions related to HTTP 2.0
 *
 * This MUST be followed by a SETTINGS frame,
 * which MAY be empty (RFC 7540)
 */
#define HTTP_2_0_CONNECTION_PREFACE_START_SEQUENCE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP_2_0_SETTINGS_MAX_FRAME_SIZE 1048576u // 2^20

#define HTTP_UPGRADE_HEADER_FIELD_CLEAR	"Upgrade: h2c"
#define HTTP_UPGRADE_HEADER_FIELD_TLS	"Upgrade: h2"

struct HTTP_frame
{
	uint32_t len:24;
	uint32_t type:8;
	uint8_t flags;
	uint32_t streamId;
} __attribute__((packed));

#define HTTP_SKIP_HOST_PART(PTR, URL)\
do {\
	char *____s_p = NULL;\
	char *____e_p = NULL;\
	if (!strncmp("http", (URL), 4))\
	{\
		(PTR) = (URL) + strlen("http://");\
		if ((*PTR) == '/')\
			++(PTR);\
			____e_p = ((URL) + strlen((URL)));\
			____s_p = memchr((PTR), '/', (____e_p - (PTR)));\
			if (____s_p)\
				(PTR) = ____s_p;\
	}\
	else\
	{\
		(PTR) = (URL);\
	}\
} while (0)

#define HTTP_private(h) (struct HTTP_private *)(h)

#define set_verb(h, v) ((h)->verb = (v))

#define HTTP_SMALL_READ_BLOCK 8
#define HTTP_MAX_WAIT_TIME 6

#define CREATION_FLAGS O_RDWR|O_CREAT|O_TRUNC
#define CREATION_MODE S_IRUSR|S_IWUSR

/*
 * Forward declarations
 */
typedef struct HTTP_dead_link http_dead_link_t;
typedef struct HTTP_redirected http_redirected_t;

/*
 * User gets struct http_t which does not
 * include the caches.
 */
struct HTTP_private
{
	struct http_t http;
/*
 * This is private data only
 * accessable within this file.
 *
 * Every HTTP object created
 * has its own cache of cookies
 * and headers, which allows
 * multithreading.
 */
	cache_t *headers;
	cache_t *cookies;
	cache_t *deadLinks;
	cache_t *redirectedLinks;
/*
 * The following are used to pass their addresses
 * to cache_alloc().
 */
	http_header_t *hfPtr; // header field object pointer
	http_dead_link_t *dlPtr; // dead link object pointer
	http_redirected_t *rlPtr; // redirected link object pointer
};

/*
int http_status_code_int(buf_t *) __nonnull((1)) __wur;
ssize_t http_response_header_len(buf_t *) __nonnull((1)) __wur;

const char *http_status_code_string(int) __wur;

void http_check_host(struct http_t *) __nonnull((1));
int http_connection_closed(struct http_t *) __nonnull((1)) __wur;
*/

void http_check_host(struct http_t *) __nonnull((1));
int http_connection_closed(struct http_t *) __nonnull((1)) __wur;

static int send_request_1_1(struct http_t *);
static int recv_response_1_1(struct http_t *);
static int build_request_header_1_1(struct http_t *);
static int append_header_1_1(buf_t *, http_header_t *);
static int check_header_1_1(buf_t *, const char *, off_t, off_t *);
static char *fetch_header_1_1(buf_t *, const char *, http_header_t *, off_t);
static char *URL_parse_host(char *, char *);
static char *URL_parse_page(char *, char *);
static const char *code_as_string(struct http_t *);

static void HTTP_cache_redirected_link(struct http_t *, const char *, const char *);
static http_dead_link_t *HTTP_search_dead_link(struct HTTP_private *);
static void HTTP_cache_dead_link(struct http_t *, const char *, int);

static int http_status_code_int(buf_t *) __nonnull((1));

struct HTTP_methods Methods_v1_1 = {
	.send_request = send_request_1_1,
	.recv_response = recv_response_1_1,
	.build_header = build_request_header_1_1,
	.append_header = append_header_1_1,
	.check_header = check_header_1_1,
	.fetch_header = fetch_header_1_1,
	.URL_parse_host = URL_parse_host,
	.URL_parse_page = URL_parse_page,
	.code_as_string = code_as_string
};

//struct HTTP_methods Methods_v2_0;



/*
 * Cache dead links so that we can avoid
 * wasting network bandwith requesting
 * them again when we see their URL in
 * another page on the site.
 */
struct HTTP_dead_link
{
	char *URL;
	int code;
	time_t timestamp;
	int times_seen;
};

/*
 * Cache redirected URLs so that we can obtain
 * their current URL if we stumble upon another
 * URL on the site that would elicit a redirect.
 *
 * XXX
 *
 *	After a session, we should save these
 *	mappings in a compressed file in the
 *	event that we crawl the same site
 *	at a future date, sparing bandwidth
 *	wastage.
 */
struct HTTP_redirected
{
	char *fromURL; // The URL that elicits an HTTP redirect
	char *toURL; // The URL found in the Location header field
	time_t when; // When we first encountered the original URL
};

static void
__ctor HTTP_init(void)
{
#ifdef DEBUG
	hlogfp = fdopen(open(LOG_FILE, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR), "r+");
	assert(hlogfp);
	_log("Opened log file\n");
#endif
	return;
}

static void
__dtor private_fini(void)
{
#ifdef DEBUG
	fclose(hlogfp);
	hlogfp = NULL;
#endif
	return;
}

FILE *hlogfp = NULL;

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
	vfprintf(hlogfp, fmt, args);
	va_end(args);

	fflush(hlogfp);

	return;
}

/**
 * Constructor for dead link cache objects.
 */
static int
http_dead_link_cache_ctor(void *dlObj)
{
	assert(dlObj);

	http_dead_link_t *dl = (http_dead_link_t *)dlObj;

	dl->URL = nw_calloc(HTTP_URL_MAX, 1);
	dl->code = 0;
	dl->timestamp = 0;
	dl->times_seen = 0;

	if (NULL == dl->URL)
		return -1;

	return 0;
}

/**
 * Destructor for dead linke cache objects.
 */
static void
http_dead_link_cache_dtor(void *dlObj)
{
	assert(dlObj);

	http_dead_link_t *dl = (http_dead_link_t *)dlObj;

	if (NULL != dl->URL)
	{
		free(dl->URL);
		dl->URL = NULL;
	}

	dl->code = 0;
	dl->timestamp = 0;
	dl->times_seen = 0;

	return;
}

static int
http_redirected_cache_ctor(void *rlObj)
{
	assert(rlObj);

	http_redirected_t *rl = (http_redirected_t *)rlObj;

	rl->fromURL = calloc(HTTP_URL_MAX, 1);
	rl->toURL = calloc(HTTP_URL_MAX, 1);

	if (!rl->fromURL || !rl->toURL)
		goto fail_dealloc;

	rl->when = 0;

	return 0;

fail_dealloc:

	if (NULL != rl->fromURL)
		free(rl->fromURL);
	if (NULL != rl->toURL)
		free(rl->toURL);

	return -1;
}

static void
http_redirected_cache_dtor(void *rlObj)
{
	assert(rlObj);

	http_redirected_t *rl = (http_redirected_t *)rlObj;

	if (NULL != rl->fromURL)
		free(rl->fromURL);
	if (NULL != rl->toURL)
		free(rl->toURL);

	rl->when = 0;

	return;
}

/**
 * Search the dead link cache for a URL.
 *
 * @http The HTTP object containing the URL.
 */
http_dead_link_t *
HTTP_search_dead_link(struct HTTP_private *private)
{
	assert(private);

	http_dead_link_t *dead = NULL;
	int objUsed = 0;
	size_t URL_len = strlen(((struct http_t *)private)->URL);

	dead = (http_dead_link_t *)private->deadLinks->cache;

	while (1)
	{
		while ((objUsed = cache_obj_used(private->deadLinks, (void *)dead)) != 0)
			++dead;

		if (objUsed < 0)
			break;

		if (!memcmp((void *)dead->URL, (void *)((struct http_t *)private)->URL, URL_len))
			return dead; 
	}

	return NULL;
}

/**
 * cache_http_cookie_ctor - initialise object for the cookie cache
 * @hh: pointer to the object in the cache
 *  -- called in cache_create()
 */
int
http_header_cache_ctor(void *hh)
{
	http_header_t *ch = (http_header_t *)hh;
	clear_struct(ch);

	if (!(ch->name = nw_calloc(HTTP_HNAME_MAX+1, 1)))
		goto fail;

	if (!(ch->value = nw_calloc(HTTP_COOKIE_MAX+1, 1)))
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
 * cache_http_cookie_dtor - free memory in http_header_t cache object
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

int
http_link_cache_ctor(void *http_link)
{
	http_link_t *hl = (http_link_t *)http_link;
	clear_struct(hl);

	hl->url = nw_calloc(HTTP_URL_MAX+1, 1);

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

/**
 * Cache a dead link.
 *
 * @http The HTTP object in which the cache resides
 * @URL The URL to cache
 * @code The HTTP code that was received for the link (e.g., 404)
 */
void
HTTP_cache_dead_link(struct http_t *http, const char *URL, int code)
{
	assert(http);
	assert(URL);
	assert(strlen(URL) < HTTP_URL_MAX);

	struct HTTP_private *private = (struct HTTP_private *)http;
	http_dead_link_t *dl = NULL;

	dl = cache_alloc(private->deadLinks, &private->dlPtr);
	if (NULL == private->dlPtr)
		goto fail;

	strcpy(dl->URL, URL);
	dl->code = code;
	dl->timestamp = time(NULL);
	++dl->times_seen;

	return;

fail:
	_log("failed to obtain cache object for dead link");
	return;
}

void
HTTP_cache_redirected_link(struct http_t *http, const char *from, const char *to)
{
	assert(http);
	assert(from);
	assert(to);

	struct HTTP_private *private = HTTP_private(http);
	http_redirected_t *rl = cache_alloc(private->redirectedLinks, private->rlPtr);

	if (NULL == rl)
		goto fail;

	size_t fromLen = strlen(from);
	size_t toLen = strlen(to);

	memcpy((void *)rl->fromURL, (void *)from, fromLen < HTTP_URL_MAX ? fromLen : HTTP_URL_MAX);
	memcpy((void *)rl->toURL, (void *)to, toLen < HTTP_URL_MAX ? toLen : HTTP_URL_MAX);
	rl->when = time(NULL);

fail:
	_log("failed to obtain cache object for redirected link");
	return;
}

/*
#define SOURCE_RANDOMNESS "/dev/urandom"
static void
HTTP_get_random_bytes(char *dest, int nr)
{
	assert(dest);

	int fd = -1;

	if ((fd = open(SOURCE_RANDOMNESS, O_RDONLY)) < 0)
		goto use_rand;

	if (read(fd, dest, nr) != nr)
		goto use_rand;

	close(fd);
	fd = -1;

	return;

use_rand:
	close(fd);
	fd = -1;
	*(uint32_t *)dest = (rand() & 0xffffffff);

	return;
}
*/

/**
 * check_cookies - check for Set-Cookie header fields in response header
 *			and clear all old cookies if there are new ones specified.
 *
 * @buf: the receive buffer
 * @http: the HTTP object containing the cookie object cache
 */
static int
check_cookies(struct http_t *http)
{
	assert(http);

	buf_t *buf = &http->conn.read_buf;
	struct HTTP_private *private = (struct HTTP_private *)http;

	if (strstr(buf->buf_head, "Set-Cookie"))
	{
		off_t off = 0;

		cache_clear_all(private->cookies);

		while (http->ops->check_header(buf, "Set-Cookie", off, &off))
		{
			if (!(private->hfPtr = (http_header_t *)cache_alloc(private->cookies, &private->hfPtr)))
			{
				fprintf(stderr, "private_check_cookies: failed to allocate HTTP header cache object\n");
				goto fail;
			}

			if (!(http->ops->fetch_header(buf, "Set-Cookie", private->hfPtr, off)))
			{
				fprintf(stderr, "private_check_cookies: failed to extract Set-Cookie header field\n");
				goto fail_dealloc;
			}

			++off;
		}
	}

	return 0;

	fail_dealloc:
	cache_clear_all(private->cookies);

	fail:
	return -1;
}

#define HTTP_HEADER_BUFSIZE 8192

/**
 * HTTP 1.1
 * Build a request header
 *
 * @http HTTP object.
 */
int
build_request_header_1_1(struct http_t *http)
{
	assert(http);

	buf_t *buf = &http->conn.write_buf;
	buf_t tmp;
	/*
	 * Cannot use static memory since we
	 * need to be thread-safe.
	 */
	//static char header_buf[4096];
	char *header_buf = calloc(HTTP_HEADER_BUFSIZE, 1);

	if (NULL == header_buf)
		return -1;

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

	switch(http->verb)
	{
		case HEAD:

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
		break;

		default:
		case GET:

		buf_append(&tmp, http->host);

		if (*(tmp.buf_tail - 1) == '/')
			buf_snip(&tmp, 1);

		sprintf(header_buf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Accept: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			http->URL, HTTP_VERSION,
			HTTP_USER_AGENT,
			HTTP_ACCEPT,
			tmp.buf_head,
			HTTP_EOH_SENTINEL);
	}

	buf_append(buf, header_buf);

	free(header_buf);
	header_buf = NULL;

/*
 * Append any cached cookies to the request header.
 */
	int nrCookies = cache_nr_used(((struct HTTP_private *)http)->cookies);

	if (nrCookies)
	{
		struct http_header_t *cookieObj = (struct http_header_t *)((struct HTTP_private *)http)->cookies->cache;
		int i;

		for (i = 0; i < nrCookies; ++i)
		{
			http->ops->append_header(buf, cookieObj);
			++nrCookies;
		}
	}

	buf_destroy(&tmp);

	return 0;
}

int
send_request_1_1(struct http_t *http)
{
	assert(http);

	struct HTTP_private *private = (struct HTTP_private *)http;
	http_dead_link_t *dead = NULL;

/*
 * Link is dead, so return the HTTP code from dead link object.
 */
	if ((dead = HTTP_search_dead_link(private)))
	{
		http->code = dead->code;
		return 0;
	}

	buf_t *buf = &http->conn.write_buf;

	buf_clear(buf);

	set_verb(http, GET);
	build_request_header_1_1(http);

	if (option_set(OPT_USE_TLS))
	{
		if (buf_write_tls(http->conn.ssl, buf) == -1)
		{
			fprintf(stderr, "send_request: failed to write to SSL socket (%s)\n", strerror(errno));
			goto fail;
		}
	}
	else
	{
		if (buf_write_socket(http->conn.sock, buf) == -1)
		{
			fprintf(stderr, "http_send_request: failed to write to socket (%s)\n", strerror(errno));
			goto fail;
		}
	}

	return 0;

fail:
	return -1;
}

#define CYCLES_MAX 100000000

static int
read_until_eoh(struct http_t *http, char **p)
{
	assert(http);

	ssize_t n;
	int is_http = 0;
	int bytes = 0;
	buf_t *buf = &http->conn.read_buf;
	register int cycles = 0;

	while (!(*p))
	{
		++cycles;

		if (cycles >= CYCLES_MAX)
			return HTTP_OPERATION_TIMEOUT;

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
				bytes += (int)n;
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

	if (is_http)
	{
		assert(!strncmp(HTTP_EOH_SENTINEL, *p, strlen(HTTP_EOH_SENTINEL)));
		*p += strlen(HTTP_EOH_SENTINEL);
	}

	return bytes;
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
read_bytes(struct http_t *http, size_t toread)
{
	assert(http);
	assert(toread > 0);

	ssize_t n;
	size_t r = toread;
	buf_t *buf = &http->conn.read_buf;
	register int cycles = 0;

/*
 * XXX
 *
 * CYCLES_MAX is our crude way of
 * deciding we have timed out.
 */
	while (r)
	{
		++cycles;
		if (cycles > CYCLES_MAX)
			break;

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

/*
 * In chunked transfer encoding, the data is sent in chunks
 * with each chunk being preceded with the number of bytes
 * of the chunk (this is used for pages that are created
 * dynamically and therefore the HTTP server cannot send
 * a Content-Length header.
 *
 * The data is encoding thus:
 *
 * \r\n[CHUNKSIZE]\r\n...DATA...\r\n[CHUNKSIZE]\r\n...DATA...\r\n0\r\n
 *
 */
static void
read_until_next_chunk_size(struct http_t *http, buf_t *buf, char **cur_pos)
{
	assert(http);
	assert(buf);
	assert(cur_pos);
	assert(buf_integrity(buf));

	off_t cur_pos_off = (*cur_pos - buf->buf_head);
	char *q;
	char *tail = buf->buf_tail;

/*
 * We want to produce the following state:
 *
 *        \r\n[CHUNKSIZE]\r\n
 *        ^
 *     CUR_POS
 *
 * We may already have this in our buffer
 * and therefore simply need to point
 * CUR_POS accordingly.
 *
 * Otherwise, do small reads until
 * we have the metadata.
 */

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

			/*
			 * Then we don't need to do
			 * anymore reads. We have already
			 * got \r\n[CHUNKSIZE]\r\n in the
			 * buffer.
			 *
			 * Adjust CUR_POS to point to the
			 * carriage return immediately after
			 * the final byte of the previous
			 * chunk.
			 */
				if (q != tail)
				{
					*cur_pos -= 2;
					return;
				}
			}
		}
	}

/*
 * We enter this function having pointed CUR_POS
 * to START_OF_PREVIOUS_CHUNK + PREVIOUS_CHUNK_SIZE.
 * We need at least two bytes here to get the \r\n
 * at the start of the metadata.
 *
 * NB - everytime we do a read, the location of
 * our buffer on the heap may change due to a
 * transparent realloc(). So we need to re-point
 * TAIL and *CUR_POS afterwards.
 */
	read_bytes(http, 2);
	*cur_pos = (buf->buf_head + cur_pos_off);
	tail = buf->buf_tail;
	*cur_pos += 2;
	cur_pos_off += 2;

	while (1)
	{
		read_bytes(http, 1);
		tail = buf->buf_tail;
		*cur_pos = (buf->buf_head + cur_pos_off);
		q = memchr(*cur_pos, 0x0a, (tail - *cur_pos));
		if (q)
		{
			*cur_pos -= 2;
			break;
		}
	}

	return;
}

/**
 * Obsolete from HTTP 2.0
 *
 * Receive an unknown amount of data from the
 * webserver (dynamically created page which
 * therefore had no Content-Length header).
 * This is common for example with pages that
 * use a script in a CGI bin and so the length
 * of the output data is variable.
 *
 * Data is sent in chunks, with each chunk
 * preceded by metadata indicating the size
 * of the chunk of data to receive.
 *
 * Ends with sequence \r\n0\r\n
 *
 */
static size_t
do_chunked_recv(struct http_t *http)
{
	assert(http);

	char *p;
	char *e;
	off_t chunk_offset;
	buf_t *buf = &http->conn.read_buf;
	size_t chunk_size;
	size_t save_size;
	size_t overread;
	size_t total_bytes = 0;
	static char tmp[HTTP_MAX_CHUNK_STR];
	char *t;
	size_t range;
#if 0
#ifndef DEBUG
	char *t;
	size_t range;
#else
	int chunk_nr = 0;
#endif
#endif

	p = HTTP_EOH(buf);

	while (!p)
	{
		total_bytes += read_bytes(http, 1);
		p = HTTP_EOH(buf);
	}

	if (!p)
	{
		fprintf(stderr, "do_chunked_recv: failed to find end of header sentinel\n");
		return -1;
	}

	read_until_next_chunk_size(http, buf, &p);

	while (1)
	{
/*
 * Skip the first \r\n in "\r\nchunk_size\r\n"
 * and collapse the buffer so we now have
 * "chunk_size\r\n"
 */
		t = p;
		SKIP_CRNL(p);

		range = (p - t);
		if (range)
		{
			buf_collapse(buf, (off_t)(t - buf->buf_head), range);
			p = t;
		}
#if 0
		++chunk_nr;
		_log("Chunk #%d\n", chunk_nr);
		SKIP_CRNL(p);
#endif

		e = memchr(p, 0x0d, HTTP_MAX_CHUNK_STR);

		if (!e)
		{
			_log("%s: failed to find next carriage return\n", __func__);

#ifdef DEBUG
			int i;

			__dump_buf(buf);

			p -= 32;

			for (i = 0; i < 64; ++i)
				_log("%02hhx ", p[i]);

			_log("\n");

			_log("%.*s\n", (int)64, p);

			_log(
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

/*
 * Now we have chunk_size\r\n
 *             ^         ^
 *             p         e
 */
		strncpy(tmp, p, (e - p));
		tmp[e - p] = 0;

		chunk_size = strtoul(tmp, NULL, 16);

#ifdef DEBUG
		_log("%sCHUNK SIZE=%lu BYTES%s\n", COL_ORANGE, chunk_size, COL_END);
#endif

		if (!chunk_size)
		{
/*
 * Then we just dealt with the last chunk and there are no more to come.
 * Collapse the buffer to get rid of the final "0\r\n" sequence.
 */
			--p;
			buf_collapse(buf, (off_t)(p - buf->buf_head), (buf->buf_tail - p));
			break;
		}

/*
 * Save the chunk size here because below we may find we already received
 * some of the chunk data, so we will do chunk_size - overread, but we
 * later need to calculate the position BUFFER START + CHUNK OFFSET +
 * CHUNK SIZE, so we need to save this.
 */
		save_size = chunk_size;
		total_bytes += save_size;

/*
 * Do not use SKIP_CRNL() here, because the first few bytes of data
 * after the \r\nCHUNK_SIZE\r\n could well be one or more \r / \n
 * chars. This would result in jumping too far when we go forward
 * CHUNK_SIZE bytes from start of the chunk data.
 */
		e += 2;

		buf_collapse(buf, (off_t)(p - buf->buf_head), (e - p));
		e = p;

/*
 * Save the offset from the start of the buffer of the chunk data,
 * since reading more data into the buffer can result in a
 * realloc(), which may move our buffer data elsewhere on the heap.
 * So use this to make sure our pointer is pointing in the right
 * place on the heap by doing start of buffer + offset later.
 */
		chunk_offset = (e - buf->buf_head);
		overread = (buf->buf_tail - e);

/*
 * Check if we already received some of the chunk data.
 */
		if (overread >= chunk_size)
		{
			p = (e + save_size);
			read_until_next_chunk_size(http, buf, &p);
		}
		else
		{
			chunk_size -= overread;
		}

		read_bytes(http, chunk_size);

#if 0
/*
 * Every now and again, we get stuck trying to read more bytes
 * (somehow) even though we already actually have gotten all
 * the data (we have </html>[\r\n]). So just break if we have
 * the closing html tag.
 */
		if (strstr(buf->buf_head, "</html>"))
			break;
#endif

/*
 * After this, P should be pointing to where the initial
 * \r is/will be in the "\r\nchunk_size\r\n" sequence.
 */
		p = (buf->buf_head + chunk_offset + save_size);
		read_until_next_chunk_size(http, buf, &p);
	}

	_log("Returning %lu from %s\n", total_bytes, __func__);
	return total_bytes;
}

/**
 * Extract the Location header field from header
 * and set the PAGE and HOST values in http object.
 *
 * @http The HTTP object
 */
static int
set_new_location(struct http_t *http)
{
	assert(http);

	struct HTTP_private *private = (struct HTTP_private *)http;
	http_header_t *location = NULL;

	if (!(location = (http_header_t *)cache_alloc(private->headers, &location)))
	{
		_log("set_new_location: failed to obtain HTTP header cache object\n");
		goto fail_dealloc;
	}

	if (!http->ops->fetch_header(&http->conn.read_buf, "Location", location, (off_t)0))
	{
		_log("%s: failed to find HTTP header field \"Location\"\n", __func__);
		goto fail_dealloc;
	}

	assert(location->vlen < HTTP_URL_MAX);

	if (!location->value[0])
		return 0;

	strcpy(http->URL, location->value);

	_log("Got new location: %s\n", location->value);

	if (!http->ops->URL_parse_host(location->value, http->host))
	{
		_log("%s: failed to parse HOST from URL\n", __func__);
		goto fail_dealloc;
	}

	_log("Extracted host: %s\n", http->host);

	if (!http->ops->URL_parse_page(location->value, http->page))
	{
		_log("%s: failed to parse page from URL\n", __func__);
		goto fail_dealloc;
	}

	_log("Extracted page: %s\n", http->page);

	cache_dealloc(private->headers, location, &location);

	return 0;

fail_dealloc:
	cache_dealloc(private->headers, location, &location);

	return -1;
}

/**
 * http_set_sock_non_blocking - set the O_NONBLOCK flag for socket
 * @http: our HTTP object
 */
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

/**
 * http_set_ssl_non_blocking - set the READ file descriptor as non blocking
 * @http: our HTTP object
 */
static void
http_set_ssl_non_blocking(struct http_t *http)
{
	if (!http->conn.ssl)
		return;

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
 * recv_response_1_1 - receive HTTP response.
 * @http HTTP object
 */
int
recv_response_1_1(struct http_t *http)
{
	assert(http);

	char *p = NULL;
	size_t clen;
	size_t overread;
	ssize_t bytes;
	int retVal = -1;
	int code = 0;
	int total_bytes = 0;
	char tmpURL[HTTP_URL_MAX];
	http_header_t *content_len = NULL;
	http_header_t *transfer_enc = NULL;
	buf_t *buf = &http->conn.read_buf;
	struct HTTP_private *private = HTTP_private(http);

/*
 * Set the (ssl) socket to non-blocking.
 * (just the read fd for ssl).
 */
	if (!http->conn.sock_nonblocking)
		http_set_sock_non_blocking(http);
	if (!http->conn.ssl_nonblocking)
		http_set_ssl_non_blocking(http);

/*
 * XXX
 *
 *	We should really parse the header fields
 *	that we are interested in and set various
 *	flags based upon the information.
 */
	content_len = (http_header_t *)cache_alloc(private->headers, &content_len);

	if (!content_len)
	{
		_log("failed to get cache object for content_len\n");
		goto fail;
	}

	transfer_enc = (http_header_t *)cache_alloc(private->headers, &transfer_enc);

	if (!transfer_enc)
	{
		_log("failed to get cache object for transfer_enc\n");
		goto fail_dealloc;
	}

/*
 * Jump back to here to resend a request after dealing with
 * a 3xx URL redirect and resending the request.
 */
__retry:

	buf_clear(&http->conn.read_buf);
	assert(http->conn.read_buf.data_len == 0);

	retVal = read_until_eoh(http, &p);

	if (retVal < 0 || HTTP_OPERATION_TIMEOUT == retVal)
	{
		_log("read_until_eoh() returned %d\n", retVal);
		goto fail_dealloc;
	}

	total_bytes += retVal;
	retVal = -1;

/*
 * If the response header has any Set-Cookie header fields, then
 * clear all current cookie objects from the cache and extract
 * the new one(s) from the header and cache them.
 */
	check_cookies(http);

	code = http_status_code_int(buf);
	_log("got status code %d\n", code);

	http->code = code;

/*
 * With HEAD, always send back the code
 * we received. With a GET, we will follow
 * redirects and resend the request
 * transparently.
 */ 
	if (HEAD == http->verb)
		goto out_dealloc;

	if (HTTP_OK != code)
	{
		char *__eoh = HTTP_EOH(&http->conn.read_buf);
		if (__eoh)
			_log("\nRESPONSE HEADER\n\n%.*s\n", (int)(__eoh - http->conn.read_buf.buf_head), http->conn.read_buf.buf_head);
	}

/*
 * Check for a URL redirect status code.
 */
	switch((unsigned int)code)
	{
		case HTTP_OK:
			break;
		case HTTP_FOUND:
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_SEE_OTHER:
/*
 * Cache the URL that caused the redirect.
 */
			memcpy((void *)tmpURL, (void *)http->URL, strlen(http->URL));

			if (set_new_location(http) < 0)
			{
				_log("set_new__location() returned < 0\n");
				goto fail_dealloc;
			}

			HTTP_cache_redirected_link(http, tmpURL, http->URL);
			buf_clear(&http->conn.write_buf);
			assert(http_wbuf(http).data_len == 0);
			set_verb(http, GET);

			if (http->ops->send_request(http) < 0)
			{
				_log("failed to resend GET request after setting new Location\n");
				goto fail_dealloc;
			}

			goto __retry;
			break;
		case HTTP_BAD_REQUEST: // cache as dead link for timebeing.
		case HTTP_NOT_FOUND:
			HTTP_cache_dead_link(http, http->URL, code);
		default:
			break;
	}

	if (http->ops->fetch_header(&http->conn.read_buf, "Transfer-Encoding", transfer_enc, (off_t)0))
	{
		if (!strncasecmp("chunked", transfer_enc->value, transfer_enc->vlen))
		{
			if (do_chunked_recv(http) == -1)
			{
				_log("do_chunked_recv() returned -1\n");
				goto fail_dealloc;
			}

			goto out_dealloc;
		}
	}

	if (http->ops->fetch_header(buf, "Content-Length", content_len, (off_t)0))
	{
		clen = strtoul(content_len->value, NULL, 0);

		overread = (buf->buf_tail - p);

		if (overread < clen)
		{
			clen -= overread;

			while (clen)
			{
				if (option_set(OPT_USE_TLS))
					bytes = buf_read_tls(http_tls(http), buf, clen);
				else
					bytes = buf_read_socket(http_socket(http), buf, clen);

				if (bytes < 0)
				{
					_log("buf_read_[tls/socket]() returned %d\n", retVal);
					goto fail_dealloc;
				}
				else
				if (!bytes)
				{
					continue;	
				}
				else
				{
					total_bytes += (int)bytes;
					clen -= bytes;
				}
			}
		}
	}
	else
	{
		_log("No Content-Length or chunked transfer encoding header fields");
		total_bytes = 0;
	}
/*
 * We shouldn't really get here, because we SHOULD
 * be getting a Content-Length header and if not
 * it would surely be sent chunked.
 *
 * The question is: should we really have this code
 * here or should we return an error given the
 * above...?
 *
	read_again:

		bytes = 0;
		p = NULL;

		if (option_set(OPT_USE_TLS))
			bytes = buf_read_tls(http_tls(http), buf, 0);
		else
			bytes = buf_read_socket(http_socket(http), buf, 0);

		if (bytes < 0)
		{
			_log("buf_read_[tls/socket]() returned < 0 (reading with no content length)\n");
			goto fail_dealloc;
		}

		total_bytes += (int)bytes;

		p = strstr(buf->buf_head, "</body");

		if (!p)
		{
			goto read_again;
		}
	}
*/

out_dealloc:
	cache_dealloc(private->headers, (void *)content_len, &content_len);
	cache_dealloc(private->headers, (void *)transfer_enc, &transfer_enc);

	return total_bytes;

fail_dealloc:
	if (content_len)
	{
		cache_dealloc(private->headers, (void *)content_len, &content_len);
	}

	if (transfer_enc)
	{
		cache_dealloc(private->headers, (void *)transfer_enc, &transfer_enc);
	}

fail:
	return -1;
}

/**
 * Return the HTTP code in the response header (200, 404...)
 *
 * @buf The buffer holding the web server's response.
 */
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
code_as_string(struct http_t *http)
{
	assert(http);

	//char code_string[64];

	switch((unsigned int)http->code)
	{
		case HTTP_OK:
			//sprintf(code_string, "%s%u OK%s", COL_DARKGREEN, HTTP_OK, COL_END);
			return "200 OK";
			break;
		case HTTP_MOVED_PERMANENTLY:
			//sprintf(code_string, "%s%u Moved Permanently%s", COL_ORANGE, HTTP_MOVED_PERMANENTLY, COL_END);
			return "301 Moved permanently";
			break;
		case HTTP_FOUND:
			//sprintf(code_string, "%s%u Found%s", COL_ORANGE, HTTP_FOUND, COL_END);
			return "302 Found";
			break;
		case HTTP_SEE_OTHER:
			//sprintf(code_string, "%s%u See Other%s", COL_ORANGE, HTTP_SEE_OTHER, COL_END);
			break;
		case HTTP_BAD_REQUEST:
			//sprintf(code_string, "%s%u Bad Request%s", COL_RED, HTTP_BAD_REQUEST, COL_END);
			return "400 Bad request";
			break;
		case HTTP_UNAUTHORISED:
			//sprintf(code_string, "%s%u Unauthorised%s", COL_RED, HTTP_UNAUTHORISED, COL_END);
			return "401 Unauthorised";
			break;
		case HTTP_FORBIDDEN:
			//sprintf(code_string, "%s%u Forbidden%s", COL_RED, HTTP_FORBIDDEN, COL_END);
			//return code_string;
			return "403 Forbidden";
			break;
		case HTTP_NOT_FOUND:
			//sprintf(code_string, "%s%u Not Found%s", COL_RED, HTTP_NOT_FOUND, COL_END);
			return "404 Not found";
			break;
		case HTTP_METHOD_NOT_ALLOWED:
			//sprintf(code_string, "%s%u Method Not Allowed%s", COL_RED, HTTP_METHOD_NOT_ALLOWED, COL_END);
			return "Method Not Allowed";
			break;
		case HTTP_REQUEST_TIMEOUT:
			//sprintf(code_string, "%s%u Request Timeout%s", COL_RED, HTTP_REQUEST_TIMEOUT, COL_END);
			return "408 Request timeout";
			break;
		case HTTP_INTERNAL_ERROR:
			//sprintf(code_string, "%s%u Internal Server Error%s", COL_RED, HTTP_INTERNAL_ERROR, COL_END);
			return "500 Internal server error";
			break;
		case HTTP_BAD_GATEWAY:
			//sprintf(code_string, "%s%u Bad Gateway%s", COL_RED, HTTP_BAD_GATEWAY, COL_END);
			return "502 Bad gateway";
			break;
		case HTTP_SERVICE_UNAV:
			//sprintf(code_string, "%s%u Service Unavailable%s", COL_RED, HTTP_SERVICE_UNAV, COL_END);
			return "503 Service unavailable";
			break;
		case HTTP_GATEWAY_TIMEOUT:
			//sprintf(code_string, "%s%u Gateway Timeout%s", COL_RED, HTTP_GATEWAY_TIMEOUT, COL_END);
			return "504 Gateway timeout";
			break;
		//case HTTP_ALREADY_EXISTS:
			//sprintf(code_string, "%s%u Local Found%s", COL_DARKGREEN, HTTP_ALREADY_EXISTS, COL_END);
		//	return "0xdeadbeef Local copy already exists";
			//break;
		//case HTTP_IS_XDOMAIN:
			//sprintf(code_string, "%s%u Is XDomain%s", COL_RED, HTTP_IS_XDOMAIN, COL_END);
		//	return "
			//break;
		default:
			//sprintf(code_string, "%sUnknown (%u)%s", COL_RED, code, COL_END);
			return "Unknown";
	}

	return "Unknown";

//	return code_string;
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
URL_parse_host(char *url, char *host)
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
URL_parse_page(char *url, char *page)
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
	if (!keep_trailing_slash(nwctx))
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

	if (!q || (q + 1) == endp)
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
check_header_1_1(buf_t *buf, const char *name, off_t off, off_t *ret_off)
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

/*
#define HTTP_STATUS(b) \
({ \
	char *__p;\
	char *__q;\
	char *__eoh = HTTP_EOH((b));\
	int __st = 0;\
	__p = (b)->buf_head;\
	__q = memchr(__p, ' ', (__eoh - __p));\
	if (__q){\
		__p = ++__q;\
		__q = memchr(__p, ' ', (__eoh - __p));\
		if (__q){\
			__st = (int)strtoul(__p, &__q, 10);\
		}\
	}\
	__st;\
})

int
http_parse_header(buf_t *buf, struct http_header *head)
{
	assert(buf);
	assert(head);

	head->next = NULL;
	head->status = -1;

	char *eoh = HTTP_EOH(buf);
	struct http_field *f = NULL;

	if (!eoh)
		return -1;

	head->status = HTTP_STATUS(buf);
	if (!head->status)
		return -1;

	char *p = NULL;
	char *q = NULL;

	q = buf->buf_head;
	p = memchr(q, '\r', (eoh - q));

	if (!p)
		return -1;

	++p;

	head->field = nw_malloc(sizeof(struct http_field));
	if (!head->field)
		return -1;

	f = head->field;

	while (1)
	{
		q = memchr(p, ':', (eoh - p));
		if (!q)
			break;

		f = nw_malloc(sizeof(struct http_field));
		if (!f)
			goto fail;

		f->nlen = (q - p);
		f->name = nw_calloc(f->nlen+1, 1);
		if (!f->name)
			goto fail;

		memcpy(f->name, p, f->nlen);
		f->name[f->nlen] = 0;

		p = ++q;
		if (*p == ' ')
			++p;

		q = memchr(p, '\r', (eoh - p));
		if (!q)
			goto fail;

		f->vlen = (q - p);
		f->value = nw_calloc(f->vlen+1, 1);
		if (!f->value)
			goto fail;

		memcpy(f->value, p, f->vlen);
		f->value[f->vlen] = 0;

		f->next = NULL;
	}
}
*/

/**
 * http_get_header - find and return a line in an HTTP header
 * @buf: the buffer containing the HTTP header
 * @name: the name of the header (e.g., "Set-Cookie")
 */
char *
fetch_header_1_1(buf_t *buf, const char *name, http_header_t *hh, off_t whence)
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

/**
 * Append a new header field to the request
 * header in the buffer.
 *
 * @buf The buffer holding the outgoing request header.
 * @hh The header field object.
 */
int
append_header_1_1(buf_t *buf, http_header_t *hh)
{
	assert(buf);
	assert(hh);

	char *p;
	char *head = buf->buf_head;
	char *eoh = HTTP_EOH(buf);
	off_t poff;

	if (!eoh)
	{
		_log("http_append_header: failed to find end of header");
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

/**
 * The URL for which the next request is to be
 * made may be on a different server. We would
 * need establish a new connection in that case.
 */
void
http_check_host(struct http_t *http)
{
	assert(http);

	char old_host[HTTP_HNAME_MAX];
	struct HTTP_private *private = (struct HTTP_private *)http;

	if (!http->URL[0])
		return;

	assert(strlen(http->host) < HTTP_HNAME_MAX);
	strcpy(old_host, http->host);
	http->ops->URL_parse_host(http->URL, http->host);

	if (strcmp(http->host, old_host))
	{
		if (cache_nr_used(private->cookies) > 0)
			cache_clear_all(private->cookies);

		http_reconnect(http);
	}

	return;
}

/**
 * Check if the HTTP connection has been closed.
 *
 * XXX - Not sure about this function.
 */
int
http_connection_closed(struct http_t *http)
{
	assert(http);

	http_header_t *connection = NULL;
	buf_t *buf = &http->conn.read_buf;
	int retVal = 0;
	struct HTTP_private *private = (struct HTTP_private *)http;

	//fprintf(stderr, "allocating header obj in CONNECTION @ %p\n", &connection);

	connection = cache_alloc(private->headers, &connection);
	assert(connection);

	http->ops->fetch_header(buf, "Connection", connection, (off_t)0);

	if (connection->value[0])
	{
		if (!strcasecmp("close", connection->value))
			retVal = 1;
	}

	//fprintf(stderr, "deallocting header obj CONNECTION @ %p\n", &connection);

	cache_dealloc(private->headers, connection, &connection);
	return retVal;
}

static int
HTTP_init_object(struct HTTP_private *private, uint64_t id)
{
	char cache_name[64];
	struct http_t *http;

/*
 * HTTP header object cache.
 */
	sprintf(cache_name, "http_header_cache-0x%lx", id);
	if (!(private->headers = cache_create(
			cache_name,
			sizeof(http_header_t),
			0,
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "HTTP_init_object: failed to create cache for HTTP header objects\n");
		goto fail;
	}

	_log("Created header cache %s\n", cache_name);

/*
 * HTTP cookie object cache.
 */
	sprintf(cache_name, "http_cookie_cache-0x%lx", id);
	if (!(private->cookies = cache_create(
			cache_name,
			sizeof(http_header_t),
			0,
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "HTTP_init_object: failed to create cache for HTTP cookie objects\n");
		goto fail_destroy_cache;
	}

	_log("Created cookies cache %s\n", cache_name);

/*
 * Dead link object cache.
 *
 * XXX
 *
 *	This should be a global cache so
 *	that all threads can see and share
 *	any dead links they found on a page.
 */
	sprintf(cache_name, "http_dead_link_cache-0x%lx", id);
	if (!(private->deadLinks = cache_create(
			cache_name,
			sizeof(http_dead_link_t),
			0,
			http_dead_link_cache_ctor,
			http_dead_link_cache_dtor)));

	_log("Created dead link cache %s\n", cache_name);

/*
 * Redirected links cache
 *
 * XXX - Should also be shared by threads.
 */
	sprintf(cache_name, "http_redirected_link_cache-0x%lx", id);
	if (!(private->redirectedLinks = cache_create(
			cache_name,
			sizeof(http_redirected_t),
			0,
			http_redirected_cache_ctor,
			http_redirected_cache_dtor)));

	_log("Created redirected link cache %s\n", cache_name);

	http = (struct http_t *)private;

	http->host = calloc(HTTP_HOST_MAX+1, 1);
	http->conn.host_ipv4 = calloc(HTTP_ALIGN_SIZE(INET_ADDRSTRLEN+1), 1);
	http->primary_host = calloc(HTTP_HOST_MAX+1, 1);
	http->page = calloc(HTTP_URL_MAX+1, 1);
	http->URL = calloc(HTTP_URL_MAX+1, 1);
	http->ops = &Methods_v1_1;
	http->version = HTTP_VERSION_1_1;

	if (buf_init(&http->conn.read_buf, HTTP_DEFAULT_READ_BUF_SIZE) < 0)
	{
		fprintf(stderr, "HTTP_init_object: failed to initialise read buf\n");
		goto fail_destroy_cache;
	}

	if (buf_init(&http->conn.write_buf, HTTP_DEFAULT_WRITE_BUF_SIZE) < 0)
	{
		fprintf(stderr, "HTTP_init_object: failed to initialise write buf\n");
		goto fail_release_mem;
	}

	assert(http->host);
	assert(http->conn.host_ipv4);
	assert(http->primary_host);
	assert(http->page);
	assert(http->URL);

	return 0;

fail_release_mem:

	buf_destroy(&http->conn.read_buf);

fail_destroy_cache:

	cache_destroy(private->headers);
	cache_destroy(private->cookies);
	cache_destroy(private->deadLinks);
	cache_destroy(private->redirectedLinks);

fail:
	return -1;
}

/**
 * Create a new HTTP object instance.
 *
 * @id The id to identify the object (e.g., thread ID)
 */
struct http_t *
HTTP_new(uint64_t id)
{
	struct HTTP_private *private = malloc(sizeof(struct HTTP_private));

	if (!private)
	{
		_log("http_new: failed to allocate memory for new HTTP object\n");
		goto fail;
	}

	if (HTTP_init_object(private, id) < 0)
	{
		_log("http_new: failed to initialise HTTP object\n");
		goto fail;
	}

	_log("Created HTTP object @ %p\n", private);
	return (struct http_t *)private;

fail:
	return NULL;
}

void
HTTP_delete(struct http_t *http)
{
	assert(http);

	struct HTTP_private *private = (struct HTTP_private *)http;

	free(http->host);
	free(http->page);
	free(http->primary_host);
	free(http->conn.host_ipv4);
	free(http->URL);

	cache_clear_all(private->headers);
	cache_destroy(private->headers);

	cache_clear_all(private->cookies);
	cache_destroy(private->cookies);

	cache_clear_all(private->deadLinks);
	cache_destroy(private->deadLinks);

	cache_clear_all(private->redirectedLinks);
	cache_destroy(private->redirectedLinks);

	buf_destroy(&http->conn.read_buf);
	buf_destroy(&http->conn.write_buf);

	_log("Deleted HTTP object\n");

	return;
}
