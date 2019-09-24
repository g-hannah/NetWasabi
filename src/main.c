#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "utils_url.h"
#include "webreaper.h"

#define CRAWL_DELAY 3
#define CRAWL_DEPTH 50
#define NR_LINKS_THRESHOLD 500
#define MAX_TIME_WAIT 8
#define MAX_FAILS 10
#define RESET_DELAY 3

static sigset_t oldset;
static sigset_t newset;

#define BLOCK_SIGNAL(signal)\
do {\
	sigemptyset(&newset);\
	sigaddset(&newset, (signal));\
	sigprocmask(SIG_BLOCK, &newset, &oldset);\
} while (0)

#define UNBLOCK_SIGNAL(signal) sigprocmask(SIG_SETMASK, &oldset, NULL)

#if 0
static sigjmp_buf __ICL_TIMEOUT__;

static void __handle_icl_timeout(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__ICL_TIMEOUT__, 1);
}
#endif

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global variables.
 */
uint32_t runtime_options = 0;
wr_cache_t *http_hcache;
wr_cache_t *http_lcache;
wr_cache_t *http_lcache2;
wr_cache_t *cookies;
int TRAILING_SLASH = 0;
size_t httplen;
size_t httpslen;
char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;
volatile int cache_switch = 0;
static int nr_reaped = 0;
static int depth = 0;
http_link_t *cache1_url_root;
http_link_t *cache2_url_root;

struct url_types url_types[] =
{
	{ "href=\"", '"', 6 },
	{ "HREF=\"", '"', 6 },
	{ "src=\"", '"', 5 },
	{ "SRC=\"", '"', 5 },
	{ "href=\'", '\'', 6 },
	{ "HREF=\'", '\'', 6 },
	{ "src=\'", '\'', 5 },
	{ "SRC=\'", '\'', 5 },
	{ "", 0, 0 }
};

/*
 * When using one ptr var to assign cache objects in a loop
 * without concern for keeping a pointer to each object, we
 * MUST use these global ones to do it. The cache implementation
 * keeps a list of pointers pointing to cache objects. If the
 * cache is moved to a new location on the heap after a realloc,
 * the address of the cache object held at the address of these
 * pointers is updated with the new address of their cache
 * object.
 *
 * This won't work in a case where we assigned many in a loop,
 * and then the local object ptr that was allocated on the stack
 * goes out of scope because we returned from the function.
 */
http_header_t **hh_loop;
http_link_t **hl_loop;
struct http_cookie_t **hc_loop;

static int REAP_DEPTH = UINT_MAX; /* default = infinite */

int path_max = 1024;

static void
__ctor __wr_init(void)
{
	path_max = pathconf("/", _PC_PATH_MAX);

	if (!path_max)
		path_max = 1024;

	hh_loop = malloc(sizeof(http_header_t *));
	hl_loop = malloc(sizeof(http_link_t *));
	hc_loop = malloc(sizeof(struct http_cookie_t *));

	assert(hh_loop);
	assert(hl_loop);
	assert(hc_loop);

	httplen = strlen("http://");
	httpslen = strlen("https://");

	return;
}

static void
__dtor __wr_fini(void)
{
	if (hh_loop)
		free(hh_loop);

	if (hl_loop)
		free(hl_loop);

	if (hc_loop)
		free(hc_loop);
}

/*
 * Catch SIGINT
 */
sigjmp_buf main_env;
struct sigaction new_act;
struct sigaction old_sigint;
struct sigaction old_sigquit;

static void
__noret usage(int exit_status)
{
	fprintf(stderr,
		"webreaper <url> [options]\n\n"
		"-T/--tls          use a TLS connection\n"
		"-oH/--req-head    show the request header (\"out header\")\n"
		"-iH/--res-head    show the response header (\"in header\")\n"
		"-D/--depth        maximum depth (#pages from which to extract URLs)\n"
		"-X/--xdomain      follow URLs into other domains\n"
		"-B/--blacklist    blacklist tokens in URLs\n"
		"--help/-h         display this information\n");

	exit(exit_status);
}

static void
__print_prog_info(void)
{
	fprintf(stdout,
		"WebReaper v%s\n"
		"Written by Gary Hannah\n\n",
		WEBREAPER_BUILD);

	return;
}

static void
__extract_cookie_info(struct http_cookie_t *dest, http_header_t *src)
{
	assert(dest);
	assert(src);

	strncpy(dest->data, src->value, src->vlen);
	dest->data[src->vlen] = 0;
	dest->data_len = src->vlen;

	char *p;
	char *e;
	char *start = dest->data;
	size_t data_len = dest->data_len;

/*
 * Some cookie values do not end with ';' but instead end with '\r\n'.
 * \r\n is not included in the http_header_t->value, so if no ';', just
 * go to the null byte.
 */

	p = strstr(start, "path");

	if (p)
	{
		p += strlen("path=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->path, p, (e - p));
		dest->path_len = (e - p);
		dest->path[dest->path_len] = 0;
	}
	else
	{
		dest->path[0] = 0;
	}

	p = strstr(start, "domain");

	if (p)	
	{
		p += strlen("domain=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->domain, p, (e - p));
		dest->domain_len = (e - p);
		dest->domain[dest->domain_len] = 0;
	}
	else
	{
		dest->domain[0] = 0;
	}

	p = strstr(start, "expires");

	if (p)
	{
		p += strlen("expires=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->expires, p, (e - p));
		dest->expires_len = (e - p);
		dest->expires[dest->expires_len] = 0;
	}
	else
	{
		dest->expires[0] = 0;
	}

	dest->expires_ts = (time(NULL) + ((time_t)86400 * 7));

	return;
}

/**
 * __check_cookies - check for Set-Cookie headers; extract and append to outgoing header if any
 * @conn: struct holding connection context
 */
static void
__check_cookies(connection_t *conn)
{
	assert(conn);

	off_t offset = 0;
	struct http_cookie_t *cookie = NULL;
	http_header_t *tmp;

#ifdef DEBUG
	fprintf(stderr, "allocating header obj to TMP @ %p\n", &tmp);
#endif
	tmp = (http_header_t *)wr_cache_alloc(http_hcache, &tmp);

	/*
	 * If there is a Set-Cookie header, then clear all
	 * previously-cached cookies. Otherwise, if no such
	 * header and we have cached cookies, append them
	 * to the buffer. Otherwise, do nothing.
	 */
	if (http_check_header(&conn->read_buf, "Set-Cookie", (off_t)0, &offset))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		offset = 0;

		while(http_check_header(&conn->read_buf, "Set-Cookie", offset, &offset))
		{
			http_fetch_header(&conn->read_buf, "Set-Cookie", tmp, offset);

			if (!tmp->name[0] && !tmp->value[0])
			{
				fprintf(stderr, "%sEMPTY VALUES FOR COOKIE FROM HEADER...%s\n", COL_ORANGE, COL_END);
				break;
			}

			http_append_header(&conn->write_buf, tmp);

#ifdef DEBUG
			fprintf(stderr, "allocating cookie obj to HC_LOOP @ %p\n", hc_loop);
#endif
			*hc_loop = (struct http_cookie_t *)wr_cache_alloc(cookies, hc_loop);

			__extract_cookie_info(*hc_loop, tmp);

			++offset;
		}
	}
	else
	{
		int nr_used = wr_cache_nr_used(cookies);
		int i;

		if (!nr_used)
			goto out_dealloc;

		cookie = (struct http_cookie_t *)cookies->cache;

		for (i = 0; i < nr_used; ++i)
		{
			while (!wr_cache_obj_used(cookies, (void *)cookie))
				++cookie;

#if 0
			if (__cookie_expired(cookie))
			{
				printf("cookie \"%s\" expired\n", cookie->data);
				wr_cache_dealloc(cookies, (void *)cookie);
				++cookie;
			}
#endif

			strncpy(tmp->value, cookie->data, cookie->data_len);
			tmp->value[cookie->data_len] = 0;
			tmp->vlen = cookie->data_len;
			strcpy(tmp->name, "Cookie");

			http_append_header(&conn->write_buf, tmp);

			++cookie;
		}
	}

	out_dealloc:
#ifdef DEBUG
	fprintf(stderr, "deallocating header object TMP @ %p\n", &tmp);
#endif
	wr_cache_dealloc(http_hcache, (void *)tmp, &tmp);

	return;
}

static int
__connection_closed(connection_t *conn)
{
	assert(conn);

	http_header_t *connection;
	buf_t *buf = &conn->read_buf;
	int rv = 0;

#ifdef DEBUG
	fprintf(stderr, "allocating header obj in CONNECTION @ %p\n", &connection);
#endif

	connection = wr_cache_alloc(http_hcache, &connection);
	assert(connection);

	http_fetch_header(buf, "Connection", connection, (off_t)0);

	if (connection->value[0])
	{
		if (strncasecmp("keep-alive", connection->value, connection->vlen))
			rv = 1;
	}

#ifdef DEBUG
	fprintf(stderr, "deallocting header obj CONNECTION @ %p\n", &connection);
#endif

	wr_cache_dealloc(http_hcache, connection, &connection);
	return rv;
}

static void
__show_request_header(buf_t *buf)
{
	assert(buf);

	fprintf(stderr, "%s%s%s", COL_RED, buf->buf_head, COL_END);
	return;
}

static void
__show_response_header(buf_t *buf)
{
	assert(buf);

	char *p = HTTP_EOH(buf);

	if (!p)
	{
		fprintf(stderr, "__show_response_header: failed to find end of HTTP header\n");
		fprintf(stderr, "%s", buf->buf_head);
		
		errno = EPROTO;
		return;
	}

	fprintf(stderr, "%s%.*s%s", COL_RED, (int)(p - buf->buf_head), buf->buf_head, COL_END);

	return;
}

static void
__check_host(connection_t *conn)
{
	assert(conn);

	static char old_host[HTTP_HNAME_MAX];

	if (!conn->full_url[0])
		return;

	assert(strlen(conn->host) < HTTP_HNAME_MAX);
	strcpy(old_host, conn->host);
	http_parse_host(conn->full_url, conn->host);

	if (strcmp(conn->host, old_host))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		fprintf(stdout,
			"%sChanging host (%s ==> %s)\n"
			"(URL: %s)\n",
			ACTION_ING_STR, old_host, conn->host,
			conn->full_url);

		reconnect(conn);
	}

	return;
}

static int
__send_head_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	__check_host(conn);

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

	__check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (option_set(OPT_SHOW_REQ_HEADER))
		__show_request_header(wbuf);

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	if (option_set(OPT_SHOW_RES_HEADER))
		__show_response_header(rbuf);

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

static int
__send_get_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	__check_host(conn);

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

	__check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (option_set(OPT_SHOW_REQ_HEADER))
		__show_request_header(wbuf);

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	if (option_set(OPT_SHOW_RES_HEADER))
		__show_response_header(rbuf);

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

#if 0
static void
__normalise_filename(char *filename)
{
	char *p = filename;
	size_t len = strlen(filename);
	char *end = (filename + len);
	buf_t tmp;

	clear_struct(&tmp);
	buf_init(&tmp, len);

	buf_append(&tmp, filename);

	if (!strncmp("http", tmp.buf_head, 4))
	{
		p = (tmp.buf_head + strlen("http://"));

		if (*p == '/')
			++p;

		buf_collapse(&tmp, (off_t)0, (p - tmp.buf_head));
	}

	p = tmp.buf_head;
	end = tmp.buf_tail;

	while (p < end)
	{
		if (*p == 0x20)
		{
			*p++ = 0x5f;

			if (*(p-2) == 0x5f)
			{
				--p;
				buf_collapse(&tmp, (off_t)(p - tmp.buf_head), (size_t)1);
				end = tmp.buf_tail;
			}

			continue;
		}

		++p;
	}

	buf_append(&tmp, ".html");

	strncpy(filename, tmp.buf_head, tmp.data_len);
	filename[tmp.data_len] = 0;

	buf_destroy(&tmp);

	return;
}
#endif

static int
__check_local_dirs(connection_t *conn, buf_t *filename)
{
	assert(conn);
	assert(filename);

	char *p;
	char *e;
	char *end;
	char *name = filename->buf_head;
	buf_t _tmp;

	buf_init(&_tmp, pathconf("/", _PC_PATH_MAX));

	if (*(filename->buf_tail - 1) == '/')
		buf_snip(filename, 1);

	end = filename->buf_tail;
	p = strstr(name, WEBREAPER_DIR);

	if (!p)
	{
		fprintf(stderr, "__check_local_dirs: failed to find webreaper directory in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	e = ++p;

	e = memchr(p, '/', (end - p));

	if (!e)
	{
		fprintf(stderr, "__check_local_dirs: failed to find necessary '/' character in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	p = ++e;

/*
 * e.g. /home/johndoe/WR_Reaped/favourite-site.com/categories/best-rated
 *                              ^start here, work along to end, checking
 * creating a directory for each part if necessary.
 */

	while (e < end)
	{
		e = memchr(p, '/', (end - p));

		if (!e) /* The rest of the filename is the file itself */
		{
			break;
		}

		buf_append_ex(&_tmp, name, (e - name));
		BUF_NULL_TERMINATE(&_tmp);

		if(access(_tmp.buf_head, F_OK) != 0)
		{
			mkdir(_tmp.buf_head, S_IRWXU);
			fprintf(stdout, "%sCreated local dir %s\n", ACTION_DONE_STR, _tmp.buf_head);
		}

		p = ++e;
		buf_clear(&_tmp);
	}

	buf_destroy(&_tmp);
	return 0;
}

static void
__replace_with_local_urls(connection_t *conn, buf_t *buf)
{
	assert(conn);
	assert(buf);

	char *tail = buf->buf_tail;
	char *p;
	char *savep;
	char *url_start;
	char *url_end;
	off_t url_start_off;
	off_t url_end_off;
	off_t savep_off;
	off_t poff;
	size_t range;
	buf_t url;
	buf_t path;
	buf_t full;
	int url_type_idx;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&path, HTTP_URL_MAX);
	buf_init(&full, HTTP_URL_MAX);

#define save_pointers()\
do {\
	savep_off = (savep - buf->buf_head);\
	poff = (savep - buf->buf_head);\
	url_start_off = (url_start - buf->buf_head);\
	url_end_off = (url_end - buf->buf_head);\
} while (0)

#define restore_pointers()\
do {\
	savep = (buf->buf_head + savep_off);\
	p = (buf->buf_head + poff);\
	url_start = (buf->buf_head + url_start_off);\
	url_end = (buf->buf_head + url_end_off);\
} while (0)

	savep = buf->buf_head;
	url_type_idx = 0;

	while (1)
	{
		buf_clear(&url);

		assert(buf->buf_tail <= buf->buf_end);
		assert(buf->buf_head >= buf->data);

		p = strstr(savep, url_types[url_type_idx].string);

		if (!p || p >= tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_start = (p += url_types[url_type_idx].len);
		url_end = memchr(url_start, url_types[url_type_idx].delim, (tail - url_start));

		if (!url_end)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		assert(buf->buf_tail <= buf->buf_end);
		assert(url_start < buf->buf_tail);
		assert(url_end < buf->buf_tail);
		assert(p < buf->buf_tail);
		assert(savep < buf->buf_tail);
		assert((tail - buf->buf_head) == (buf->buf_tail - buf->buf_head));

		range = (url_end - url_start);

		if (!range)
		{
			++savep;
			continue;
		}

		if (!strncmp("http://", url_start, range) || !strncmp("https://", url_start, range))
		{
			savep = ++url_end;
			continue;
		}

		if (range >= HTTP_URL_MAX)
		{
			savep = ++url_end;
			continue;
		}

		assert(range < HTTP_URL_MAX);

		buf_append_ex(&url, url_start, range);
		BUF_NULL_TERMINATE(&url);

		if (range)
		{
			//fprintf(stderr, "turning %s into full url\n", url.buf_head);
			make_full_url(conn, &url, &full);
			//fprintf(stderr, "made %s\n", full.buf_head);

			if (make_local_url(conn, &full, &path) == 0)
			{
				//fprintf(stderr, "made local url %s\n", path.buf_head);
				buf_collapse(buf, (off_t)(url_start - buf->buf_head), range);
				tail = buf->buf_tail;

				save_pointers();

				assert(path.data_len < path_max);
				buf_shift(buf, (off_t)(url_start - buf->buf_head), path.data_len);

				restore_pointers();
				tail = buf->buf_tail;

				assert((url_start - buf->buf_head) == url_start_off);
				assert((url_end - buf->buf_head) == url_end_off);
				assert((p - buf->buf_head) == poff);
				assert((savep - buf->buf_head) == savep_off);

				strncpy(url_start, path.buf_head, path.data_len);
			}
		}

		assert(url.magic == BUFFER_MAGIC);
		assert(full.magic == BUFFER_MAGIC);
		assert(path.magic == BUFFER_MAGIC);

		savep = ++url_end;

		if (savep >= tail)
			break;
	}
}

static int
__archive_page(connection_t *conn)
{
	int fd = -1;
	buf_t *buf = &conn->read_buf;
	buf_t tmp;
	buf_t local_url;
	char *p;
	int rv;

	p = HTTP_EOH(buf);

	if (p)
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));

	__replace_with_local_urls(conn, buf);

	buf_init(&tmp, HTTP_URL_MAX);
	buf_init(&local_url, 1024);

	buf_append(&tmp, conn->full_url);
	make_local_url(conn, &tmp, &local_url);

/* Now we have "file:///path/to/file.extension" */
	buf_collapse(&local_url, (off_t)0, strlen("file://"));

	rv = __check_local_dirs(conn, &local_url);

	if (rv < 0)
		goto fail_free_bufs;

	if (access(local_url.buf_head, F_OK) == 0)
	{
		fprintf(stdout, "%s%sAlready archived %s%s\n", COL_RED, ATTENTION_STR, local_url.buf_head, COL_END);
		goto out_free_bufs;
	}

	fd = open(local_url.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd == -1)
	{
		fprintf(stderr, "__archive_page: failed to create file %s (%s)\n", local_url.buf_head, strerror(errno));
		goto fail_free_bufs;
	}

	fprintf(stdout, "%sCreated file %s\n", ACTION_DONE_STR, local_url.buf_head);
	++nr_reaped;

	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

	out_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return 0;

	fail_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return -1;
}

/**
 * __handle301 - handle 301 Moved Permanently
 * @conn: struct holding connection context
 */
static int
__handle301(connection_t *conn)
{
	http_header_t *location = NULL;
	buf_t tmp_url;
	buf_t tmp_full;

#ifdef DEBUG
	fprintf(stderr, "allocating header obj LOCATION @ %p\n", &location);
#endif

	location = (http_header_t *)wr_cache_alloc(http_hcache, &location);
	http_fetch_header(&conn->read_buf, "Location", location, (off_t)0);

	fprintf(stdout, "%sRedirecting to %s%s%s\n", ACTION_ING_STR, COL_ORANGE, location->value, COL_END);

	assert(location->vlen < HTTP_URL_MAX);

	if (location->value[location->vlen - 1] == '/')
		TRAILING_SLASH = 1;

	if (strncmp("http://", location->value, 7) && strncmp("https://", location->value, 8))
	{
		buf_init(&tmp_url, HTTP_URL_MAX);
		buf_init(&tmp_full, HTTP_URL_MAX);

		buf_append(&tmp_url, location->value);
		make_full_url(conn, &tmp_url, &tmp_full);

		http_parse_host(tmp_full.buf_head, conn->host);
		http_parse_page(tmp_full.buf_head, conn->page);
		strncpy(conn->full_url, tmp_full.buf_head, tmp_full.data_len);
		conn->full_url[tmp_full.data_len] = 0;

		buf_destroy(&tmp_url);
		buf_destroy(&tmp_full);
	}
	else
	{
		http_parse_host(location->value, conn->host);
		http_parse_page(conn->full_url, conn->page);

		strncpy(conn->full_url, location->value, location->vlen);
		conn->full_url[location->vlen] = 0;
	}

	assert(!memchr(conn->host, '/', strlen(conn->host)));

#ifdef DEBUG
	fprintf(stderr, "deallocating header obj LOCATION @ %p\n", &location);
#endif

	wr_cache_dealloc(http_hcache, (void *)location, &location);

	if (!strncmp("https", conn->full_url, 5))
	{
		if (!option_set(OPT_USE_TLS))
			conn_switch_to_tls(conn);
	}

	return 0;
}

static int
__do_request(connection_t *conn)
{
	assert(conn);

	int status_code = 0;

	if (local_archive_exists(conn->full_url))
		return HTTP_ALREADY_EXISTS;
	/*
	 * Save bandwidth: send HEAD first.
	 */
	resend_head:
	status_code = __send_head_request(conn);

#if 0
	fprintf(stderr,
		"__do_request():\n\n"
		"full_url=%s\n"
		"page=%s\n"
		"host=%s\n"
		"primary_host=%s\n",
		conn->full_url,
		conn->page,
		conn->host,
		conn->primary_host);

	fprintf(stdout, "%s [HEAD] %s (%s)\n", ACTION_ING_STR, http_status_code_string(status_code), conn->full_url);
#endif

	switch(status_code)
	{
		case HTTP_FOUND:
		case HTTP_MOVED_PERMANENTLY:
			__handle301(conn);
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

	/*
	 * We only get here if 200 OK.
	 *
	 * With a HEAD request, the web server
	 * terminates the connection since
	 * only metadata is being requested.
	 */
	if (__connection_closed(conn))
	{
		fprintf(stdout, "%s%sRemote peer closed connection%s\n", COL_RED, ACTION_DONE_STR, COL_END);
		__show_response_header(&conn->read_buf);
		reconnect(conn);
	}

	status_code &= ~status_code;

	status_code = __send_get_request(conn);

	return status_code;
}

char *no_url_files[] =
{
	".jpg",
	".jpeg",
	".png",
	".gif",
	".js",
	".css",
	".pdf",
	".svg",
	".ico",
	NULL
};

static int
__url_parseable(char *url)
{
	int i;

	for (i = 0; no_url_files[i] != NULL; ++i)
	{
		if (strstr(url, no_url_files[i]))
			return 0;
	}

	return 1;
}

static void
deconstruct_btree(http_link_t *root)
{
	if (!root)
	{
		fprintf(stderr, "deconstruct_btree: root is NULL\n");
		return;
	}

	if (root->left)
	{
		fprintf(stderr, "Going left from %p to %p\n", root, root->left);
		deconstruct_btree(root->left);
	}

	if (root->right)
	{
		fprintf(stderr, "Going right from %p to %p\n", root, root->right);
		deconstruct_btree(root->right);
	}

	fprintf(stderr, "Setting left and right to NULL in node %p\n", root);
	root->left = NULL;
	root->right = NULL;

	return;
}

/**
 * reap - archive the pages in the link cache,
 *    choose one at random and return that choice. That will be
 *    our next page from which to parse links.
 * @cachep: the cache of parsed links
 * @conn: our struct with connection context
 */
static int
reap(wr_cache_t *cachep, wr_cache_t *cachep2, connection_t *conn)
{
	assert(cachep);
	assert(cachep2);
	assert(conn);

	int nr_links = 0;
	int nr_links_sibling;
	int fill = 1;
	int status_code = 0;
	int i;
	size_t len;
	http_link_t *link;
	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
#if 0
	struct sigaction it_nact;
	struct sigaction it_oact;
	sigjmp_buf __ICL_TIMEOUT__;
#endif

	TRAILING_SLASH = 0;
/*
 * As we archive the pages from URLs stored in one cache,
 * we fill the sibling cache with URLs to follow in the next
 * iteration of the while loop. We use the CACHE_SWITCH flag
 * for using one while filling the other. Fill until we pass
 * a threshold number of URLs we wish to have for archiving
 * next. Stop filling when FILL == 0.
 *
 * Base case for the loop is our 'crawl depth' being equal
 * to CRAWL_DEPTH (#iterations of while loop).
 */

#if 0
	clear_struct(&it_nact);
	clear_struct(&it_oact);
	it_nact.sa_flags = 0;
	it_nact.sa_handler = __handle_icl_timeout;
	sigemptyset(&it_nact.sa_mask);
	if (sigaction(SIGALRM, &it_nact, &it_oact) < 0)
	{
		fprintf(stderr, "reap: failed to set signal handler for SIGALRM\n");
		goto fail;
	}

	if (sigsetjmp(__ICL_TIMEOUT__, 0) != 0)
	{
		fprintf(stderr, "%s%sTimed out getting %s%s\n", COL_RED, ATTENTION_STR, conn->full_url, COL_END);

		buf_clear(rbuf);
		buf_clear(wbuf);

		return FL_RESET;
	}
#endif

	if (!wr_cache_nr_used(cachep))
		cache_switch = 1;
	else
		cache_switch = 0;


while (1)
{
	fprintf(stderr,
		"Cache 1 is at %p\n"
		"Cache 2 is at %p\n",
		cache1_url_root,
		cache2_url_root);

	if (!cache_switch)
	{
		link = (http_link_t *)cachep->cache;
		nr_links = wr_cache_nr_used(cachep);

		fprintf(stderr, "Draining %d URLs in cache 1 -- filling cache 2\n", nr_links);

		fprintf(stderr, "Deconstructing binary tree in cache 2\n");
		deconstruct_btree(cache2_url_root);

		wr_cache_clear_all(cachep2);

		cache2_url_root = NULL;
		
	}
	else
	{
		link = (http_link_t *)cachep2->cache;
		nr_links = wr_cache_nr_used(cachep2);

		fprintf(stderr, "Draining %d URLs in cache 2 -- filling cache 1\n", nr_links);

		fprintf(stderr, "Deconstructing binary tree in cache 1\n");
		deconstruct_btree(cache1_url_root);

		if (wr_cache_nr_used(cachep) > 0)
			wr_cache_clear_all(cachep);

		cache1_url_root = NULL;
	}

	if (!nr_links)
		break;

	fill = 1;

	for (i = 0; i < nr_links; ++i)
	{
		buf_clear(wbuf);
		len = strlen(link->url);

		if (!len)
		{
			++link;
			continue;
		}

		assert(len < HTTP_URL_MAX);

		strncpy(conn->full_url, link->url, len);
		conn->full_url[len] = 0;

		if (!http_parse_page(conn->full_url, conn->page))
			continue;

		BLOCK_SIGNAL(SIGINT);
		sleep(CRAWL_DELAY);
		UNBLOCK_SIGNAL(SIGINT);

		__check_host(conn);

		resend:
		if (link->nr_requests > 2) /* loop */
		{
			++link;
			//fprintf(stderr, "Skipping %s%s%s (infinite redirect loop)\n", COL_ORANGE, link->url, COL_END);
			continue;
		}

		fprintf(stdout, "===> %s%s%s <===\n", COL_ORANGE, conn->page, COL_END);

		status_code = __do_request(conn);

		++(link->nr_requests);

		if (FL_OPERATION_TIMEOUT != status_code)
			fprintf(stdout, "%s%s (%s)\n", ACTION_ING_STR, http_status_code_string(status_code), link->url);

		switch(status_code)
		{
			case HTTP_OK:
			case HTTP_NOT_FOUND: /* don't want to keep requesting the link and getting 404, so just archive it */
				break;
			case HTTP_MOVED_PERMANENTLY:
			/*
			 * Shouldn't get here, because __do_request() first
			 * sends a HEAD request, and handles 301/302 for us.
			 */
				__handle301(conn);
				buf_clear(wbuf);
				goto resend;
				break;
			case HTTP_BAD_REQUEST:
				__show_request_header(wbuf);

				if (wr_cache_nr_used(cookies) > 0)
					wr_cache_clear_all(cookies);

				buf_clear(wbuf);
				buf_clear(rbuf);

				reconnect(conn);

				goto next;
				break;
			case HTTP_FORBIDDEN:
			case HTTP_INTERNAL_ERROR:
			case HTTP_BAD_GATEWAY:
			case HTTP_SERVICE_UNAV:
			case HTTP_GATEWAY_TIMEOUT:
				__show_response_header(rbuf);

					if (wr_cache_nr_used(cookies) > 0)
						wr_cache_clear_all(cookies);

					buf_clear(wbuf);
					buf_clear(rbuf);

					reconnect(conn);

					goto next;
					break;
			case HTTP_ALREADY_EXISTS:
			/*
			 * Ignore 302 Found because it is used a lot for obtaining a random
			 * link, for example a random wiki article (Special:Random).
			 */
			case HTTP_FOUND:
				goto next;
			case FL_OPERATION_TIMEOUT:

				fprintf(stdout, "%s\n", rbuf->buf_head);
				buf_clear(rbuf);

				if (!conn->host[0])
					strcpy(conn->host, conn->primary_host);

				reconnect(conn);

				goto next;
				break;
			default:
				fprintf(stdout, "reap: received HTTP status code %d\n", status_code);
				goto fail;
		}

		if (fill)
		{
			if (__url_parseable(conn->full_url))
			{
				if (!cache_switch)
				{
					parse_links(cachep2, cachep, &cache2_url_root, conn);
					nr_links_sibling = wr_cache_nr_used(cachep2);
				}
				else
				{
					parse_links(cachep, cachep2, &cache1_url_root, conn);
					nr_links_sibling = wr_cache_nr_used(cachep);
				}

				if (nr_links_sibling >= NR_LINKS_THRESHOLD)
					fill = 0;
			}
		}

		fprintf(stdout, "%sArchiving %s\n", ACTION_ING_STR, conn->full_url);
		__archive_page(conn);

		next:
		++link;
		TRAILING_SLASH = 0;
	}

	++depth;

	if (cache_switch)
		cache_switch = 0;
	else
		cache_switch = 1;

	if (depth >= CRAWL_DEPTH)
		break;
}

	return 0;

	fail:
	return -1;
}

static void
catch_signal(int signo)
{
	if (signo != SIGINT && signo != SIGQUIT)
		return;

	siglongjmp(main_env, 1);
}

#if 0
static void
__dump_links(wr_cache_t *cachep)
{
	http_link_t *lp = NULL;
	int nr_used = wr_cache_nr_used(cachep);
	int i;

	lp = (http_link_t *)cachep->cache;
	for (i = 0; i < nr_used; ++i)
	{
		while (!wr_cache_obj_used(cachep, (void *)lp))
			++lp;

		printf("link>>%s\n", lp->url);
		++lp;
	}

	return;
}
#endif

static void
__check_directory(void)
{
	char *home = getenv("HOME");
	buf_t tmp;

	buf_init(&tmp, path_max);
	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR);

	if (access(tmp.buf_head, F_OK) != 0)
		mkdir(tmp.buf_head, S_IRWXU);

	buf_destroy(&tmp);

	return;
}

/*
 * ./webreaper <url> [options]
 */
int
main(int argc, char *argv[])
{
	if (argc < 2)
	{
		usage(EXIT_FAILURE);
	}

	if (get_opts(argc, argv) < 0)
	{
		fprintf(stderr, "main: failed to parse program options\n");
		goto fail;
	}

#if 0
	if (!valid_url(argv[1]))
		goto fail;
#endif

	__print_prog_info();
	srand(time(NULL));

	clear_struct(&new_act);
	clear_struct(&old_sigint);
	clear_struct(&old_sigquit);

	new_act.sa_flags = 0;
	new_act.sa_handler = catch_signal;
	sigemptyset(&new_act.sa_mask);

	if (sigaction(SIGINT, &new_act, &old_sigint) < 0)
	{
		fprintf(stderr, "main: failed to set SIGINT handler (%s)\n", strerror(errno));
		goto fail;
	}

	if (sigaction(SIGQUIT, &new_act, &old_sigquit) < 0)
	{
		fprintf(stderr, "main: failed to set SIGQUIT handler (%s)\n", strerror(errno));
		goto fail;
	}

	__check_directory();

	connection_t conn;
	int status_code;
	int do_not_archive = 0;
	int rv;
	int nr_fails = 0;
	size_t url_len;
	buf_t *rbuf = NULL;
	buf_t *wbuf = NULL;

	conn_init(&conn);

	http_parse_host(argv[1], conn.host);
	http_parse_page(argv[1], conn.page);

	url_len = strlen(argv[1]);

	assert(url_len < HTTP_URL_MAX);

	strncpy(conn.full_url, argv[1], url_len);
	conn.full_url[url_len] = 0;

	//if (conn.full_url[url_len-1] == '/')
		//conn.full_url[--url_len] = 0;

	strcpy(conn.primary_host, conn.host);

	fprintf(stdout,
		"%sReaping site %s%s%s\n",
		ACTION_ING_STR, COL_ORANGE, conn.full_url, COL_END);

	/*
	 * Initialises read/write buffers in conn.
	 */
	if (open_connection(&conn) < 0)
		goto fail;

	rbuf = &conn.read_buf;
	wbuf = &conn.write_buf;

	/*
	 * Create a new cache for http_link_t objects.
	 */
	http_lcache = wr_cache_create(
			"http_link_cache",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	http_lcache2 = wr_cache_create(
			"http_link_cache2",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	/*
	 * Create a cache for HTTP header fields.
	 */
	http_hcache = wr_cache_create(
			"http_header_field_cache",
			sizeof(http_header_t),
			0,
			wr_cache_http_header_ctor,
			wr_cache_http_header_dtor);

	/*
	 * Create a cache for cookies; separate cache because we want
	 * a different struct to separate and easily access cookie
	 * params (like domain, path, etc).
	 */
	cookies = wr_cache_create(
			"cookie_cache",
			sizeof(struct http_cookie_t),
			0,
			http_cookie_ctor,
			http_cookie_dtor);

	/*
	 * Catch SIGINT and SIGQUIT so we can release cache memory, etc.
	 */
	if (sigsetjmp(main_env, 0) != 0)
	{
		fprintf(stderr, "%c%c%c%c%c%c", 0x08, 0x20, 0x08, 0x08, 0x20, 0x08);
		fprintf(stderr, "Caught signal! Exiting!\n");
		goto out_disconnect;
	}

	buf_clear(rbuf);
	buf_clear(wbuf);

	printf(">>> %s%s%s <<<\n", COL_ORANGE, conn.page, COL_END);

	resend:
	status_code = __do_request(&conn);

	fprintf(stdout, "%s%s (%s)\n", ACTION_ING_STR, http_status_code_string(status_code), conn.full_url);

	switch(status_code)
	{
		case HTTP_OK:
			break;
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_FOUND:
			__handle301(&conn);
			goto resend;
			break;
		case HTTP_ALREADY_EXISTS:
			do_not_archive = 1;
			__send_get_request(&conn); /* in this case we still need to get it to extract URLs */
			break;
		case HTTP_BAD_REQUEST:
		case HTTP_FORBIDDEN:
		case HTTP_GATEWAY_TIMEOUT:
		case HTTP_BAD_GATEWAY:
		case HTTP_INTERNAL_ERROR:
			__show_response_header(rbuf);
			default:
				goto out_disconnect;
		case FL_OPERATION_TIMEOUT:
			fprintf(stderr, "%sOperation timed out%s\n", COL_RED, COL_END);
			goto out_disconnect;
	}

	parse_links(http_lcache, http_lcache2, &cache1_url_root, &conn);

	if (!do_not_archive)
	{
		fprintf(stdout, "%sArchiving %s\n", ACTION_ING_STR, conn.full_url);
		__archive_page(&conn);
	}

	if (!wr_cache_nr_used(http_lcache))
	{
		fprintf(stdout, "%sParsed zero pages from URL %s\n", ACTION_DONE_STR, conn.full_url);
		goto out_disconnect;
	}

	try_again:
	rv = reap(http_lcache, http_lcache2, &conn);

	if (rv < 0)
	{
		goto fail_disconnect;
	}
	else
	if (FL_RESET == rv)
	{
		buf_clear(&conn.read_buf);
		buf_clear(&conn.write_buf);
		reconnect(&conn);

		BLOCK_SIGNAL(SIGINT);
		sleep(RESET_DELAY);
		UNBLOCK_SIGNAL(SIGINT);

		if (wr_cache_nr_used(http_lcache) >= wr_cache_nr_used(http_lcache2))
			wr_cache_clear_all(http_lcache2);
		else
			wr_cache_clear_all(http_lcache);	

		++nr_fails;
		if (nr_fails < MAX_FAILS)
			goto try_again;
		else
			goto fail_disconnect;
	}

	fprintf(stdout, "%sFinished reaping %d total pages (depth=%d)\n", ACTION_DONE_STR, nr_reaped, depth);

	out_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	if (wr_cache_nr_used(http_lcache) > 0)
		wr_cache_clear_all(http_lcache);
	if (wr_cache_nr_used(http_lcache2) > 0)
		wr_cache_clear_all(http_lcache2);
	if (wr_cache_nr_used(http_hcache) > 0)
		wr_cache_clear_all(http_hcache);
	if (wr_cache_nr_used(cookies) > 0)
		wr_cache_clear_all(cookies);

	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_lcache2);
	wr_cache_destroy(http_hcache);
	wr_cache_destroy(cookies);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_SUCCESS);

	fail_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	if (wr_cache_nr_used(http_lcache) > 0)
		wr_cache_clear_all(http_lcache);
	if (wr_cache_nr_used(http_lcache2) > 0)
		wr_cache_clear_all(http_lcache2);
	if (wr_cache_nr_used(http_hcache) > 0)
		wr_cache_clear_all(http_hcache);
	if (wr_cache_nr_used(cookies) > 0)
		wr_cache_clear_all(cookies);

	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_lcache2);
	wr_cache_destroy(http_hcache);
	wr_cache_destroy(cookies);

	fail:
	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_FAILURE);
}

int
get_opts(int argc, char *argv[])
{
	int		i;

	USER_BLACKLIST_NR_TOKENS = 0;

	for (i = 1; i < argc; ++i)
	{
		while (i < argc && argv[i][0] != '-')
			++i;

		if (i == argc)
			break;

		if (!strcmp("--help", argv[i])
			|| !strcmp("-h", argv[i]))
		{
			usage(EXIT_SUCCESS);
		}
		else
		if (!strcmp("--depth", argv[i])
		|| !strcmp("-D", argv[i]))
		{
			++i;

			if (i == argc)
			{
				fprintf(stderr, "-D/--depth requires an argument\n");
				usage(EXIT_FAILURE);
			}

			REAP_DEPTH = atoi(argv[i]);
			assert(REAP_DEPTH > 0);
			assert(REAP_DEPTH < 0xffffff);
		}
		else
		if (!strcmp("--blacklist", argv[i])
		|| !strcmp("-B", argv[i]))
		{
			int nr_tokens = 10;
			int idx = 0;
			size_t token_len;
			USER_BLACKLIST_NR_TOKENS = 0;


			++i;

			if (i == argc || !strncmp("--", argv[i], 2) || !strncmp("-", argv[i], 1))
			{
				fprintf(stderr, "--blacklist/-B requires an argument\n");
				usage(EXIT_FAILURE);
			}

			MATRIX_INIT(user_blacklist, nr_tokens, TOKEN_MAX, char);

			while (i < argc && strncmp("--", argv[i], 2) && strncmp("-", argv[i], 1))
			{
				token_len = strlen(argv[i]);
				assert(token_len < TOKEN_MAX);

				MATRIX_CHECK_CAPACITY(user_blacklist, idx, nr_tokens, TOKEN_MAX, char);

				strncpy(user_blacklist[idx], argv[i], token_len);
				user_blacklist[idx][token_len] = 0;

				++USER_BLACKLIST_NR_TOKENS;
				++idx;
				++i;
			}

			--i;
		}
		else
		if (!strcmp("--xdomain", argv[i])
			|| !strcmp("-X", argv[i]))
		{
			set_option(OPT_ALLOW_XDOMAIN);
		}
		else
		if (!strcmp("-oH", argv[i])
			|| !strcmp("--req-head", argv[i]))
		{
			set_option(OPT_SHOW_REQ_HEADER);
		}
		else
		if (!strcmp("-iH", argv[i])
			|| !strcmp("--res-head", argv[i]))
		{
			set_option(OPT_SHOW_RES_HEADER);
		}
		else
		if (!strcmp("-T", argv[i])
			|| strcmp("--tls", argv[i]))
		{
			set_option(OPT_USE_TLS);
		}
		else
		{
			continue;
		}
	}

	return 0;
}
