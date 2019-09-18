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
#include <time.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "webreaper.h"

#define SLEEP_TIME	3

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global variables.
 */
uint32_t runtime_options = 0;
wr_cache_t *http_hcache;
wr_cache_t *http_lcache;
wr_cache_t *cookies;
static char PRIMARY_HOST[HTTP_HOST_MAX];
static size_t PRIMARY_HOST_LEN = 0;

#ifndef PATHMAX
int PATHMAX = 0;

static void
__ctor __wr_init(void)
{
	PATHMAX = pathconf("/", _PC_PATH_MAX);
	if (PATHMAX == 0)
		PATHMAX = 1024;
}
#endif

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
		"-T/--tls            use a TLS connection\n"
		"-R/--raw            show raw HTML output\n"
		"-oH/--req-head  	   show the request header (\"out header\")\n"
		"-iH/--res-head    	 show the response header (\"in header\")\n"
		"--help/-h           display this information\n");

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

static int
__includes_host(char *url)
{
	assert(url);

	size_t url_len = strlen(url);

	if (memchr(url, '.', url_len))
		return 1;
	else
		return 0;
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

	/*
	 * If there is a Set-Cookie header, then clear all
	 * previously-cached cookies. Otherwise, if no such
	 * header and we have cached cookies, append them
	 * to the buffer. Otherwise, do nothing.
	 */
	if (http_check_header(&conn->read_buf, "Set-Cookie", (off_t)0, &offset))
	{
		printf("Clearing old cookies\n");
		wr_cache_clear_all(cookies);
		offset = 0;

		tmp = (http_header_t *)wr_cache_alloc(http_hcache);

		while(http_check_header(&conn->read_buf, "Set-Cookie", offset, &offset))
		{
			http_fetch_header(&conn->read_buf, "Set-Cookie", tmp, offset);
			http_append_header(&conn->write_buf, tmp);

			cookie = (struct http_cookie_t *)wr_cache_alloc(cookies);

			__extract_cookie_info(cookie, tmp);

			++offset;
			printf("Appended cookie:\n\n"
				"domain=%s\n"
				"path=%s\n"
				"expires=%s\n",
				cookie->domain,
				cookie->path,
				cookie->expires);
		}
	}
	else
	{
		int nr_used = wr_cache_nr_used(cookies);
		int i;

		if (!nr_used)
			return;

		tmp = (http_header_t *)wr_cache_alloc(http_hcache);

		cookie = (struct http_cookie_t *)cookies->cache;

		printf("Appending %d saved cookies\n", nr_used);
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

	wr_cache_dealloc(http_hcache, (void *)tmp);

	return;
}

static void
__show_request_header(buf_t *buf)
{
	assert(buf);

	fprintf(stderr, "%s", buf->buf_head);
	return;
}

static void
__show_response_header(buf_t *buf)
{
	assert(buf);

	char *p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);

	if (!p)
	{
		fprintf(stderr, "__show_response_header: failed to find end of HTTP header\n");
		fprintf(stderr, "%s", buf->buf_head);
		
		errno = EPROTO;
		return;
	}

	p += strlen(HTTP_EOH_SENTINEL);
	fprintf(stderr, "%.*s", (int)(p - buf->buf_head), buf->buf_head);

	return;
}

static void
__adjust_host_and_page(connection_t *conn)
{
	assert(conn);

	char *host_dup;
	char *p;
	char *e;
	buf_t tmp;
	int got_host = 0;
	size_t http_len = strlen("http://");
	size_t https_len = strlen("https://");

	buf_init(&tmp, HTTP_URL_MAX);

	if (__includes_host(conn->page))
	{
		got_host = 1;
		host_dup = wr_strdup(conn->host);
		http_parse_host(conn->page, conn->host);

		fprintf(stderr, "PARSED HOST = %s\n", conn->host);

		if (strcmp(host_dup, conn->host))
		{
			fprintf(stderr, "DIFFERENT HOST - RECONNECTING\n");
			fprintf(stderr, "host=%s ; page=%s\n", conn->host, conn->page);
			wr_cache_clear_all(cookies);
			reconnect(conn);
		}

		free(host_dup);
		host_dup = NULL;
	}
	else
	{
		if (strcmp(conn->host, PRIMARY_HOST))
		{
			fprintf(stderr, "RECOPYING PRIMARY HOST\n");
			strncpy(conn->host, PRIMARY_HOST, PRIMARY_HOST_LEN);
			conn->host[PRIMARY_HOST_LEN] = 0;
		}
	}

	if (!strncmp("http", conn->page, 4)) // then we have the full link */
		goto out_free_buf;

	if (option_set(OPT_USE_TLS))
		buf_append(&tmp, "https://");
	else
		buf_append(&tmp, "http://");

	if (!got_host)
		buf_append(&tmp, conn->host);

	buf_append(&tmp, conn->page);

	/* Remove extra slashes: e.g., https:////... */
	if (!strncmp("http://", tmp.buf_head, http_len))
	{
		p = tmp.buf_head + http_len;
		e = p;

		while (*e == '/')
			++e;

		if (e - p)
			buf_collapse(&tmp, (off_t)(p - tmp.buf_head), (e - p));
	}
	else
	{
		p = tmp.buf_head + https_len;
		e = p;

		while (*e == '/')
			++e;

		if (e - p)
			buf_collapse(&tmp, (off_t)(p - tmp.buf_head), (e - p));
	}

	strncpy(conn->page, tmp.buf_head, tmp.data_len);
	conn->page[tmp.data_len] = 0;

	out_free_buf:
	buf_destroy(&tmp);

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

	buf_clear(wbuf);

	__adjust_host_and_page(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"HEAD %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s%s",
			conn->page, HTTP_VERSION,
			HTTP_USER_AGENT,
			conn->host, HTTP_EOH_SENTINEL);

	buf_append(wbuf, tmp_cbuf);

	__check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (option_set(OPT_SHOW_REQ_HEADER))
		__show_request_header(wbuf);

	if (http_send_request(conn) < 0)
		goto fail;

	if (http_recv_response(conn) < 0)
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
	return -1;
}

static int
__send_get_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;

	buf_clear(wbuf);

	__adjust_host_and_page(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			conn->page, HTTP_VERSION,
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

	if (http_recv_response(conn) < 0)
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
	return -1;
}

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

static int
__check_local_dirs(buf_t *filename)
{
	assert(filename);

	char *p;
	char *e;
	char *end;
	char *name = filename->buf_head;
	size_t len;
	buf_t tmp;

	len = filename->data_len;

	if (*(filename->buf_tail - 1) == '/')
		buf_snip(filename, 1);

	end = filename->buf_tail;
	buf_init(&tmp, len+1);
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
			/* unless... */
			e = strstr(p, ".html");
			if (!strncmp(PRIMARY_HOST, p, (e - p)))
			{
				buf_snip(filename, strlen(".html"));

				if (access(name, F_OK) != 0)
				{
					mkdir(filename->buf_head, S_IRWXU);
					fprintf(stderr, "@@@ Created local dir %s\n", name);
				}

				buf_append(filename, "/main_page.html");
			}

			break;
		}

		buf_append_ex(&tmp, name, (e - name));

		BUF_NULL_TERMINATE(&tmp);

		if (access(tmp.buf_head, F_OK) != 0)
		{
			mkdir(tmp.buf_head, S_IRWXU);
			fprintf(stderr, "@@@ Created local dir %s\n", tmp.buf_head);
		}

		p = ++e;
		buf_clear(&tmp);
	}

	buf_destroy(&tmp);
	return 0;
}

static int
__archive_page(connection_t *conn)
{
	int fd = -1;
	buf_t *buf = &conn->read_buf;
	buf_t tmp;
	char *filename = wr_strdup(conn->page);
	char *home = NULL;
	char *p;

	buf_init(&tmp, HTTP_URL_MAX);

	p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);

	if (p)
	{
		p += strlen(HTTP_EOH_SENTINEL);
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));
	}

	__normalise_filename(filename);

	home = getenv("HOME");
	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR "/");
	if (!strstr(filename, conn->host))
		buf_append(&tmp, conn->host);
	buf_append(&tmp, filename);

	if (__check_local_dirs(&tmp) < 0)
		goto out_free;

	if (access(tmp.buf_head, F_OK) == 0)
	{
		printf("%s!!! Already archived %s%s\n", COL_RED, tmp.buf_head, COL_END);
		goto out;
	}

	fd = open(tmp.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd == -1)
		goto out_free;

#ifdef DEBUG
	printf("%s@@@ Created file %s%s\n", COL_GREEN, tmp.buf_head, COL_END);
#endif

	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

	out:
	free(filename);
	buf_destroy(&tmp);
	return 0;

	out_free:
	free(filename);
	buf_destroy(&tmp);

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

	location = (http_header_t *)wr_cache_alloc(http_hcache);
	http_fetch_header(&conn->read_buf, "Location", location, (off_t)0);

#ifdef DEBUG
	printf("301/302 ===> %s%s%s\n", COL_ORANGE, location->value, COL_END);
#endif

	memset(conn->host, 0, HTTP_URL_MAX);
	http_parse_host(location->value, conn->host);

	strncpy(conn->page, location->value, location->vlen);
	conn->page[location->vlen] = 0;

	wr_cache_dealloc(http_hcache, (void *)location);

	if (!strncmp("https", conn->page, 5))
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

	/*
	 * Save bandwidth: send HEAD first.
	 */
	resend_head:
	status_code = __send_head_request(conn);

	switch(status_code)
	{
		case HTTP_FOUND:
		case HTTP_MOVED_PERMANENTLY:
			__handle301(conn);
			reconnect(conn); /* server resets connection after HEAD */
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
	reconnect(conn);

	status_code &= ~status_code;
	status_code = __send_get_request(conn);

	return status_code;
}

/**
 * __iterate_cached_links - archive the pages in the link cache,
 *    choose one at random and return that choice. That will be
 *    our next page from which to parse links.
 * @cachep: the cache of parsed links
 * @conn: our struct with connection context
 */
static int
__iterate_cached_links(wr_cache_t *cachep, connection_t *conn)
{
	assert(cachep);
	assert(conn);

	int nr_links = wr_cache_nr_used(cachep);
	int status_code = 0;
	int choice;
	int i;
	size_t len;
	http_link_t *link;
	buf_t *wbuf = &conn->write_buf;

	if (!nr_links)
	{
		fprintf(stderr, "__iterate_cached_links: no links\n");
		return -1;
	}
	else
	if (nr_links > 0)
	{
		assert(wr_cache_obj_used(cachep, cachep->cache));
	}

	/*
	 * Choose a random link that works to follow after
	 * reaping all of the URLs in the list.
	 */
	while (HTTP_OK != status_code)
	{
		choice = (rand() % nr_links);

		link = (http_link_t *)((char *)http_lcache->cache + (choice * cachep->objsize));
		len = strlen(link->url);
		strncpy(conn->page, link->url, len);
		conn->page[len] = 0;

		status_code = __send_head_request(conn);

		switch (status_code)
		{
			case HTTP_OK:
				break;
			case HTTP_MOVED_PERMANENTLY:
			case HTTP_FOUND:
				__handle301(conn);
				reconnect(conn);
				break;
			default:
				return status_code;
		}
	}

	fprintf(stderr, "FOUND WORKING LINK TO FOLLOW NEXT %s\n", link->url);
	//wr_cache_clear_all(cookies);

	link = (http_link_t *)cachep->cache;

	for (i = 0; i < nr_links; ++i)
	{
		if (i == choice)
		{
			++link;
			continue;
		}

		sleep(SLEEP_TIME);

		buf_clear(wbuf);

		len = strlen(link->url);
		strncpy(conn->page, link->url, len);
		conn->page[len] = 0;

		__adjust_host_and_page(conn);

		resend:
		if (link->nr_requests > 2) /* loop */
		{
			++link;
			fprintf(stderr, "Skipping %s%s%s (infinite redirect loop)\n", COL_ORANGE, link->url, COL_END);
			continue;
		}

		printf("===> %s%s%s <===\n", COL_ORANGE, conn->page, COL_END);
		status_code = __do_request(conn);

		link->status_code = status_code;
		++link->nr_requests;

		switch(status_code)
		{
			case HTTP_OK:
				link->time_reaped = time(NULL);
				break;
			case HTTP_MOVED_PERMANENTLY:
			case HTTP_FOUND:
			/*
			 * Shouldn't get here, because __do_request() first
			 * sends a HEAD request, and handles 301/302 for us.
			 */
				__handle301(conn);
				buf_clear(wbuf);
				goto resend;
				break;
			case HTTP_BAD_REQUEST:
			case HTTP_NOT_FOUND:
				goto next;
			default:
				fprintf(stderr, "__iterate_cached_links: received HTTP status code %d\n", status_code);
				goto fail;
		}

		fprintf(stderr, "Archiving %s\n", conn->page);
		__archive_page(conn);

		next:
		++link;
	}

	return choice;

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

	buf_init(&tmp, PATHMAX);
	buf_append(&tmp, home);
	buf_append(&tmp, "/WR_Reaped");

	if (access(tmp.buf_head, F_OK) != 0)
		mkdir(tmp.buf_head, S_IRUSR|S_IWUSR|S_IXUSR);

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
		usage(EXIT_FAILURE);

	__print_prog_info();

	if (get_opts(argc, argv) < 0)
		goto fail;

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
	http_link_t *link = NULL;
	int status_code;
	int choice = 0;
	int _url_len = 0;

	conn_init(&conn);

	http_parse_host(argv[1], conn.host);

	_url_len = strlen(argv[1]);
	strncpy(conn.page, argv[1], _url_len);
	conn.page[_url_len] = 0;

	if (conn.page[_url_len-1] == '/')
		conn.page[--_url_len] = 0;

	PRIMARY_HOST_LEN = strlen(conn.host);
	strncpy(PRIMARY_HOST, conn.host, PRIMARY_HOST_LEN);
	PRIMARY_HOST[PRIMARY_HOST_LEN] = 0;

	fprintf(stderr,
		"PRIMARY HOST = %s\n"
		"PAGE         = %s\n",
		PRIMARY_HOST,
		conn.page);

	/*
	 * Initialises read/write buffers in conn.
	 */
	if (open_connection(&conn) < 0)
		goto fail;

	/*
	 * Create a new cache for http_link_t objects.
	 */
	http_lcache = wr_cache_create(
			"http_link_cache",
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

	while (1)
	{
		loop_start:

		/*
		 * Would rather sleep between requests to avoid
		 * having IP address banned by the server.
		 */
		sleep(SLEEP_TIME);

		buf_clear(&conn.read_buf);
		buf_clear(&conn.write_buf);

		printf(">>> %s%s%s <<<\n", COL_ORANGE, conn.page, COL_END);
		status_code = __do_request(&conn);

		switch(status_code)
		{
			case HTTP_OK:
				break;
			case HTTP_MOVED_PERMANENTLY:
			case HTTP_FOUND:
				__handle301(&conn);
				goto loop_start;
				break;
			case HTTP_NOT_FOUND:
				fprintf(stderr, "@@@ 404 Not Found\n");
				goto out_disconnect;
			case HTTP_BAD_REQUEST:
				printf("@@@ 400 Bad Request\n"
#ifdef DEBUG
				"\n%.*s\n", (int)conn.write_buf.data_len, conn.write_buf.buf_head);
#else
				);
#endif
				goto out_disconnect;
			default:
				fprintf(stderr, "main: received HTTP status code %d\n", status_code);
				goto out_disconnect;
		}

		fprintf(stderr, "Archiving %s\n", conn.page);
		__archive_page(&conn);

		/* parse_links(wr_cache_t *cachep, buf_t *buf, const char *host); */

		fprintf(stderr, "Extracting links from page\n");
		parse_links(http_lcache, &conn.read_buf, conn.host);

		/*
		 * Choose one of the links at random (rand() MODULO #links)
		 * to follow and proceed to extract links from its page
		 */
		choice = __iterate_cached_links(http_lcache, &conn);

		if (choice < 0)
			goto out_disconnect;

#ifdef DEBUG
		fprintf(stderr, "CHOSEN TO FOLLOW LINK #%d\n", choice);
#endif

		int nr_links = wr_cache_nr_used(http_lcache);

		assert(nr_links > 0);
		assert(choice < nr_links);

		link = (http_link_t *)((char *)http_lcache->cache + (choice * http_lcache->objsize));

		strncpy(conn.page, link->url, strlen(link->url));
		conn.page[strlen(link->url)] = 0;

		wr_cache_clear_all(http_lcache);
	}

	/*
	 * Destroys the read/write buffers in conn.
	 */
	close_connection(&conn);
	conn_destroy(&conn);

	wr_cache_clear_all(http_lcache);
	wr_cache_clear_all(http_hcache);
	wr_cache_clear_all(cookies);
	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_hcache);
	wr_cache_destroy(cookies);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_SUCCESS);

	out_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	wr_cache_clear_all(http_lcache);
	wr_cache_clear_all(http_hcache);
	wr_cache_clear_all(cookies);
	wr_cache_destroy(http_lcache);
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
		if (!strcmp("--raw", argv[i])
			|| !strcmp("-R", argv[i]))
		{
			set_option(OPT_SHOW_RAW);
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
