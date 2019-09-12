#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "webreaper.h"

static int get_opts(int, char *[]) __nonnull((2)) __wur;

uint32_t runtime_options = 0;
wr_cache_t *http_hcache;

const char *const KEYWORDS[] =
{
	"programming",
	" c ",
	"posix",
	"linux",
	NULL
};

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

static int
__found_keywords(buf_t *buf)
{
	return 0;
}

static void
__append_cookies(wr_cache_t *cachep, connection_t *conn)
{
	return;
}

static void
__archive_page(connection_t *conn)
{
	return;
}

static int
__do_request(connection_t *conn)
{
	assert(conn);

	int status_code = 0;

	http_build_request_header(conn, HTTP_GET, conn->page);
	__append_cookies(http_hcache, conn);

	if (http_send_request(conn) < 0)
		goto fail;

	if (http_recv_response(conn) < 0)
		goto fail;

	status_code = http_status_code_int(&conn->read_buf);

	assert(status_code != -1);
	return status_code;

	fail:
	return -1;
}

/**
 * __handle301 - handle 301 Moved Permanently
 * @conn: struct holding connection context
 */
static void
__handle301(connection_t *conn)
{
	return;
}

#if 0
/**
 * __check_cookies - check for Set-Cookie headers; extract and append to outgoing header if any
 * @conn: struct holding connection context
 */
static void
__check_cookies(connection_t *conn)
{
	assert(conn);

	off_t offset = 0;
	http_header_t *cookie;

	/*
	 * Clear all previous Cookie headers.
	 */
	if (http_check_header(&conn->read_buf, "Set-Cookie", (off_t)0, &offset))
		wr_cache_clear_all(http_hcache);

	offset = 0;

	while(http_check_header(&conn->read_buf, "Set-Cookie", offset, &offset))
	{
		cookie = (http_header_t *)wr_cache_alloc(http_hcache);
		http_fetch_header(&conn->read_buf, "Set-Cookie", cookie, offset);
		http_append_header(&conn->write_buf, cookie);
		++offset;
	}

	return;
}
#endif

static int
__same_domain(char *url, char *current)
{
	size_t url_len = strlen(url);
	char *p = url;
	char *end = (url + url_len);
	static char tmp[HTTP_URL_MAX];

	if (!strncmp(url, "http", 4))
	{
		end = memchr(url, '/', ((url + url_len) - url));
		if (!end)
			return 0;

		end += 2;
		p = end;

		end = memchr(p, '/', ((url + url_len) - p));
		if (!end)
			end = (url + url_len);

		p = url;

		strncpy(tmp, p, (end - p));
		tmp[end - p] = 0;
	}
	else
	{
		end = memchr(url, '/', ((url + url_len) - url));
		if (!end)
			end = (url + url_len);

		strncpy(tmp, url, (end - url));
		tmp[end - url] = 0;
	}

	if (!strcmp(current, tmp))
		return 1;
	else
		return 0;
}

static int
__switch_host(char *url, connection_t *conn)
{
	assert(url);
	assert(conn);

	shutdown(conn->sock, SHUT_RDWR);
	
	if (option_set(OPT_USE_TLS))
	{
		SSL_free(conn->ssl);
		SSL_CTX_free(conn->ssl_ctx);
		conn->ssl = NULL;
		conn->ssl_ctx = NULL;
	}

	close(conn->sock);
	conn->sock = -1;

	memset(conn->host, 0, HTTP_URL_MAX);
	memset(conn->page, 0, HTTP_URL_MAX);

	http_parse_host(url, conn->host);
	http_parse_page(url, conn->page);

	if (open_connection(conn) < 0)
		goto fail;

#ifdef DEBUG
	printf("Connected to new host \"%s\"\n", conn->host);
#endif

	return 0;

	fail:
	return -1;
}

static int
__iterate_cached_links(wr_cache_t *cachep, connection_t *conn)
{
	assert(cachep);
	assert(conn);

	char *saved_host = wr_strdup(conn->host);
	int nr_links = wr_cache_nr_used(cachep);
	int status_code = 0;
	int i;
	http_link_t *link;

	for (i = 0; i < nr_links; ++i)
	{
		link = ((http_link_t *)cachep->cache + i);

		if (!(__same_domain(link->url, saved_host)))
		{
			if (__switch_host(link->url, conn) < 0)
				goto fail;

			free(saved_host);
			saved_host = NULL;
			saved_host = wr_strdup(conn->host);
		}

		resend:
		status_code = __do_request(conn);

		switch(status_code)
		{
			case HTTP_OK:
				break;
			case HTTP_MOVED_PERMANENTLY:
				__handle301(conn);
				goto resend;
				break;
			default:
				fprintf(stderr, "__iterate_cached_links: received HTTP status code %d\n", status_code);
				goto out_release_dup_str;
		}

		if (__found_keywords(&conn->read_buf))
			__archive_page(conn);
	}

	out_release_dup_str:
	free(saved_host);
	saved_host = NULL;

	fail:
	return -1;
}

/*
 * ./webreaper <url> [options]
 */
int
main(int argc, char *argv[])
{
	if (argc < 2)
		usage(EXIT_FAILURE);

	if (get_opts(argc, argv) < 0)
		goto fail;

	connection_t conn;
	http_state_t http_state;
	wr_cache_t *http_lcache;
	int status_code;

	clear_struct(&http_state);
	http_state.base_page = wr_strdup(argv[1]);

	conn_init(&conn);
	http_parse_host(http_state.base_page, conn.host);
	http_parse_page(http_state.base_page, conn.page);

	/*
	 * Initialises read/write buffers in conn.
	 */
	if (open_connection(&conn) < 0)
		goto fail;

	/*
	 * Create a new cache for http_link_t objects.
	 */
	http_lcache = wr_cache_create("http_link_cache",
							sizeof(http_link_t),
							0,
							wr_cache_http_link_ctor,
							wr_cache_http_link_dtor);

	/*
	 * Some websites require setting more than once cookie, so create
	 * a cache for them so that it is easy to pass them around.
	 */
	http_hcache = wr_cache_create("http_cookie_cache",
							sizeof(http_header_t),
							0,
							wr_cache_http_cookie_ctor,
							wr_cache_http_cookie_dtor);

	while (1)
	{
		loop_start:

		buf_clear(&conn.read_buf);
		buf_clear(&conn.write_buf);

		status_code = __do_request(&conn);

		switch(status_code)
		{
			case HTTP_OK:
				break;
			case HTTP_MOVED_PERMANENTLY:
				__handle301(&conn);
				goto loop_start;
				break;
			default:
				fprintf(stderr, "main: received HTTP status code %d\n", status_code);
				goto out_disconnect;
		}

		/* http_parse_links(wr_cache_t *cachep, buf_t *buf, const char *host); */
		http_parse_links(http_lcache, &conn.read_buf, conn.host);

		__iterate_cached_links(http_lcache, &conn);
	}

	/*
	 * Destroys the read/write buffers in conn.
	 */
	close_connection(&conn);
	conn_destroy(&conn);

	free(http_state.base_page);

	exit(EXIT_SUCCESS);

	out_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	fail:
	fprintf(stderr, "%s\n", strerror(errno));
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
