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

#define SLEEP_TIME		5

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global variables.
 */
uint32_t runtime_options = 0;
wr_cache_t *http_hcache;

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
		if (!strncmp("https", tmp.buf_head, 5))
			p = (tmp.buf_head + strlen("https://"));
		else
			p = (tmp.buf_head + strlen("http://"));

		buf_collapse(&tmp, (off_t)0, (p - tmp.buf_head));
	}

	p = tmp.buf_head;
	end = tmp.buf_tail;

	while (p < end)
	{
		if (*p == 0x20
		|| (*p != 0x5f && !isalpha(*p) && !isdigit(*p)))
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
__archive_page(connection_t *conn)
{
	int fd = -1;
	buf_t *buf = &conn->read_buf;
	//char *start;
	//char *savep = buf->buf_head;
	//char *tail = buf->buf_tail;
	//char *p;
	char *filename = wr_strdup(conn->page);
	char *p;
	//size_t range;

	p = strstr(buf->buf_head, HTTP_EOH_SENTINEL);

	if (p)
	{
		p += strlen(HTTP_EOH_SENTINEL);
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));
	}

	printf("Normalising filename\n");
	__normalise_filename(filename);
	printf("Normalised: %s\n", filename);

	fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd == -1)
		goto out_free_name;

	printf("Opened file on fd %d\n", fd);

	printf("Writing to file with buf_write_fd() (towrite=%lu bytes)\n", buf->data_len);
	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

	free(filename);
	return 0;

	out_free_name:
	free(filename);

	return -1;
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
	http_header_t *cookie = NULL;
	http_header_t *hp = NULL;

	/*
	 * If there is a Set-Cookie header, then clear all
	 * previously-cached cookies. Otherwise, if no such
	 * header and we have cached cookies, append them
	 * to the buffer. Otherwise, do nothing.
	 */
	if (http_check_header(&conn->read_buf, "Set-Cookie", (off_t)0, &offset))
	{
		printf("Clearing old cookies\n");
		wr_cache_clear_all(http_hcache);
		offset = 0;

		while(http_check_header(&conn->read_buf, "Set-Cookie", offset, &offset))
		{
			cookie = (http_header_t *)wr_cache_alloc(http_hcache);
			http_fetch_header(&conn->read_buf, "Set-Cookie", cookie, offset);
			http_append_header(&conn->write_buf, cookie);
			++offset;
			printf("Appended cookie=%s\n", cookie->value);
		}
	}
	else
	{
		int nr_used = wr_cache_nr_used(http_hcache);
		int i;

		if (!nr_used)
			return;

		hp = (http_header_t *)http_hcache->cache;

		printf("Appending %d saved cookies\n", nr_used);
		for (i = 0; i < nr_used; ++i)
		{
			while (!wr_cache_obj_used(http_hcache, (void *)hp))
				++hp;

			if (strncmp("Cookie", hp->name, hp->nlen))
			{
				++hp;
				continue;
			}

			http_append_header(&conn->write_buf, hp);
			++hp;
		}
	}

	return;
}

static int
__do_request(connection_t *conn)
{
	assert(conn);

	int status_code = 0;

	http_build_request_header(conn, HTTP_GET, conn->page);

	/*
	 * Will append cached or new cookies.
	 */
	__check_cookies(conn);

	printf("Sending HTTP request\n");
	if (http_send_request(conn) < 0)
		goto fail;

	printf("Receiving HTTP response\n");
	if (http_recv_response(conn) < 0)
		goto fail;

	printf("Getting status code\n");
	status_code = http_status_code_int(&conn->read_buf);

	return status_code;

	fail:
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
	http_parse_host(location->value, conn->host);
	strncpy(conn->page, location->value, location->vlen);
	conn->page[location->vlen] = 0;
	wr_cache_dealloc(http_hcache, (void *)location);

	if (!strncmp("https", conn->page, 5))
		conn_switch_to_tls(conn);

	return 0;
}

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

	printf("Connected to new host \"%s\"\n", conn->host);

	return 0;

	fail:
	return -1;
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

	char *saved_host = wr_strdup(conn->host);
	int nr_links = wr_cache_nr_used(cachep);
	int status_code = 0;
	int choice;
	int i;
	http_link_t *link;

	if (!nr_links && wr_cache_obj_used(cachep, cachep->cache))
	{
		fprintf(stderr,
			"__iterate_cached_links: nr_used==0 && first object used...\n");
		goto fail;
	}
	else
	if (!nr_links)
	{
		printf("no links\n");
		return -2;
	}

	printf("Iterating over parsed links (%d)\n", nr_links);

	choice = (rand() % nr_links);

	for (i = 0; i < nr_links; ++i)
	{
		if (i == choice)
			continue;

		sleep(SLEEP_TIME);

		link = ((http_link_t *)cachep->cache + i);

		if (!(__same_domain(link->url, saved_host)))
		{
			printf("New domain - switching host (old=%s ; new=%s)\n", saved_host, link->url);

			if (__switch_host(link->url, conn) < 0)
				goto fail;

			free(saved_host);
			saved_host = NULL;
			saved_host = wr_strdup(conn->host);
		}

		http_parse_host(link->url, conn->host);
		http_parse_page(link->url, conn->page);

		resend:
		printf("Requesting %s from host %s\n", conn->page, conn->host);
		status_code = __do_request(conn);

		switch(status_code)
		{
			case HTTP_OK:
				printf("200 OK\n");
				link->time_reaped = time(NULL);
				break;
			case HTTP_MOVED_PERMANENTLY:
			case HTTP_FOUND:
				__handle301(conn); /* can also handle 302 since both give Location header */
				buf_clear(&conn->write_buf);
				goto resend;
				break;
			default:
				fprintf(stderr, "__iterate_cached_links: received HTTP status code %d\n", status_code);
				goto out_release_dup_str;
		}

		printf("Archiving page\n");
		__archive_page(conn);
	}

	free(saved_host);
	saved_host = NULL;
	return choice;

	out_release_dup_str:
	free(saved_host);
	saved_host = NULL;

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

static void
__check_directory(void)
{
	char *home = getenv("HOME");
	buf_t tmp;

	buf_init(&tmp, pathconf("/", _PC_PATH_MAX));
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
	http_state_t http_state;
	http_link_t *link = NULL;
	wr_cache_t *http_lcache = NULL;
	int status_code;
	int choice = 0;

	clear_struct(&http_state);
	http_state.base_page = wr_strdup(argv[1]);

	conn_init(&conn);
	http_parse_host(http_state.base_page, conn.host);
	http_parse_page(http_state.base_page, conn.page);

	fprintf(stderr,
		"parsed host: %s\n"
		"parsed page: %s\n",
		conn.host,
		conn.page);

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

	if (sigsetjmp(main_env, 0) != 0)
	{
		fprintf(stderr, "%c%c%c%c%c%c", 0x08, 0x20, 0x08, 0x08, 0x20, 0x08);
		fprintf(stderr, "Caught signal! Exiting!\n");
		goto out_disconnect;
	}

	while (1)
	{
		loop_start:

		sleep(SLEEP_TIME);

		buf_clear(&conn.read_buf);
		buf_clear(&conn.write_buf);

		printf("Requesting %s from host %s\n", conn.page, conn.host);
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
			case HTTP_BAD_REQUEST:
				printf("400 Bad Request\n\n%.*s\n", (int)conn.write_buf.data_len, conn.write_buf.buf_head);
				goto out_disconnect;
			default:
				fprintf(stderr, "main: received HTTP status code %d\n", status_code);
				goto out_disconnect;
		}

		printf("Archiving page\n");
		__archive_page(&conn);

		/* http_parse_links(wr_cache_t *cachep, buf_t *buf, const char *host); */

		printf("Parsing links\n");
		parse_links(http_lcache, &conn.read_buf, conn.host);

		__dump_links(http_lcache);

		break;

		choice = __iterate_cached_links(http_lcache, &conn);
		printf("choice=%d\n", choice);

		if (choice < 0)
			goto out_disconnect;

		link = (http_link_t *)((char *)http_lcache->cache + (choice * http_lcache->objsize));

		http_parse_host(link->url, conn.host);
		http_parse_page(link->url, conn.page);

		wr_cache_clear_all(http_lcache);
	}

	/*
	 * Destroys the read/write buffers in conn.
	 */
	close_connection(&conn);
	conn_destroy(&conn);

	wr_cache_clear_all(http_lcache);
	wr_cache_clear_all(http_hcache);
	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_hcache);

	free(http_state.base_page);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_SUCCESS);

	out_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	wr_cache_clear_all(http_lcache);
	wr_cache_clear_all(http_hcache);
	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_hcache);

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
