#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "webreaper.h"

static int get_opts(int, char *[]) __nonnull((2)) __wur;

uint32_t runtime_options = 0;

static void
__noret usage(int exit_status)
{
	fprintf(stderr,
		"webreaper <url> [options]\n\n"
		"--tls      use a TLS connection\n"
		"--help/-h  display this information\n");

	exit(exit_status);
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

	http_state_t http_state;
	connection_t conn;
	wr_cache_t *http_lcache; /* link cache */
	wr_cache_t *http_hcache; /* header cache */
	http_link_t *lp;
	http_header_t *hp;

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

	off_t off = 0;

	for (;;)
	{
		if (http_build_request_header(&conn, HTTP_GET, conn.page) < 0)
			goto fail;

		if (http_check_header(&conn.read_buf, "Set-Cookie", off, &off))
		{
/*
 * Clear all old cookies and append the
 * new ones in the outgoing HTTP request.
 */
			wr_cache_clear_all(http_hcache);

			off = 0;

			while (http_check_header(&conn.read_buf, "Set-Cookie", off, &off))
			{
				http_header_t *ch = (http_header_t *)wr_cache_alloc(http_hcache);
				assert(wr_cache_obj_used(http_hcache, (void *)ch));
				assert(ch->name);
				assert(ch->value);
				http_fetch_header(&conn.read_buf, "Set-Cookie", ch, off);
				assert(ch->value[0]);
				strncpy(ch->name, "Cookie", strlen("Cookie"));
				ch->name[strlen("Cookie")] = 0;
				ch->nlen = strlen("Cookie");
				http_append_header(&conn.write_buf, ch);
				++off;
			}
		}

#ifdef DEBUG
		printf("%s", conn.write_buf.buf_head);
#endif

		if (http_send_request(&conn) < 0)
			goto fail;

		if (http_recv_response(&conn) < 0)
			goto fail;

#ifdef DEBUG
		printf("%.*s\n", (int)http_response_header_len(&conn.read_buf), conn.read_buf.buf_head);
#endif

		int status_code = http_status_code_int(&conn.read_buf);

/*
 * 301 Permanently Moved and 302 Found both give
 * a location header of the link we should request
 * instead.
 */
		if (status_code == HTTP_MOVED_PERMANENTLY
			|| status_code == HTTP_FOUND)
		{
			buf_clear(&conn.write_buf);
			http_header_t *location = (http_header_t *)wr_cache_alloc(http_hcache);
			http_fetch_header(&conn.read_buf, "Location", location, (off_t)0);
			http_parse_host(location->value, conn.host);

			if (strstr(location->value, "https") && !option_set(OPT_USE_TLS))
			{
				/*
				 * conn_switch_to_tls() destroys our read/write buffers.
				 * copy the old read_buf so we can extract any cookies
				 * that we will need to set when resending our request.
				 */
				buf_t tmp_copy;

				buf_init(&tmp_copy, conn.read_buf.buf_size);
				buf_copy(&tmp_copy, &conn.read_buf);

				conn_switch_to_tls(&conn);

				buf_copy(&conn.read_buf, &tmp_copy);
				buf_destroy(&tmp_copy);
			}

			strncpy(conn.page, location->value, location->vlen);
			conn.page[location->vlen] = 0;
			wr_cache_dealloc(http_hcache, (void *)location);

			continue;
		}

		http_parse_links(http_lcache, &conn.read_buf);
		http_link_t *lp = (http_link_t *)http_lcache->cache;

		while (wr_cache_obj_used(http_lcache, (void *)lp))
		{
			printf("%s (%ld)\n", lp->url, lp->time_reaped);
			++lp;
		}

		break;
	}

	lp = (http_link_t *)http_lcache->cache;
	while (wr_cache_obj_used(http_lcache, (void *)lp))
		wr_cache_dealloc(http_lcache, (void *)lp);

	hp = (http_header_t *)http_hcache->cache;
	while (wr_cache_obj_used(http_hcache, (void *)hp))
		wr_cache_dealloc(http_hcache, (void *)hp);

	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_hcache);

	/*
	 * Destroys the read/write buffers in conn.
	 */
	close_connection(&conn);
	conn_destroy(&conn);

	free(http_state.base_page);

	exit(EXIT_SUCCESS);

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

		if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i]))
		{
			usage(EXIT_SUCCESS);
		}
		else
		if (!strcmp("--tls", argv[i]))
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
