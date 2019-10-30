#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "fast_mode.h"
#include "http.h"
#include "misc.h"
#include "queue.h"
#include "request.h"
#include "webreaper.h"

static pthread_t workers[FAST_MODE_NR_WORKERS];
static struct worker_ctx worker_ctx[FAST_MODE_NR_WORKERS];
static pthread_barrier_t barrier;
static volatile sig_atomic_t workers_begin = 0;
static volatile sig_atomic_t cache_switch = 0;

static int goal;

static wr_cache_t cache1;
static wr_cache_t cache2;
static wr_cache_t http_headers;
static wr_cache_t http_cookies;
static wr_cache_t queue_cache;

static int
queue_cache_ctor(void *obj)
{
	struct queue_item *qi = (struct queue_item *)obj;

	qi->next = qi->prev = NULL;
	qi->data = (void *)NULL;
	qi->size = (size_t)0;
}

static void
__ctor __fast_mode_init(void)
{
	if (!(cache1 = wr_cache_create(
			"fast_mode_url_cache1",
			0,
			sizeof(http_link_t),
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache1\n");
		goto fail;
	}

	if (!(cache2 = wr_cache_create(
			"fast_mode_url_cache2",
			0,
			sizeof(http_link_t),
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache2\n");
		goto fail;
	}

	if (!(http_headers = wr_cache_create(
			"fast_mode_header_cache",
			0,
			sizeof(http_header_t),
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create HTTP header cache\n");
		goto fail;
	}

	if (!(http_cookies = wr_cache_create(
			"fast_mode_cookie_cache",
			0,
			sizeof(http_header_t),
			http_header_cache_ctor,
			http_header_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create HTTP cookie cache\n");
		goto fail;
	}

	if (!(queue_cache = wr_cache_create(
			"fast_mode_queue_cache",
			0,
			sizeof(struct queue_item),
			queue_cache_ctor,
			NULL)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create queue items cache\n");
		goto fail;
	}

	if (pthread_barrier_init(&barrier, NULL, FAST_MODE_NR_WORKERS) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise worker barrier\n");
		goto fail;
	}

	return;

	fail:
	exit(EXIT_FAILURE);
}

static void
__dtor __fast_mode_fini(void)
{
	wr_cache_clear_all(cache1);
	wr_cache_clear_all(cache2);
	wr_cache_clear_all(http_headers);
	wr_cache_clear_all(http_cookies);
	wr_cache_clear_all(queue_cache);

	wr_cache_destroy(cache1);
	wr_cache_destroy(cache2);
	wr_cache_destroy(http_headers);
	wr_cache_destroy(http_cookies);
	wr_cache_destroy(queue_cache);

	return;
}

static void *
worker_reap(void *args)
{
	struct worker_ctx *ctx = (struct worker_ctx *)args;
	wr_cache_t *cache1 = ctx->cache1;
	wr_cache_t *cache2 = ctx->cache2;
	http_link_t *link = NULL;
	size_t len;
	int goal;
	connection_t conn;

	conn_init(&conn);

	strcpy(conn.full_url, ctx->main_url);
	http_parse_host(conn.full_url, conn.host);
	http_parse_page(conn.full_url, conn.page);

	if (open_connection(&conn) < 0)
	{
		fprintf(stderr, "0x%lx: failed to connect to remote server\n", pthread_self());
		goto thread_fail;
	}

	while (!workers_begin);

	while (1)
	{
		if (!cache_switch)
		{
			wr_cache_lock(&cache1->lock);

			link = wr_cache_next_used(cache1);
			len = strlen(link->url);
			strcpy(conn.full_url, link->url);
			wr_cache_dealloc(cachep, (void *)link);

			wr_cache_unlock(&cache1->lock);
		}
		else
		{
			wr_cache_lock(&cache2->lock);

			link = wr_cache_next_used(cache2);
			len = strlen(link->url);
			strcpy(conn.full_url, link->url);
			wr_cache_dealloc(cache2, (void *)link);

			wr_cache_unlock(&cache2->lock);
		}

		status_code = do_request(conn);
		switch((unsigned int)status_code)
		{
			case HTTP_OK:
			case HTTP_GONE:
			case HTTP_NOT_FOUND:
				break;
			case HTTP_BAD_REQUEST:
				if (wr_cache_nr_used(cookies) > 0)
					wr_cache_clear_all(cookies);

				buf_clear(wbuf);
				buf_clear(rbuf);

				reconnect(conn);

				goto next;
				break;
			case HTTP_METHOD_NOT_ALLOWED:
			case HTTP_FORBIDDEN:
			case HTTP_INTERNAL_ERROR:
			case HTTP_BAD_GATEWAY:
			case HTTP_SERVICE_UNAV:
			case HTTP_GATEWAY_TIMEOUT:
				if (wr_cache_nr_used(cookies) > 0)
					wr_cache_clear_all(cookies);

				buf_clear(wbuf);
				buf_clear(rbuf);

				reconnect(conn);

				goto next;
				break;
			case HTTP_IS_XDOMAIN:
			case HTTP_ALREADY_EXISTS:
			/*
			 * Ignore 302 Found because it is used a lot for obtaining a random
			 * link, for example a random wiki article (Special:Random).
			 */
			case HTTP_FOUND:
			case FL_HTTP_SKIP_LINK:
				goto next;
			case FL_OPERATION_TIMEOUT:

				buf_clear(rbuf);

				if (!conn->host[0])
					strcpy(conn->host, conn->primary_host);

				reconnect(conn);

				goto next;
				break;
			default:
				put_error_msg("Unknown HTTP status code returned (%d)", status_code);
				goto fail;
		}
	}

	pthread_exit((void *)0);

	thread_fail:
	conn_destroy(&conn);
	pthread_exit((void *)-1);
}

int
do_fast_mode(connection_t *conn, const char *remote_host)
{
	int i;
	int err;
	int status_code;

	status_code = do_request(conn);
	if (!http_status_ok(status_code))
		goto fail;

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		worker_ctx[i].cache1 = cache1;
		worker_ctx[i].cache2 = cache2;

		if ((err = pthread_create(&workers[i], NULL, worker_reap, (void *)&worker_ctx[i])) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail;
		}
	}

	workers_begin = 1;

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		pthread_join(workers[i]);

	return 0;

	fail:
	return -1;
}
