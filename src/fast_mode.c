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
#include "request.h"
#include "webreaper.h"

static pthread_t workers[FAST_MODE_NR_WORKERS];
static struct worker_ctx worker_ctx[FAST_MODE_NR_WORKERS];
static pthread_barrier_t barrier;
static pthread_barrier_t start_barrier;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_cond_t cache_switch_cond;
static pthread_mutex_t cache_switch_mtx;
static volatile sig_atomic_t do_switch = 0;
static volatile sig_atomic_t nr_workers_eoc = 0;

static wr_cache_t *cache1;
static wr_cache_t *cache2;
static wr_cache_t *http_headers;
static wr_cache_t *filling;
static wr_cache_t *draining;

struct cache_ctx cache_ctx1;
struct cache_ctx cache_ctx2;

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

	if (pthread_mutex_init(&cache_switch_mtx, NULL) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise cache switching mutex\n");
		goto fail;
	}

	if (pthread_barrier_init(&barrier, NULL, FAST_MODE_NR_WORKERS) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise worker barrier\n");
		goto fail;
	}

	if (pthread_barrier_init(&start_barrier, NULL, (FAST_MODE_NR_WORKERS + 1)) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise start barrier\n");
		goto fail;
	}

	cache_ctx1.cache = cache1;
	cache_ctx1.root = NULL;
	cache_ctx2.cache = cache2;
	cache_ctx2.root = NULL;

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
	pthread_mutex_destroy(&cache_switch_mtx);
	pthread_barrier_destroy(&barrier);
	pthread_barrier_destroy(&start_barrier);

	wr_cache_destroy(cache1);
	wr_cache_destroy(cache2);
	wr_cache_destroy(http_headers);
	wr_cache_destroy(http_cookies);

	return;
}

static void
init_worker_environ(void)
{
	draining = cache1;
	filling = cache2;
	return;
}

/**
 * worker_signal_eoc - signal that thread has reached end of a cycle
 */
static inline void
worker_signal_eoc(void)
{
	++nr_workers_eoc;
	return;
}

static void *
worker_reap(void *args)
{
	struct worker_ctx *ctx = (struct worker_ctx *)args;
	wr_cache_t *cache1 = ctx->cache1;
	wr_cache_t *cache2 = ctx->cache2;
	wr_cache_t *fcache; /* pointer to current filling cache */
	wr_cache_t *dcache; /* pointer to current draining cache */
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

	pthread_barrier_wait(&start_barrier);
	pthread_once(&once, init_worker_environ);

	while (1)
	{
		wr_cache_lock(draining);

		link = wr_cache_next_used(draining);

		if (!link)
		{
			if (!wr_cache_nr_used(filling))
			{
				wr_cache_unlock(draining);
				goto thread_exit;
			}

			worker_signal_eoc();
			pthread_cond_wait(&cache_switch_cond, &draining->lock);
			continue;
		}

		status_code = do_request(conn);
		switch((unsigned int)status_code)
		{
			case HTTP_OK:
			case HTTP_GONE:
			case HTTP_NOT_FOUND:
				break;
			case HTTP_BAD_REQUEST:
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

		next:
	}

	thread_exit:
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
	{
		fprintf(stderr, "do_fast_mode: failed to get page from web server (HTTP status code: %u)\n", (unsigned int)status_code);
		goto fail;
	}

	if (parse_links(

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

	pthread_barrier_wait(&start_barrier);

	while (1)
	{
		while (nr_workers_eoc < FAST_MODE_NR_WORKERS);

		nr_workers_eoc = 0;
		if (draining == cache1)
		{
			draining = cache2;
			filling = cache1;
		}
		else
		{
			draining = cache1;
			filling = cache2;
		}

		wr_cache_lock(draining);

		pthread_cond_broadcast(&cache_switch_cond);
		pthread_cond_destroy(&cache_switch_cond);
		cache_switch_cond = PTHREAD_COND_INITIALIZER;

		wr_cache_unlock(draining);
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		pthread_join(workers[i]);

	return 0;

	fail:
	return -1;
}
