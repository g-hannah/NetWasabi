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
static pthread_barrier_t start_barrier;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_cond_t cache_switch_cond;
static pthread_mutex_t eoc_mtx;
static volatile sig_atomic_t do_switch = 0;
static volatile sig_atomic_t nr_workers_eoc = 0;

static wr_cache_t *filling;
static wr_cache_t *draining;

struct cache_ctx cache1;
struct cache_ctx cache2;

static void
__ctor __fast_mode_init(void)
{
	if (!(cache1.cache = wr_cache_create(
			"fast_mode_url_cache1",
			sizeof(http_link_t),
			0,
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache1\n");
		goto fail;
	}

	if (!(cache2.cache = wr_cache_create(
			"fast_mode_url_cache2",
			sizeof(http_link_t),
			0,
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache2\n");
		goto fail;
	}

	if (pthread_barrier_init(&start_barrier, NULL, (FAST_MODE_NR_WORKERS + 1)) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise start barrier\n");
		goto fail;
	}

	if (pthread_mutex_init(&eoc_mtx, NULL) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise eoc mutex\n");
		goto fail;
	}

	cache1.root = NULL;
	cache2.root = NULL;

	return;

	fail:
	exit(EXIT_FAILURE);
}

static void
__dtor __fast_mode_fini(void)
{
	wr_cache_clear_all(cache1.cache);
	wr_cache_clear_all(cache2.cache);
	pthread_barrier_destroy(&start_barrier);
	pthread_mutex_destroy(&eoc_mtx);

	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);

	return;
}

static void
init_worker_environ(void)
{
	draining = cache1.cache;
	filling = cache2.cache;

	cache1.state = DRAINING;
	cache2.state = FILLING;

	return;
}

/**
 * worker_signal_eoc - signal that thread has reached end of a cycle
 */
static inline void
worker_signal_eoc(void)
{
	pthread_mutex_lock(&eoc_mtx);
	++nr_workers_eoc;
	pthread_mutex_unlock(&eoc_mtx);
	return;
}

#define __filling(c1, c2) ((c1).state == FILLING ? (c1) : (c2))
#define __draining(c1, c2) ((c1).state == DRAINING ? (c1) : (c2))

static void *
worker_reap(void *args)
{
	char *main_url = (char *)args;
	http_link_t *link = NULL;
	struct http_t *http = NULL;
	size_t len;

	if (!(http = http_new()))
	{
		put_error_msg("failed to get new HTTP object");
		goto thread_fail;
	}

	strcpy(http->full_url, main_url);
	if (!http_parse_host(http->full_url, http->host))
		goto thread_fail;

	if (!http_parse_page(http->full_url, http->page))
		goto thread_fail;

	if (http_connect(http) < 0)
	{
		put_error_msg("failed to connect to remove server");
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

		status_code = do_request(http);

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

				http_reconnect(ctx->http);

				goto next;
				break;
			default:
				put_error_msg("Unknown HTTP status code returned (%d)", status_code);
				goto fail;
		}

		next:

		if (parse_links(http, &__filling(cache1, cache2), &__draining(cache1, cache2)) < 0)
			put_error_msg("0x%lx: failed to parse URLs from page", pthread_self());
	}

	thread_exit:

	if (http)
	{
		http_disconnect(http);
		http_delete(http);
	}

	pthread_exit((void *)0);

	thread_fail:
	conn_destroy(&conn);
	pthread_exit((void *)-1);
}

/**
 * do_fast_mode - create FAST_MODE_NR_WORKERS threads to crawl the target website
 *				controlling the switching of caches from DRAINING to FILLING.
 *
 * @remote_host: the target website to crawl
 */
int
do_fast_mode(const char *remote_host)
{
	int i;
	int err;
	int status_code;
	int __done = 0;
	struct http_t *http = NULL;

	if (!(http = http_new()))
	{
		fprintf(stderr, "do_fast_mode: failed to get HTTP object\n");
		goto fail;
	}

	if (!http_parse_host(remote_host, http->host))
		goto fail;
	if (!http_parse_page(remote_host, http->page))
		goto fail;

	if (http_connect(http) < 0)
	{
		fprintf(stderr, "do_fast_mode: failed to connect to remote host\n");
		goto fail;
	}

	status_code = do_request(http);

	if (parse_links(http, &cache1, &cache2) < 0)
	{
		fprintf(stderr, "do_fast_mode: failed to parse links from starting page\n");
		goto fail;
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		if ((err = pthread_create(&workers[i], NULL, worker_reap, (void *)remote_host)) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail;
		}
	}

	http_disconnect(http);
	http_delete(http);

	pthread_barrier_wait(&start_barrier);

	while (1)
	{
		while (nr_workers_eoc < FAST_MODE_NR_WORKERS);

		nr_workers_eoc = 0;

		if (cache1.state == DRAINING)
		{
			draining = cache2.cache;
			filling = cache1.cache;

			cache2.state = DRAINING;
			cache1.state = FILLING;
		}
		else
		{
			draining = cache1.cache;
			filling = cache2.cache;

			cache1.state = DRAINING;
			cache2.state = FILLING;
		}

		if (!wr_cache_nr_used(draining) && !wr_cache_nr_used(filling))
			__done = 1;

		wr_cache_lock(draining);
		pthread_cond_broadcast(&cache_switch_cond);
		wr_cache_unlock(draining);

		if (__done)
			break;
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		pthread_join(workers[i], NULL);

	return 0;

	fail:
	return -1;
}
