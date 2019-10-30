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
#include "html.h"
#include "webreaper.h"

pthread_t workers[FAST_MODE_NR_WORKERS];
struct worker_ctx worker_ctx[FAST_MODE_NR_WORKERS];
pthread_mutex_t cache1_mtx;
pthread_mutex_t cache2_mtx;
pthread_barrier_t barrier;

static volatile sig_atomic_t workers_begin = 0;

wr_cache_t cache1;
wr_cache_t cache2;
wr_cache_t http_headers;
wr_cache_t http_cookies;

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

	if (pthread_mutex_init(&cache1_mtx) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise cache 1 mutex\n");
		goto fail;
	}

	if (pthread_mutex_init(&cache2_mtx) != 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to initialise cache 2 mutex\n");
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

	wr_cache_destroy(cache1);
	wr_cache_destroy(cache2);
	wr_cache_destroy(http_headers);
	wr_cache_destroy(http_cookies);

	pthread_mutex_destroy(&cache1_mtx);
	pthread_mutex_destroy(&cache2_mtx);

	return;
}

int
do_fast_mode(const char *remote_host)
{
	int i;
	int err;

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

	fail:
	return -1;
}
