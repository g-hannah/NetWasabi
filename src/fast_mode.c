#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "html.h"
#include "webreaper.h"

pthread_t workers[FAST_MODE_NR_WORKERS];
struct worker_ctx[FAST_MODE_NR_WORKERS];
pthread_mutex_t cache1_mtx;
pthread_mutex_t cache2_mtx;
pthread_barrier_t barrier;

wr_cache_t cache1;
wr_cache_t cache2;
wr_cache_t http_headers;
wr_cache_t http_cookies;

static void
__ctor __fast_mode_init(void)
{
	/*
	 * create caches
	 * initialise mutexes
	 */
}

static void
__dtor __fast_mode_fini(void)
{
	/*
	 * destroy caches
	 * destroy mutexes
	 */
}

int
do_fast_mode(const char *remote_host)
{
	int i;

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
	}
}
