#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "fast_mode.h"
#include "http.h"
#include "webreaper.h"

static pthread_t workers[FAST_MODE_NR_WORKERS];
static pthread_barrier_t start_barrier;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_cond_t cache_switch_cond;
static pthread_mutex_t eoc_mtx;
static volatile sig_atomic_t nr_workers_eoc = 0;

static wr_cache_t *filling;
static wr_cache_t *draining;

struct cache_ctx cache1;
struct cache_ctx cache2;

static volatile long unsigned __initialising_thread = 0;
static int __threads_exit = 0;
static int nr_draining;
static int nr_filling;

static void
__ctor __fast_mode_init(void)
{
#if 0
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
#endif

	return;
}

static void
__dtor __fast_mode_fini(void)
{
#if 0
	wr_cache_clear_all(cache1.cache);
	wr_cache_clear_all(cache2.cache);
	pthread_barrier_destroy(&start_barrier);
	pthread_mutex_destroy(&eoc_mtx);

	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);
#endif

	return;
}

static void
init_worker_environ(void)
{
	draining = cache1.cache;
	filling = cache2.cache;

	cache1.state = DRAINING;
	cache2.state = FILLING;

	__initialising_thread = pthread_self();

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

/**
 * __get_next_link - get next URL from the URL cache
 * @ctx: the cache context containing the cache and the binary tree root
 */
static http_link_t *__get_next_link(struct cache_ctx ctx)
{
	http_link_t *nptr = ctx.root;

	if (!nptr)
		return NULL;

	while (1)
	{
		if (!nptr->left && !nptr->right)
			break;

		while (nptr->left)
			nptr = nptr->left;

		while (nptr->right)
			nptr = nptr->right;
	}

/*
 * We are artificially removing the object from the cache by
 * pointing the parent's pointer to NULL so that threads will
 * not come to this already-found node.
 */

	if (nptr->parent)
	{
		if (nptr->parent->right == nptr)
			nptr->parent->right = NULL;
		else
			nptr->parent->left = NULL;
	}
	else
	{
		ctx.root = NULL;
	}

	return nptr;
}

static void *
worker_reap(void *args)
{
	char *main_url = (char *)args;
	http_link_t *link = NULL;
	struct http_t *http = NULL;
	int status_code;

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

	strcpy(http->primary_host, http->host);

	if (http_connect(http) < 0)
	{
		put_error_msg("failed to connect to remove server");
		goto thread_fail;
	}

	pthread_once(&once, init_worker_environ);

	if (__initialising_thread == pthread_self())
	{
		status_code = do_request(http);
		if (HTTP_OK != status_code)
		{
			__threads_exit = 1;
		}
		else
		{
			if (parse_links(http, &cache1, &cache2) < 0)
			{
				put_error_msg("Failed to get URLs from start page");
				__threads_exit = 1;
			}
			else
			{
				nr_draining = wr_cache_nr_used(cache1.cache);
				nr_filling = 0;
			}
		}
	}

	pthread_barrier_wait(&start_barrier);

	if (__threads_exit)
		goto thread_exit;

	while (1)
	{
		wr_cache_lock(draining);

		link = __get_next_link(container_of(draining, (struct cache_ctx), cache));

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
		else
		{
			--nr_draining;
			wr_cache_unlock(draining);
		}

		status_code = do_request(http);

		switch((unsigned int)status_code)
		{
			case HTTP_OK:
			case HTTP_GONE:
			case HTTP_NOT_FOUND:
				break;
			case HTTP_BAD_REQUEST:
				buf_clear(&http_wbuf(http));
				buf_clear(&http_rbuf(http));

				http_reconnect(http);

				goto next;
				break;
			case HTTP_METHOD_NOT_ALLOWED:
			case HTTP_FORBIDDEN:
			case HTTP_INTERNAL_ERROR:
			case HTTP_BAD_GATEWAY:
			case HTTP_SERVICE_UNAV:
			case HTTP_GATEWAY_TIMEOUT:
				buf_clear(&http_wbuf(http));
				buf_clear(&http_rbuf(http));

				http_reconnect(http);

				goto next;
				break;
			case HTTP_IS_XDOMAIN:
			case HTTP_ALREADY_EXISTS:
			case FL_HTTP_SKIP_LINK:
				goto next;
			case HTTP_OPERATION_TIMEOUT:

				buf_clear(&http_rbuf(http));

				if (!http->host[0])
					strcpy(http->host, http->primary_host);

				http_reconnect(http);

				goto next;
				break;
			default:
				put_error_msg("Unknown HTTP status code returned (%d)", status_code);
				goto thread_fail;
		}

		next:

		if (parse_links(http, cache1.state == FILLING ? &cache1 : &cache2, cache1.state == DRAINING ? &cache1 : &cache2) < 0)
			put_error_msg("0x%lx: failed to parse URLs from page", pthread_self());

		wr_cache_lock(filling);
		nr_filling = wr_cache_nr_used(filling);
		wr_cache_unlock(filling);
	}

	thread_exit:

	if (http)
	{
		http_disconnect(http);
		http_delete(http);
	}

	pthread_exit((void *)0);

	thread_fail:

	if (http)
	{
		http_disconnect(http);
		http_delete(http);
	}

	pthread_exit((void *)-1);
}

/**
 * do_fast_mode - create FAST_MODE_NR_WORKERS threads to crawl the target website
 *				controlling the switching of caches from DRAINING to FILLING.
 *
 * @remote_host: the target website to crawl
 */
int
do_fast_mode(char *remote_host)
{
	int i;
	int err;
	int __done = 0;

	cache1.cache = NULL;
	cache2.cache = NULL;

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

	pthread_barrier_init(&start_barrier, NULL, FAST_MODE_NR_WORKERS);

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		if ((err = pthread_create(&workers[i], NULL, worker_reap, (void *)remote_host)) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail;
		}
	}

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

		if (!nr_draining && !nr_filling)
			__done = 1;

		wr_cache_lock(draining);
		pthread_cond_broadcast(&cache_switch_cond);
		wr_cache_unlock(draining);

		if (__done)
			break;
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		pthread_join(workers[i], NULL);

	wr_cache_clear_all(cache1.cache);
	wr_cache_clear_all(cache2.cache);
	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);

	return 0;

	fail:

	if (cache1.cache)
		wr_cache_destroy(cache1.cache);

	if (cache2.cache)
		wr_cache_destroy(cache2.cache);

	return -1;
}
