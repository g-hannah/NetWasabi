#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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
#include "screen_utils.h"
#include "webreaper.h"

static pthread_t workers[FAST_MODE_NR_WORKERS];
static pthread_barrier_t start_barrier;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_cond_t cache_switch_cond;
static pthread_mutex_t eoc_mtx;
static pthread_mutex_t fin_mtx;
static volatile int nr_workers_eoc = 0;
static volatile int nr_workers_fin = 0;
static volatile long unsigned __initialising_thread = 0;
static volatile int __threads_exit = 0;
static volatile int nr_draining = 0;
static volatile int nr_filling = 0;

static wr_cache_t *filling;
static wr_cache_t *draining;

struct cache_ctx cache1;
struct cache_ctx cache2;

#ifdef DEBUG
int WDEBUG = 1;
#else
int WDEBUG = 0;
#endif

#define WLOG_FILE "./fast_mode_log.txt"
FILE *wlogfp = NULL;

static void
wlog(const char *fmt, ...)
{
	if (!WDEBUG)
		return;

	va_list args;

	va_start(args, fmt);
	vfprintf(wlogfp, fmt, args);
	va_end(args);

	return;
}

static void
__ctor __fast_mode_init(void)
{
#ifdef DEBUG
	wlogfp = fdopen(open(WLOG_FILE, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR), "r+");
#endif
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
#ifdef DEBUG
	fclose(wlogfp);
	wlogfp = NULL;
#endif
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
 * worker_signal_fin - signal that thread has finished and is exiting
 */
static inline void
worker_signal_fin(void)
{
	pthread_mutex_lock(&fin_mtx);
	++nr_workers_fin;
	pthread_mutex_unlock(&fin_mtx);
	return;
}

/**
 * __get_next_link - get next URL from the URL cache
 * @ctx: the cache context containing the cache and the binary tree root
 */
static http_link_t *__get_next_link(struct cache_ctx *ctx)
{
	http_link_t *nptr = ctx->root;

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
		ctx->root = NULL;
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
		wlog("[0x%lx] I am the initialising thread\n", pthread_self());

		http_send_request(http, GET);
		http_recv_response(http);

		status_code = http_status_code_int(&http->conn.read_buf);

		if (HTTP_OK != status_code)
		{
			wlog("[0x%lx] HTTP status code = %d\n", pthread_self(), status_code);
			__threads_exit = 1;
		}
		else
		{
			wlog("[0x%lx] calling parse_links()\n", pthread_self());
			if (parse_links(http, &cache1, &cache2) < 0)
			{
				wlog("[0x%lx] failed to parse URLs from page\n", pthread_self());
				put_error_msg("Failed to get URLs from start page");
				__threads_exit = 1;
			}
			else
			{
				nr_draining = wr_cache_nr_used(cache1.cache);
				nr_filling = 0;
				wlog("[0x%lx] %d in cache1\n", pthread_self(), nr_draining);
			}
		}
	}

	wlog("[0x%lx] Calling pthread_barrier_wait()\n", pthread_self());
	pthread_barrier_wait(&start_barrier);

	if (__threads_exit)
	{
		wlog("[0x%lx] __threads_exit == 1 ; jumping to label thread_exit\n", pthread_self());
		goto thread_exit;
	}

	while (1)
	{
		wr_cache_lock(draining);

		link = __get_next_link(cache1.state == DRAINING ? &cache1 : &cache2);

		if (!link)
		{
			wlog("[0x%lx] __get_next_link gave me NULL\n", pthread_self());
			if (!wr_cache_nr_used(filling))
			{
				wlog("[0x%lx] URLs in draining = %d\n", pthread_self(), wr_cache_nr_used(draining));
				wlog("[0x%lx] Unlocking cache and jumping to thread_exit\n", pthread_self());
				worker_signal_fin();
				worker_signal_eoc();
				wr_cache_unlock(draining);
				goto thread_exit;
			}

			wlog("[0x%lx] Draining cache empty. Calling worker_signal_eoc()\n", pthread_self());
			wlog("[0x%lx] Waiting for main thread to broadcast condition\n", pthread_self());
			worker_signal_eoc();
			pthread_cond_wait(&cache_switch_cond, &draining->lock);
			continue;
		}
		else
		{
			wlog("[0x%lx] Got URL from cache\n", pthread_self());
			--nr_draining;

			if (draining == cache1.cache)
				update_cache1_count(nr_draining);
			else
				update_cache2_count(nr_draining);

			wr_cache_unlock(draining);
		}

		wlog("[0x%lx] Calling do_request()\n", pthread_self());

		strcpy(http->full_url, link->url);
		http_parse_host(link->url, http->host);
		http_parse_page(link->url, http->page);

		status_code = do_request(http);

		update_current_url(link->url);

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
				wlog("[0x%lx] Received erroneous status code %d\n", pthread_self(), status_code);
				put_error_msg("Unknown HTTP status code returned (%d)", status_code);
				worker_signal_fin();
				worker_signal_eoc();
				goto thread_fail;
		}

		next:

		if (parse_links(http, cache1.state == FILLING ? &cache1 : &cache2, cache1.state == DRAINING ? &cache1 : &cache2) < 0)
			put_error_msg("0x%lx: failed to parse URLs from page", pthread_self());

		wr_cache_lock(filling);

		nr_filling = wr_cache_nr_used(filling);

		if (filling == cache1.cache)
			update_cache1_count(nr_filling);
		else
			update_cache2_count(nr_filling);

		wr_cache_unlock(filling);

		wlog("[0x%lx] Archiving page\n", pthread_self());
		archive_page(http);
	}

	thread_exit:

	wlog("[0x%lx] Exiting\n", pthread_self());

	if (http)
	{
		http_disconnect(http);
		http_delete(http);
	}

	pthread_exit((void *)0);

	thread_fail:

	wlog("[0x%lx] Failed -- exiting\n", pthread_self());

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
	pthread_attr_t attr;

	cache1.cache = NULL;
	cache2.cache = NULL;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

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
	pthread_mutex_init(&eoc_mtx, NULL);
	pthread_mutex_init(&fin_mtx, NULL);
	pthread_cond_init(&cache_switch_cond, NULL);

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		if ((err = pthread_create(&workers[i], &attr, worker_reap, (void *)remote_host)) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail_release_mem;
		}
	}

	while (1)
	{
		while (nr_workers_eoc < FAST_MODE_NR_WORKERS);

		nr_workers_eoc = 0;

		if (nr_workers_fin == FAST_MODE_NR_WORKERS)
		{
			wlog("[main] Both caches empty ; workers have quit. Quitting now\n");
			break;
		}

		wlog("[main] Switching cache states\n");

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

		wlog("[main] Broadcasting condition to worker threads\n");

		wr_cache_lock(draining);
		pthread_cond_broadcast(&cache_switch_cond);
		wr_cache_unlock(draining);
	}

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_cond_destroy(&cache_switch_cond);

	wr_cache_clear_all(cache1.cache);
	wr_cache_clear_all(cache2.cache);
	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);

	return 0;

	fail_release_mem:

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_cond_destroy(&cache_switch_cond);

	fail:

	if (cache1.cache)
		wr_cache_destroy(cache1.cache);

	if (cache2.cache)
		wr_cache_destroy(cache2.cache);

	return -1;
}
