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
#include "netwasabi.h"

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

static cache_t *filling;
static cache_t *draining;

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
	if (!(cache1.cache = cache_create(
			"fast_mode_url_cache1",
			sizeof(http_link_t),
			0,
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache1\n");
		goto fail;
	}

	if (!(cache2.cache = cache_create(
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
	cache_clear_all(cache1.cache);
	cache_clear_all(cache2.cache);
	pthread_barrier_destroy(&start_barrier);
	pthread_mutex_destroy(&eoc_mtx);

	cache_destroy(cache1.cache);
	cache_destroy(cache2.cache);
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

	update_cache_status(1, FL_CACHE_STATUS_DRAINING);
	update_cache_status(2, FL_CACHE_STATUS_FILLING);

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

/*
 * XXX: There may be an issue here resulting in us believing
 * we have processed all the URLs in the cache when in fact
 * we may have missed perhaps a part of the binary tree.
 */
static http_link_t *__get_next_link(struct cache_ctx *ctx)
{
	http_link_t *nptr = ctx->root;

	if (nr_draining > 0)
		assert(nptr);

	if (!nptr)
		return NULL;

/*
 * Search the binary tree in post-order.
 */
	while (1)
	{
		if (!nptr->left && !nptr->right)
			break;

		while (nptr->left)
			nptr = nptr->left;

		if (nptr->right)
			nptr = nptr->right;
	}

/*
 * We are artificially removing the object from the cache by
 * pointing the parent's pointer to NULL so that threads will
 * not come to this already-found node.
 *
 * The main thread will actually call cache_clear_all()
 * when toggling the cache states.
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

	--nr_draining;

	return nptr;
}

static void *
worker_crawl(void *args)
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

/*
 * Set up intitial state of caches (cache 1 state = DRAINING
 * cache 2 state = FILLING). Draw cache states on the screen,
 * etc. Thread that called init_worker_environ() then
 * has the responsibility of getting the very initial page
 * and filling cache 1 with its URLs (whilst the other
 * threads wait to start working at the START_BARRIER).
 */
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
				assert(cache1.root != NULL);
				nr_draining = cache_nr_used(cache1.cache);
				nr_filling = 0;
				wlog("[0x%lx] %d in cache1\n", pthread_self(), nr_draining);
			}
		}
	}

/*
 * Workers that weren't the first ones to call pthread_once() wait
 * here before starting to process the URLs in the DRAINING cache.
 */
	wlog("[0x%lx] Calling pthread_barrier_wait()\n", pthread_self());
	pthread_barrier_wait(&start_barrier);

	if (__threads_exit)
	{
		wlog("[0x%lx] __threads_exit == 1 ; jumping to label thread_exit\n", pthread_self());
		goto thread_exit;
	}

	while (1)
	{
		cache_lock(draining);

		link = __get_next_link(cache1.state == DRAINING ? &cache1 : &cache2);

		if (!link)
		{
			wlog("[0x%lx] __get_next_link gave me NULL\n", pthread_self());
			if (!cache_nr_used(filling))
			{
/*
 * There are no remaining URLs in the DRAINING cache, and we didn't
 * add any new ones to the FILLING cache. So it's time to exit now.
 */
				wlog("[0x%lx] URLs in draining = %d\n", pthread_self(), cache_nr_used(draining));
				wlog("[0x%lx] Unlocking cache and jumping to thread_exit\n", pthread_self());
				worker_signal_fin();
				worker_signal_eoc();
				cache_unlock(draining);
				goto thread_exit;
			}

/*
 * The DRAINING cache is now empty. We have URLs in the FILLING cache that
 * we will get once the main thread switches the cache states. So workers
 * will signal end of cache (EOC) by calling worker_signal_eoc(). When the
 * number of workers that have signaled EOC == FAST_MODE_NR_WORKERS, the main
 * thread will switch the cache states and adjust our pointers and then
 * broadcast to the workers that the condition has been met. The kernel will
 * wake them back up and they can continue to work on the URLs in the
 * now-DRAINING cache.
 */
			wlog("[0x%lx] Draining cache empty. Calling worker_signal_eoc()\n", pthread_self());
			wlog("[0x%lx] Waiting for main thread to broadcast condition\n", pthread_self());
			worker_signal_eoc();
			pthread_cond_wait(&cache_switch_cond, &draining->lock);
			continue;
		}
		else
		{
			wlog("[0x%lx] Got \"%s\" from cache\n", pthread_self(), link->url);

			if (draining == cache1.cache)
				update_cache1_count(nr_draining);
			else
				update_cache2_count(nr_draining);

			cache_unlock(draining);
		}

		strcpy(http->full_url, link->url);
		http_parse_host(link->url, http->host);
		http_parse_page(link->url, http->page);

		wlog("[0x%lx] Calling do_request()\n", pthread_self());
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

/*
 * TODO:
 *
 * There seems to be a deadlock happening when some of the threads
 * have called pthread_cond_wait() above and are waiting for the main
 * thread to broadcast, whereas one worker is just parsing the URLs
 * from the last link in the cache. It tries to lock FCTX->cache but
 * waits forever. The only time we lock the FILLING cache is below
 * when we want to update the number we have in it. When the threads
 * call pthread_cond_wait, it's for the DRAINING cache, and the mutex
 * is unlocked while the kernel places them on a waiting queue for
 * the condition to be broadcast. So even the DRAINING cache mutex
 * should be free.
 */
		if (parse_links(http, cache1.state == FILLING ? &cache1 : &cache2, cache1.state == DRAINING ? &cache1 : &cache2) < 0)
		{
			wlog("[0x%lx] Failed to parse URLs from %s\n", pthread_self(), link->url);
			put_error_msg("0x%lx: failed to parse URLs from page", pthread_self());
		}

		cache_lock(filling);

		nr_filling = cache_nr_used(filling);

		if (filling == cache1.cache)
			update_cache1_count(nr_filling);
		else
			update_cache2_count(nr_filling);

		cache_unlock(filling);

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

	if (!(cache1.cache = cache_create(
			"fast_mode_url_cache1",
			sizeof(http_link_t),
			0,
			http_link_cache_ctor,
			http_link_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache1\n");
		goto fail;
	}

	if (!(cache2.cache = cache_create(
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
		if ((err = pthread_create(&workers[i], &attr, worker_crawl, (void *)remote_host)) != 0)
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
/*
 * The workers didn't actually empty the cache. They artificially
 * remove URLs from the cache by searching the binary tree overlay
 * in postorder and when they find a node they adjust the pointer
 * in their parent node that points to them by setting it to %NULL.
 * So we call cache_clear_all() here to actually empty the cache.
 */
			cache_clear_all(cache1.cache);

			draining = cache2.cache;
			filling = cache1.cache;

			cache2.state = DRAINING;
			cache1.state = FILLING;

			update_cache_status(1, FL_CACHE_STATUS_FILLING);
			update_cache_status(2, FL_CACHE_STATUS_DRAINING);
		}
		else
		{
			cache_clear_all(cache2.cache);

			draining = cache1.cache;
			filling = cache2.cache;

			cache1.state = DRAINING;
			cache2.state = FILLING;

			update_cache_status(1, FL_CACHE_STATUS_DRAINING);
			update_cache_status(2, FL_CACHE_STATUS_FILLING);
		}

		wlog("[main] Broadcasting condition to worker threads\n");

		cache_lock(draining);
		pthread_cond_broadcast(&cache_switch_cond);
		cache_unlock(draining);
	}

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_cond_destroy(&cache_switch_cond);

	cache_clear_all(cache1.cache);
	cache_clear_all(cache2.cache);
	cache_destroy(cache1.cache);
	cache_destroy(cache2.cache);

	return 0;

	fail_release_mem:

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_cond_destroy(&cache_switch_cond);

	fail:

	if (cache1.cache)
		cache_destroy(cache1.cache);

	if (cache2.cache)
		cache_destroy(cache2.cache);

	return -1;
}
