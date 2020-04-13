#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
# include <errno.h>
# include <pthread.h>
# include <signal.h>
# include <unistd.h>
#elif define __MSWINDOWS__
# include <windows.h>
#else
# error "Do not know which OS we are running on..."
#endif

#ifdef __linux__
typedef pthread_t worker_t
typedef void * worker_func_return_t
typedef pthread_mutex_t mutex_t
# define thread_create(id, attribute, thread_func, func_args) \
	pthread_create((id), (attribute), (thread_func), (func_args))
# define mutex_lock(m) \
	pthread_mutex_lock(&(m))
# define mutex_unlock(m) \
	pthread_mutex_unlock(&(m))
# define mutex_create pthread_mutex_init
#elif defined __MSWINDOWS__
typedef HANDLE worker_t
typedef HANDLE mutex_t
typedef DWORD worker_func_return_t 
# define thread_create(id, attribute, thread_func, func_args) \
	CreateThread(NULL, 0, (thread_func), NULL, 0, NULL)
# define mutex_lock(m) \
	WaitForSingleObject((m), INFINITE)
# define mutex_unlock(m) \
	ReleaseMutex((m))
# define mutex_create CreateMutex(NULL, FALSE, NULL)
#endif

#include "btree.h"
#include "buffer.h"
#include "cache.h"
#include "cache_management.h"
#include "fast_mode.h"
#include "http.h"
#include "malloc.h"
#include "queue.h"
#include "screen_utils.h"
#include "netwasabi.h"

#define __option_set(w, o) ((w)->runtime_options & (o))
#define __set_option(w, o) ((w)->runtime_options |= (o))
#define __unset_option(w, o) ((w)->runtime_options &= ~(o))

#define __threshold(w) ((w)->cache_thresh)

struct worker_thread
{
	worker_t tid;
	int active;
	int idx;
	char *main_url;
	uint32_t runtime_options;
	unsigned int cache_thresh;
};

static queue_obj_t *URL_queue = NULL;
static btree_obj_t *tree_archived = NULL;

static struct worker_thread workers[FAST_MODE_NR_WORKERS];
static pthread_attr_t attr;
static pthread_barrier_t start_barrier;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_cond_t cache_switch_cond;

#define queue_lock(pthread_mutex_lock(&Mutex_Queue))
#define queue_unlock(pthread_mutex_lock(&Mutex_Queue))
#define tree_lock(pthread_mutex_lock(&Mutex_Tree))
#define tree_unlock(pthread_mutex_unlock(&Mutex_Tree))
static pthread_mutex_t Mutex_Queue;
static pthread_mutex_t Mutex_Tree;
//static pthread_mutex_t eoc_mtx;
static pthread_mutex_t Mutex_Finished;
static pthread_mutex_t Mutex_Reconnect;

static volatile long unsigned Initializing_Worker = 0;
static volatile int Threads_Exit = 0;
static volatile int Nr_Threads_Working = FAST_MODE_NR_WORKERS;

//static volatile int nr_workers_eoc = 0;

static volatile int nr_reconnected = 0;
static volatile sig_atomic_t __do_reconnect = 0;
static struct sigaction __old_sigpipe;
static struct sigaction __new_sigpipe;

static cache_t *Dead_URL_cache;

#ifdef DEBUG
# define WLOG_FILE "./fast_mode_log.txt"
FILE *wlogfp = NULL;
#endif

/**
 * A worker may write to a broken pipe after the
 * remote server resets the connection (possible
 * due to high volume of parallel requests). So
 * get all workers to disconnect and reconnect.
 */
static void
catch_sigpipe(int signo)
{
	if (SIGPIPE != signo)
		return;

	__do_reconnect = 1;
	return;
}

static void
wlog(const char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(wlogfp, fmt, args);
	va_end(args);

	fflush(wlogfp);
#else
	(void)fmt;
#endif
	return;
}

static void
__ctor __fast_mode_init(void)
{
#ifdef DEBUG
	wlogfp = fdopen(open(WLOG_FILE, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR), "r+");
#endif

	clear_struct(&__new_sigpipe);
	__new_sigpipe.sa_flags = 0;
	__new_sigpipe.sa_handler = catch_sigpipe;
	sigemptyset(&__new_sigpipe.sa_mask);

	if (sigaction(SIGPIPE, &__new_sigpipe, &__old_sigpipe) < 0)
	{
		fprintf(stderr, "__fast_mode_init: failed to set signal handler for SIGPIPE\n");
		goto fail;
	}

	return;

	fail:
	exit(EXIT_FAILURE);
}

static void
__dtor __fast_mode_fini(void)
{
#ifdef DEBUG
	fclose(wlogfp);
	wlogfp = NULL;
#endif

	sigaction(SIGPIPE, &__old_sigpipe, NULL);

	return;
}

/**
 * Initialise the shared variables and save
 * the thread id of the worker that called
 * the function for error checking and such
 * by the worker after returning.
 */
static void
init_worker_environ(void)
{
	//draining = cache1.cache;
	//filling = cache2.cache;

	//cache1.state = DRAINING;
	//cache2.state = FILLING;

	//update_cache_status(1, FL_CACHE_STATUS_DRAINING);
	//update_cache_status(2, FL_CACHE_STATUS_FILLING);

	__initialising_thread = pthread_self();

	return;
}

/**
 * worker_signal_eoc - signal that thread has reached end of a cycle
 *
static inline void
worker_signal_eoc(void)
{
	pthread_mutex_lock(&eoc_mtx);
	++nr_workers_eoc;
	pthread_mutex_unlock(&eoc_mtx);
	return;
}
*/

/**
 * worker_signal_fin - signal that thread has finished and is exiting
 */
static inline void
worker_signal_fin(struct worker_thread *wt)
{
	pthread_mutex_lock(&Mutex_Finished);
	--Nr_Threads_Working;
	pthread_mutex_unlock(&Mutex_Finished);

	wt->active = 0;

	return;
}

/**
 * worker_signal_recon - signal that thread has done a reconnect after
 *			signal handler set __do_reconnect to non-zero.
 */
static inline void
worker_signal_recon(void)
{
/*
 * Mutex not locked/unlocked here as should already be locked before
 * calling this func as we are also protecting __DO_RECONNECT with it.
 */
	++nr_reconnected;
	return;
}

/**
 * __get_next_link - get next URL from the URL cache
 * @ctx: the cache context containing the cache and the binary tree root
 *
static URL_t *__get_next_link(struct cache_ctx *ctx)
{
	URL_t *nptr = ctx->root;
	URL_t *parent = NULL;

	if (!nptr)
		return NULL;

/*
 * Search the binary tree in post-order.
 *
	while (1)
	{
		if (!nptr->left && !nptr->right)
		{
			wlog("[0x%lx] Found node @ %p%s\n", pthread_self(), nptr, nptr == ctx->root ? "(is root)" : "");
			break;
		}

		while (nptr->left)
		{
			parent = nptr;
			nptr = nptr->left;
		}

		if (nptr->right)
		{
			parent = nptr;
			nptr = nptr->right;
		}
	}

/*
 * We are artificially removing the object from the cache by
 * pointing the parent's pointer to NULL so that threads will
 * not come to this already-found node.
 *
 * The main thread will actually call cache_clear_all()
 * when toggling the cache states.
 *

	if (parent)
	{
		if (parent->right == nptr)
			parent->right = NULL;
		else
			parent->left = NULL;
	}
	else
	{
		ctx->root = NULL;
	}

	return nptr;
}
*/

static void *
worker_crawl(void *args)
{
	struct worker_thread *wt = (struct worker_thread *)args;
	struct http_t *http = NULL;
	queue_item_t *item = NULL;
	dead_url_t *dead = NULL;
	//URL_t *link = NULL;

	char *main_url;
	char URL[HTTP_URL_MAX];
	int status_code;
	size_t URL_len;

	main_url = wt->main_url;

	if (!(http = HTTP_new((uint32_t)pthread_self())))
	{
		put_error_msg("failed to get new HTTP object");
		goto thread_fail;
	}

	http->followRedirects = 1;
	http->verb = GET;

	strcpy(http->URL, main_url);

	http->ops->URL_parse_host(http->URL, http->host);
	http->ops->URL_parse_page(http->URL, http->page);

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

	if (Initializing_Worker == pthread_self())
	{
		http->ops->send_request(http);
		http->ops->recv_response(http);

		status_code = http->code;

		if (HTTP_OK != status_code)
		{
			wlog("[0x%lx] HTTP status code = %d\n", pthread_self(), status_code);
			Threads_Exit = 1;
		}
		else
		{
			wlog("[0x%lx] calling parse_links()\n", pthread_self());
			parse_links(http, URL_queue, tree_archived);

			if (!URL_queue->nr_items)
			{
				wlog("No URLs parsed from initial page\n");
				Threads_Exit = 1;
			}
			else
			{
				wlog("Parsed %d URLs from initial page\n", URL_queue->nr_items);
			}
		}
	}

/*
 * Workers that weren't the first ones to call pthread_once() wait
 * here before starting to process the URLs in the DRAINING cache.
 */
	wlog("[0x%lx] Calling pthread_barrier_wait()\n", pthread_self());
	pthread_barrier_wait(&start_barrier);

	if (Threads_Exit)
	{
		wlog("[0x%lx] __threads_exit == 1 ; jumping to label thread_exit\n", pthread_self());
		goto thread_exit;
	}

	while (1)
	{
		queue_lock();

		item = QUEUE_dequeue(URL_queue);

		queue_unlock();

		if (!item)
		{
			goto thread_exit;
		}

		URL_len = item->data_len;
		strncpy(URL, (char *)item->data, URL_len);
		URL[URL_len] = 0;

		cache_lock(Dead_URL_cache);
		// O(n)
		dead = search_dead_URL(Dead_URL_cache, link->URL);

		if (dead)
		{
			cache_unlock(Dead_URL_cache);
			continue;
		}

		cache_unlock(Dead_URL_cache);

		tree_lock();
		// ~O(logN)
		if (BTREE_search_data(tree_archived, (void *)URL, URL_len))
		{
			tree_unlock();
			continue;
		}

		tree_unlock();

		strcpy(http->URL, URL);

		http->ops->URL_parse_host(link->URL, http->host);
		http->ops->URL_parse_page(link->URL, http->page);

		http->ops->send_request(http);
		http->ops->recv_response(http);

		update_current_url(URL);

		switch(http->code)
		{
			case HTTP_OK:

				break;

			case HTTP_NOT_FOUND:

				cache_lock(Dead_URL_cache);
				cache_dead_URL(Dead_URL_cache, http->URL, http->code);
				cache_unlock(Dead_URL_cache);

			default:

				goto next;
		}

		archive_page(http);

		queue_lock();
		tree_lock();

		BTREE_put_data(tree_archived, (void *)URL, strlen(URL));
		parse_links(http, URL_queue, tree_archived);

		tree_unlock();
		queue_unlock();

	next:

		pthread_mutex_lock(&Mutex_Reconnect);

		if (__do_reconnect)
		{
			http_disconnect(http);
			http_connect(http);

			wlog("[0x%lx] Doing reconnect!\n");

			++nr_reconnected;

			if (nr_reconnected >= FAST_MODE_NR_WORKERS)
			{
				__do_reconnect = 0;
				nr_reconnected = 0;
			}
		}

		pthread_mutex_unlock(&Mutex_Reconnect);
	}

thread_exit:

	wlog("[0x%lx] Exiting\n", pthread_self());

	if (http)
	{
		http_disconnect(http);
		HTTP_delete(http);
	}

	worker_signal_fin(wt);
	//worker_signal_eoc();

	pthread_exit((void *)0);

thread_fail:

	wlog("[0x%lx] Failed -- exiting\n", pthread_self());
	worker_signal_fin(wt);
	//worker_signal_eoc();

	if (http)
	{
		http_disconnect(http);
		HTTP_delete(http);
	}

	pthread_exit((void *)-1);
}

/**
 * respawn_dead_threads - respawn dead threads
 *
 * Some threads may exit due to an error of some sort.
 * They will call worker_signal_fin(), which will
 * decrement NR_EXTANT_WORKERS. The main thread will
 * check this against FAST_MODE_NR_WORKERS, and call
 * this function if there are fewer extant than we
 * started with.
 */
static void
respawn_dead_threads(void)
{
	int i;
	int err;

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		if (!workers[i].active)
		{
			workers[i].active = 1;
			workers[i].runtime_options = runtime_options;

			if (option_set(OPT_CACHE_THRESHOLD))
				workers[i].cache_thresh = nwctx.config.cache_thresh;
			else
				workers[i].cache_thresh = UINT_MAX;

			if ((err = pthread_create(&workers[i].tid, &attr, worker_crawl, (void *)&workers[i])) != 0)
			{
				wlog("[main] Failed to respawn dead thread (%s)\n", strerror(err));
			}
			else
			{
				wlog("[main] Respawned dead thread\n");
				pthread_mutex_lock(&Mutex_Finished);
				++Nr_Threads_Working;
				pthread_mutex_unlock(&Mutex_Finished);
			}
		}
	}
}

int
do_fast_mode(char *remote_host)
{
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	URL_queue = QUEUE_object_new();
	tree_archived = BTREE_object_new();

	if (!(Dead_URL_cache = cache_create(
			"dead_url_cache",
			sizeof(Dead_URL_t),
			0,
			Dead_URL_cache_ctor,
			Dead_URL_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create dead url cache\n");
		goto fail;
	}

	pthread_barrier_init(&start_barrier, NULL, FAST_MODE_NR_WORKERS);

	pthread_mutex_init(&Mutex_Queue);
	pthread_mutex_init(&Mutex_Tree);
	//pthread_mutex_init(&eoc_mtx, NULL);
	pthread_mutex_init(&Mutex_Finished, NULL);
	pthread_mutex_init(&Mutex_Reconnect, NULL);

	//pthread_cond_init(&cache_switch_cond, NULL);

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		workers[i].active = 1;
		workers[i].idx = i;
		workers[i].main_url = strdup(remote_host); /* give each their own copy of the main URL */
		workers[i].runtime_options = runtime_options;

		if (option_set(OPT_CACHE_THRESHOLD))
			workers[i].cache_thresh = nwctx.config.cache_thresh;
		else
			workers[i].cache_thresh = UINT_MAX;

		if ((err = thread_create(&workers[i].tid, &attr, worker_crawl, (void *)&workers[i])) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail_release_mem;
		}
	}

	while (1)
	{
		pthread_mutex_lock(&Mutex_Finished);
		if (!Nr_Threads_Working)
		{
			pthread_mutex_unlock(&Mutex_Finished);
			break;
		}
		else
		{
			pthread_mutex_unlock(&Mutex_Finished);
			usleep(1000);
			continue;
		}
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		free(workers[i].main_url);

	pthread_attr_destroy(&attr);

	pthread_mutex_destroy(&Mutex_Queue);
	pthread_mutex_destroy(&Mutex_Tree);
	//pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&Mutex_Finished);
	pthread_mutex_destroy(&Mutex_Reconnect);

	//pthread_cond_destroy(&cache_switch_cond);

	pthread_barrier_destroy(&start_barrier);

	cache_clear_all(Dead_URL_cache);
	cache_destroy(Dead_URL_cache);

	return 0;

fail_release_mem:

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		free(workers[i].main_url);

	pthread_attr_destroy(&attr);

	pthread_mutex_destroy(&Mutex_Queue);
	pthread_mutex_destroy(&Mutex_Tree);
	//pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&Mutex_Finished);
	pthread_mutex_destroy(&Mutex_Reconnect);

	//pthread_cond_destroy(&cache_switch_cond);

	pthread_barrier_destroy(&start_barrier);

fail:

	if (Dead_URL_cache)
		cache_destroy(Dead_URL_cache);

	return -1;
}

/**
 * do_fast_mode - create FAST_MODE_NR_WORKERS threads to crawl the target website
 *				controlling the switching of caches from DRAINING to FILLING.
 *
 * @remote_host: the target website to crawl
 *
int
do_fast_mode(char *remote_host)
{
	int i;
	int err;

	cache1.cache = NULL;
	cache2.cache = NULL;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (!(cache1.cache = cache_create(
			"fast_mode_url_cache1",
			sizeof(URL_t),
			0,
			URL_cache_ctor,
			URL_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache1\n");
		goto fail;
	}

	if (!(cache2.cache = cache_create(
			"fast_mode_url_cache2",
			sizeof(URL_t),
			0,
			URL_cache_ctor,
			URL_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create cache2\n");
		goto fail;
	}

	if (!(Dead_URL_cache = cache_create(
			"dead_url_cache",
			sizeof(Dead_URL_t),
			0,
			Dead_URL_cache_ctor,
			Dead_URL_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create dead url cache\n");
		goto fail;
	}

#if 0
//	We're going to be asking the HTTP module
//	to automatically follow URL redirects.

	if (!(Redirected_URL_cache = cache_create(
			"redirected_url_cache",
			sizeof(Redirected_URL_t),
			0,
			Redirected_URL_cache_ctor,
			Redirected_URL_cache_dtor)))
	{
		fprintf(stderr, "__fast_mode_init: failed to create redirected url cache\n");
		goto fail;
	}
#endif

	pthread_barrier_init(&start_barrier, NULL, FAST_MODE_NR_WORKERS);
	pthread_mutex_init(&eoc_mtx, NULL);
	pthread_mutex_init(&fin_mtx, NULL);
	pthread_mutex_init(&recon_mtx, NULL);
	pthread_cond_init(&cache_switch_cond, NULL);

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
	{
		workers[i].active = 1;
		workers[i].idx = i;
		workers[i].main_url = strdup(remote_host); /* give each their own copy of the main URL *
		workers[i].runtime_options = runtime_options;

		if (option_set(OPT_CACHE_THRESHOLD))
			workers[i].cache_thresh = nwctx.config.cache_thresh;
		else
			workers[i].cache_thresh = UINT_MAX;

		if ((err = pthread_create(&workers[i].tid, &attr, worker_crawl, (void *)&workers[i])) != 0)
		{
			fprintf(stderr, "do_fast_mode: failed to create worker thread (%s)\n", strerror(err));
			goto fail_release_mem;
		}
	}

	while (1)
	{
		while (1)
		{
			pthread_mutex_lock(&eoc_mtx);
			if (nr_workers_eoc >= FAST_MODE_NR_WORKERS)
			{
				pthread_mutex_unlock(&eoc_mtx);
				break;
			}
			else
			{
				pthread_mutex_unlock(&eoc_mtx);
				usleep(1000);
				continue;
			}
		}

/*
 * Here there's no need to use the mutex because all the workers
 * have called pthread_cond_wait(), so there cannot be any
 * contention.
 *
		nr_workers_eoc = 0;

		usleep(1000);
		if (NR_EXTANT_WORKERS < FAST_MODE_NR_WORKERS)
		{
			if ((FAST_MODE_NR_WORKERS - NR_EXTANT_WORKERS) == FAST_MODE_NR_WORKERS)
			{
				if (!nr_filling && !nr_draining)
				{
					wlog("[main] Caches are empty. Workers have finished. Main thread exiting\n");
					update_operation_status("Finished crawling site");
					break;
				}
			}
/*
 * Otherwise, we have NR_EXTANT_WORKERS workers waiting for the main
 * thread to switch the cache states and call pthread_cond_broadcast().
 * Respawn the dead threads first and then toggle the cache states.
 *
			int nr_respawn = (FAST_MODE_NR_WORKERS - NR_EXTANT_WORKERS);

			pthread_barrier_destroy(&start_barrier);
			pthread_barrier_init(&start_barrier, NULL, nr_respawn);

			respawn_dead_threads();
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
 *
			deconstruct_btree(cache1.root, cache1.cache);
			cache_clear_all(cache1.cache);

			draining = cache2.cache;
			filling = cache1.cache;

			cache2.state = DRAINING;
			cache1.state = FILLING;

			nr_draining = cache_nr_used(cache2.cache);

			update_cache_status(1, FL_CACHE_STATUS_FILLING);
			update_cache_status(2, FL_CACHE_STATUS_DRAINING);
		}
		else
		{
			deconstruct_btree(cache2.root, cache2.cache);
			cache_clear_all(cache2.cache);

			draining = cache1.cache;
			filling = cache2.cache;

			cache1.state = DRAINING;
			cache2.state = FILLING;

			nr_draining = cache_nr_used(cache1.cache);

			update_cache_status(1, FL_CACHE_STATUS_DRAINING);
			update_cache_status(2, FL_CACHE_STATUS_FILLING);
		}

		wlog("[main] Broadcasting condition to worker threads\n");

		assert(nr_draining >= 0);
		nr_filling = 0;
		fill = 1;
		pthread_cond_broadcast(&cache_switch_cond);
	}

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		free(workers[i].main_url);

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_mutex_destroy(&recon_mtx);
	pthread_cond_destroy(&cache_switch_cond);
	pthread_barrier_destroy(&start_barrier);

	cache_clear_all(cache1.cache);
	cache_clear_all(cache2.cache);
	cache_destroy(cache1.cache);
	cache_destroy(cache2.cache);
	cache_clear_all(Dead_URL_cache);
	cache_destroy(Dead_URL_cache);

	return 0;

	fail_release_mem:

	for (i = 0; i < FAST_MODE_NR_WORKERS; ++i)
		free(workers[i].main_url);

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&eoc_mtx);
	pthread_mutex_destroy(&fin_mtx);
	pthread_mutex_destroy(&recon_mtx);
	pthread_cond_destroy(&cache_switch_cond);
	pthread_barrier_destroy(&start_barrier);

	fail:

	if (cache1.cache)
		cache_destroy(cache1.cache);

	if (cache2.cache)
		cache_destroy(cache2.cache);

	if (Dead_URL_cache)
		cache_destroy(Dead_URL_cache);

	return -1;
}
*/
