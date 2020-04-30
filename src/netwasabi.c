#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h> /* for mkdir() */
#include <unistd.h>
#include "btree.h"
#include "buffer.h"
#include "cache.h"
#include "cache_management.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "screen_utils.h"
#include "utils_url.h"
#include "netwasabi.h"
#include "queue.h"

#define CREATE_FLAGS O_RDWR|O_CREAT|O_TRUNC
#define CREATE_MODE S_IRUSR|S_IWUSR

static cache_t *Dead_URL_cache = NULL;

#ifdef DEBUG
# define __LOG_FILE__ "./nw_log.txt"
FILE *logfp = NULL;
#endif

static void
Log(const char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(logfp, fmt, args);
	fflush(logfp);
	va_end(args);
#else
	(void)fmt;
#endif

	return;
}

#ifdef DEBUG
static void
__ctor __dbg_init(void)
{
	logfp = fdopen(open(__LOG_FILE__, CREATE_FLAGS, CREATE_MODE), "r+");

	assert(logfp);

	return;
}

static void
__dtor __dbg_fini(void)
{
	fclose(logfp);
	logfp = NULL;

	return;
}
#endif

static sigset_t oldset;
static sigset_t newset;

#define BLOCK_SIGNAL(signal)\
do {\
	sigemptyset(&newset);\
	sigaddset(&newset, (signal));\
	sigprocmask(SIG_BLOCK, &newset, &oldset);\
} while (0)

#define UNBLOCK_SIGNAL(signal) sigprocmask(SIG_SETMASK, &oldset, NULL)

int nr_reaped = 0;
int current_depth = 0;
int url_cnt = 0;

void
update_bytes(size_t bytes)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_BYTES_UP);
	right(UPDATE_BYTES_RIGHT);
	fprintf(stderr, "%12lu", bytes);
	reset_left();
	down(UPDATE_BYTES_UP);

	pthread_mutex_unlock(&screen_mutex);
}

void
update_cache1_count(int count)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CACHE1_COUNT_UP);
	right(UPDATE_CACHE1_COUNT_RIGHT);
	fprintf(stderr, "%4d", count);
	reset_left();
	down(UPDATE_CACHE1_COUNT_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_cache2_count(int count)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CACHE2_COUNT_UP);
	right(UPDATE_CACHE2_COUNT_RIGHT);
	fprintf(stderr, "%4d", count);
	reset_left();
	down(UPDATE_CACHE2_COUNT_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_cache_status(int cache, int status_flag)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CACHE_STATUS_UP);
	right(cache == 1 ? UPDATE_CACHE1_STATUS_RIGHT : UPDATE_CACHE2_STATUS_RIGHT);
	
	switch(status_flag)
	{
		default:
		case FL_CACHE_STATUS_FILLING:
			fprintf(stderr, "%s (filling) %s", COL_DARKGREEN, COL_END);
			break;
		case FL_CACHE_STATUS_DRAINING:
			fprintf(stderr, " %s(draining)%s", COL_LIGHTGREY, COL_END);
			break;
		case FL_CACHE_STATUS_FULL:
			fprintf(stderr, "   %s(full)  %s ", COL_DARKRED, COL_END);
			break;
	}

	reset_left();
	down(UPDATE_CACHE_STATUS_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_current_url(const char *url)
{
	size_t url_len = strlen(url);
	int too_long = 0;
	int max_len = OUTPUT_TABLE_COLUMNS - 10;

	if (url_len >= (size_t)max_len)
		too_long = 1;

	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CURRENT_URL_UP);
	clear_line();
	right(UPDATE_CURRENT_URL_RIGHT);

	fprintf(stderr, " %s%.*s%s",
		ACTION_ING_STR,
		too_long ? max_len : (int)url_len,
		url,
		too_long ? "..." : "");

	reset_left();
	down(UPDATE_CURRENT_URL_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_current_local(const char *url)
{
	size_t url_len = strlen(url);
	int too_long = 0;
	int max_len = OUTPUT_TABLE_COLUMNS - 18;

	if (url_len >= (size_t)max_len)
		too_long = 1;

	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CURRENT_LOCAL_UP);
	clear_line();

	if (!url_len)
		goto out_release_lock;

	right(UPDATE_CURRENT_LOCAL_RIGHT);

	fprintf(stderr, " %sCreated %s%.*s%s%s",
		ACTION_DONE_STR,
		COL_DARKGREY,
		too_long ? max_len : (int)url_len,
		url,
		too_long ? "..." : "",
		COL_END);

	out_release_lock:
	reset_left();
	down(UPDATE_CURRENT_LOCAL_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_operation_status(const char *status_string, ...)
{
	size_t len;
	int too_long = 0;
	int max_len = OUTPUT_TABLE_COLUMNS - 6;
	va_list args;
	static char tmp[256];

	va_start(args, status_string);
	vsprintf(tmp, status_string, args);
	va_end(args);

	len = strlen(tmp);

	if (len >= (size_t)max_len)
		too_long = 1;

	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_OP_STATUS_UP);
	clear_line();

	if (!len)
		goto out_release_lock;

	right(UPDATE_OP_STATUS_RIGHT);

	fprintf(stderr, "%s(%.*s%s)%s",
			COL_LIGHTRED,
			too_long ? max_len : (int)len,
			tmp,
			too_long ? "..." : "",
			COL_END);

	out_release_lock:
	reset_left();
	down(UPDATE_OP_STATUS_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_connection_state(struct http_t *http, int state)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_CONN_STATE_UP);
	clear_line();
	right(UPDATE_CONN_STATE_RIGHT);

	switch(state)
	{
		default:
		case FL_CONNECTION_CONNECTED:
			fprintf(stderr, "%sConnected%s to %s%s%s (%s)", COL_DARKGREEN, COL_END, COL_RED, http->host, COL_END, http->conn.host_ipv4);
			break;
		case FL_CONNECTION_DISCONNECTED:
			fprintf(stderr, "%sDisconnected%s", COL_LIGHTGREY, COL_END);
			break;
		case FL_CONNECTION_CONNECTING:
			fprintf(stderr, "Connecting to server %s at %s", http->host, http->conn.host_ipv4);
			break;
	}

	reset_left();
	down(UPDATE_CONN_STATE_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
update_status_code(int status_code)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_STATUS_CODE_UP);

	right(UPDATE_STATUS_CODE_RIGHT);

	switch(status_code)
	{
		case HTTP_OK:
		//case HTTP_ALREADY_EXISTS:
			fprintf(stderr, "%s%3d%s", COL_DARKGREEN, status_code, COL_END);
			break;
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_FOUND:
		case HTTP_SEE_OTHER:
			fprintf(stderr, "%s%3d%s", COL_ORANGE, status_code, COL_END);
			break;
		default:
			fprintf(stderr, "%s%3d%s", COL_RED, status_code, COL_END);
	}

	reset_left();
	down(UPDATE_STATUS_CODE_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
put_error_msg(const char *fmt, ...)
{
	va_list args;
	static char tmp[256];
	size_t len;
	int go_right = 1;

	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	va_end(args);

	len = strlen(tmp);

	if (len < OUTPUT_TABLE_COLUMNS)
		go_right = (OUTPUT_TABLE_COLUMNS - len);

	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_ERROR_MSG_UP);
	clear_line();
	right(go_right);

	fprintf(stderr, "%s%.*s%s", COL_RED, !go_right ? OUTPUT_TABLE_COLUMNS : (int)len, tmp, COL_END);
	reset_left();
	down(UPDATE_ERROR_MSG_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

void
clear_error_msg(void)
{
	pthread_mutex_lock(&screen_mutex);

	reset_left();
	up(UPDATE_ERROR_MSG_UP);
	clear_line();
	down(UPDATE_ERROR_MSG_UP);

	pthread_mutex_unlock(&screen_mutex);
	return;
}

#if 0
void
deconstruct_btree(URL_t *root, cache_t *cache)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
	if (root == (URL_t *)NULL)
	{
		return;
	}
#pragma GCC diagnostic pop

	assert((char *)root >= (char *)cache->cache && ((char *)root - (char *)cache->cache) < cache->cache_size);

	if (root->left)
	{
		deconstruct_btree(root->left, cache);
	}

	if (root->right)
	{
		deconstruct_btree(root->right, cache);
	}

	root->left = NULL;
	root->right = NULL;

	return;
}
#endif

/**
 * Ensure local directories exist on the local machine
 * for given URLs. Start from the name of the NETWASABI
 * directory and move towards the end of the URL, creating
 * if necessary directories that do not yet exist.
 *
 * @http Our HTTP object
 * @filename The pathname of the document to be archived.
 */
int
check_local_dirs(struct http_t *http, buf_t *filename)
{
	assert(http);
	assert(filename);

	char *p;
	char *e;
	char *end;
	char *name = filename->buf_head;
	buf_t _tmp;

	buf_init(&_tmp, pathconf("/", _PC_PATH_MAX));

	if (*(filename->buf_tail - 1) == '/')
		buf_snip(filename, 1);

	end = filename->buf_tail;
	p = strstr(name, NETWASABI_DIR);

	if (!p)
	{
		put_error_msg("check_local_dirs: failed to find netwasabi directory in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	e = ++p;

	e = memchr(p, '/', (end - p));

	if (!e)
	{
		put_error_msg("check_local_dirs: failed to find necessary '/' character in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	p = ++e;

/*
 * e.g. /home/johndoe/${NETWASABI_DIR}/favourite-site.com/categories/best-rated
 *                              ^start here, work along to end, checking
 * creating a directory for each part if necessary.
 */

	while (e < end)
	{
		e = memchr(p, '/', (end - p));

		if (!e) /* The rest of the filename is the file itself */
		{
			break;
		}

		buf_append_ex(&_tmp, name, (e - name));
		BUF_NULL_TERMINATE(&_tmp);

		if(access(_tmp.buf_head, F_OK) != 0)
		{
			if (mkdir(_tmp.buf_head, S_IRWXU) < 0)
				put_error_msg("Failed to create directory: %s", strerror(errno));
		}

		p = ++e;
		buf_clear(&_tmp);
	}

	buf_destroy(&_tmp);
	return 0;
}

int
archive_page(struct http_t *http)
{
	assert(http);

	int fd = -1;
	buf_t *buf = &http_rbuf(http);
	buf_t tmp;
	buf_t local_url;
	char *p;
	int rv;

	p = HTTP_EOH(buf);

	if (!p)
	{
		put_error_msg("Could not find end of HTTP header");
		goto fail;
	}

	buf_collapse(buf, (off_t)0, (p - buf->buf_head));

	buf_init(&tmp, HTTP_URL_MAX);
	buf_clear(&tmp);

	buf_init(&local_url, 1024);
	buf_append(&tmp, http->URL);

	make_local_url(http, &tmp, &local_url);

/*
 * Remove the "file://" from start to end up
 * with local filesystem pathname.
 */
	buf_collapse(&local_url, (off_t)0, strlen("file://"));
	rv = check_local_dirs(http, &local_url);

	if (rv < 0)
		goto fail_free_bufs;

	if (access(local_url.buf_head, F_OK) == 0)
	{
		goto out_free_bufs;
	}

	fd = open(local_url.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd == -1)
	{
		put_error_msg("Failed to create local copy (%s)", strerror(errno));
		goto fail_free_bufs;
	}

	update_operation_status("Created %s", local_url.buf_head);

	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

out_free_bufs:

	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return 0;

fail_free_bufs:

	buf_destroy(&tmp);
	buf_destroy(&local_url);

fail:

	return -1;
}

static const char *const __disallowed_tokens[] =
{
	"javascript:",
	"data:image",
	".exe",
	".dll",
	"cgi-",
	(char *)NULL
};

static int nr_urls_call = 0;

/**
 *
 * @http: our HTTP object with remote host info
 */
static int
URL_acceptable(struct http_t *http, btree_obj_t *tree_archived, buf_t *url)
{
	assert(http);

	int i;

	if (url->data_len >= 256)
		return 0;

	if (strstr(url->buf_head, "mailto"))
		return 0;

	if (!strncmp("http:", url->buf_head, 5)
	|| !strncmp("https:", url->buf_head, 6))
	{
		if (url->data_len < httplen || url->data_len < httpslen)
			return 0;

#if 0
		if (got_token_graph(nwctx))
		{
			http_parse_page(url->buf_head, tmp_page);
			if (!robots_eval_url(allowed, forbidden, tmp_page))
			{
				return 0;
			}
		}
#endif
	}

	if (local_archive_exists(http, url->buf_head))
	{
		return 0;
	}

	if (memchr(url->buf_head, '#', url->buf_tail - url->buf_head))
		return 0;

	for (i = 0; __disallowed_tokens[i] != NULL; ++i)
	{
		if (strstr(url->buf_head, __disallowed_tokens[i]))
			return 0;
	}

	char Host[1024];
	http->ops->URL_parse_host(url->buf_head, Host);

	if (memcmp((void *)http->host, (void *)Host, strlen(Host)))
	{
		return 0;
	}

	if (BTREE_search_data(tree_archived, (void *)url->buf_head, url->data_len))
		return 0;

	return 1;
}

/**
 * XXX	Should probably go into utils_url.c
 *
 * Parse URLs from document and add them to the queue.
 *
 * @http our HTTP object with remote host info
 * @URL_queue our queue of URLs that we will add to
 * @tree_archived tree of already-archived URLs to search through before adding to queue
 */
int
parse_URLs(struct http_t *http, queue_obj_t *URL_queue, btree_obj_t *tree_archived)
{
	assert(http);
	assert(URL_queue);
	assert(tree_archived);

	char *p = NULL;
	char *savep = NULL;
	char delim;
	int url_type_idx = 0;
	size_t url_len = 0;
	buf_t *buf = &http_rbuf(http);
	buf_t URL;
	buf_t full_URL;
	buf_t path;

	if (buf_init(&URL, HTTP_URL_MAX) < 0)
		goto fail;

	if (buf_init(&full_URL, HTTP_URL_MAX) < 0)
		goto fail_destroy_bufs;

	if (buf_init(&path, path_max) < 0)
		goto fail_destroy_bufs;

	savep = buf->buf_head;

	while (1)
	{
		buf_clear(&URL);
		buf_clear(&full_URL);
		buf_clear(&path);

		p = strstr(savep, url_types[url_type_idx].string);
		delim = url_types[url_type_idx].delim;

		if (!p || p >= buf->buf_tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		savep = (p += url_types[url_type_idx].len);
		p = memchr(savep, delim, (buf->buf_tail - savep));

		if (!p)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_len = (p - savep);

		if (!url_len || url_len >= HTTP_URL_MAX)
		{
			savep = ++p;
			continue;
		}

		assert(url_len > 0);
		assert(url_len < HTTP_URL_MAX);

		buf_append_ex(&URL, savep, url_len);
		BUF_NULL_TERMINATE(&URL);

		//Log("\nMaking full URL from %s\n", URL.buf_head);
		make_full_url(http, &URL, &full_URL);
		//Log("\nMade full URL: %s\n", full_URL.buf_head);

		if (!URL_acceptable(http, tree_archived, &full_URL))
		{
			//Log("\nURL is not acceptable\n");
			savep = ++p;
			continue;
		}

		if (QUEUE_enqueue(URL_queue, (void *)full_URL.buf_head, full_URL.data_len) < 0)
			goto fail_destroy_bufs;

		//Log("\nAdded URL to queue: %d items in queue\n", URL_queue->nr_items);

		savep = ++p;
		++nr_urls_call;
	}

	buf_destroy(&URL);
	buf_destroy(&full_URL);
	buf_destroy(&path);

	return nr_urls_call;

fail_destroy_bufs:

	buf_destroy(&URL);
	buf_destroy(&full_URL);
	buf_destroy(&path);

fail:
	return -1;
}

int
Crawl_WebSite(struct http_t *http, queue_obj_t *URL_queue, btree_obj_t *tree_archived)
{
	assert(http);
	assert(URL_queue);
	assert(tree_archived);

	if (!URL_queue->nr_items)
		return 0;

	queue_item_t *item = NULL;
	Dead_URL_t *dead = NULL;
	int code;

	if (!(Dead_URL_cache = cache_create(
			"dead_url_cache",
			sizeof(Dead_URL_t),
			0,
			Dead_URL_cache_ctor,
			Dead_URL_cache_dtor)))
	{
		put_error_msg("failed to create cache for dead URLs");
		//fprintf(stderr, "crawl: failed to create dead url cache\n");
		goto fail;
	}

	while (1)
	{
		buf_clear(&http_rbuf(http));
		buf_clear(&http_wbuf(http));

		Log("%d items in queue\n", URL_queue->nr_items);
		item = QUEUE_dequeue(URL_queue);
		Log("%d items in queue\n", URL_queue->nr_items);

		if (!item)
			break;

		assert(item->data_len < HTTP_URL_MAX);
		strcpy(http->URL, (char *)item->data);
		http->URL_len = item->data_len;

		if ((dead = search_dead_URL(Dead_URL_cache, http->URL)))
		{
			++dead->times_seen;
			continue;
		}

		//http->ops->URL_parse_host(http->URL, http->host);
		http->ops->URL_parse_page(http->URL, http->page);

		BLOCK_SIGNAL(SIGINT);
		sleep(crawl_delay(&nwctx));
		UNBLOCK_SIGNAL(SIGINT);

		http->ops->send_request(http);
		http->ops->recv_response(http);

		code = http->code;

		switch (code)
		{
			case HTTP_OK:

				break;

			case HTTP_NOT_FOUND:

				cache_dead_URL(Dead_URL_cache, http->URL, code);
				Log("%d dead URLs cached\n", cache_nr_used(Dead_URL_cache));

			default:

				goto next;
		}

		Log("Adding URL to archived documents tree\n");
		BTREE_put_data(tree_archived, (void *)http->URL, http->URL_len);
#ifdef DEBUG
		btree_node_t *node = BTREE_search_data(tree_archived, (void *)http->URL, http->URL_len);
		assert(node);
#endif
		Log("%d archived documents\n", tree_archived->nr_nodes);

		if (URL_parseable(http->URL))
		{
			parse_URLs(http, URL_queue, tree_archived);
			transform_document_URLs(http);
		}

		archive_page(http);

	next:

		(void)code;
	}

fail:
	return -1;
}
