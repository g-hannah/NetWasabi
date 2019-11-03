#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "screen_utils.h"
#include "utils_url.h"
#include "webreaper.h"

#define CRAWL_DELAY_DEFAULT 3
#define MAX_CRAWL_DELAY 30
#define CRAWL_DEPTH_DEFAULT 50
#define NR_LINKS_THRESHOLD 500
#define MAX_TIME_WAIT 8
#define MAX_FAILS 10
#define RESET_DELAY 3

#define UPDATE_BYTES_UP 8
#define UPDATE_CACHE1_COUNT_UP 8
#define UPDATE_CACHE2_COUNT_UP 8
#define UPDATE_CACHE_STATUS_UP 7
#define UPDATE_CURRENT_URL_UP 4
#define UPDATE_CURRENT_LOCAL_UP 4
#define UPDATE_STATUS_CODE_UP 8
#define UPDATE_CONN_STATE_UP 10
#define UPDATE_OP_STATUS_UP 3
#define UPDATE_ERROR_MSG_UP 5
#define UPDATE_BYTES_RIGHT 40
#define UPDATE_CACHE1_COUNT_RIGHT 11
#define UPDATE_CACHE2_COUNT_RIGHT 27
#define UPDATE_CACHE1_STATUS_RIGHT 3
#define UPDATE_CACHE2_STATUS_RIGHT 18
#define UPDATE_CURRENT_URL_RIGHT 1
#define UPDATE_CURRENT_LOCAL_RIGHT 1
#define UPDATE_STATUS_CODE_RIGHT 83
#define UPDATE_CONN_STATE_RIGHT 2
#define UPDATE_OP_STATUS_RIGHT 2
#define CACHE_STATUS_LEN 10
#define OUTPUT_TABLE_COLUMNS 90

static sigset_t oldset;
static sigset_t newset;

#define BLOCK_SIGNAL(signal)\
do {\
	sigemptyset(&newset);\
	sigaddset(&newset, (signal));\
	sigprocmask(SIG_BLOCK, &newset, &oldset);\
} while (0)

#define UNBLOCK_SIGNAL(signal) sigprocmask(SIG_SETMASK, &oldset, NULL)

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global variables.
 */
struct webreaper_ctx wrctx = {0};
uint32_t runtime_options = 0;

size_t httplen;
size_t httpslen;
char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;
static int nr_reaped = 0;
static int current_depth = 0;

static struct cache_ctx cache1;
static struct cache_ctx cache2;

struct winsize winsize;
int url_cnt = 0;
pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;
static volatile sig_atomic_t screen_updater_stop = 0;

struct graph_ctx *allowed;
struct graph_ctx *forbidden;

struct url_types url_types[] =
{
	{ "href=\"", '"', 6 },
	{ "HREF=\"", '"', 6 },
	{ "src=\"", '"', 5 },
	{ "SRC=\"", '"', 5 },
	{ "href=\'", '\'', 6 },
	{ "HREF=\'", '\'', 6 },
	{ "src=\'", '\'', 5 },
	{ "SRC=\'", '\'', 5 },
	{ "thumbnail_src\":\"", '"', 16 },
	{ "src\":\"", '"', 6 },
	{ "", 0, 0 }
};

/*
 * When using one ptr var to assign cache objects in a loop
 * without concern for keeping a pointer to each object, we
 * MUST use these global ones to do it. The cache implementation
 * keeps a list of pointers pointing to cache objects. If the
 * cache is moved to a new location on the heap after a realloc,
 * the address of the cache object held at the address of these
 * pointers is updated with the new address of their cache
 * object.
 *
 * This won't work in a case where we assigned many in a loop,
 * and then the local object ptr that was allocated on the stack
 * goes out of scope because we returned from the function.
 */
http_header_t **hh_loop;
http_link_t **hl_loop;
struct http_cookie_t **hc_loop;

int path_max = 1024;

static void
__ctor __wr_init(void)
{
	path_max = pathconf("/", _PC_PATH_MAX);

	if (!path_max)
		path_max = 1024;

	httplen = strlen("http://");
	httpslen = strlen("https://");

/*
 * For calling fcntl() once only in buf_read_socket/tls()
 * to set O_NONBLOCK flag. On a reconnect, reset to zero.
 */
	SET_SOCK_FLAG_ONCE = 0;
	SET_SSL_SOCK_FLAG_ONCE = 0;

	pthread_mutex_init(&screen_mutex, NULL);

	return;
}

static void
__dtor __wr_fini(void)
{
	pthread_mutex_destroy(&screen_mutex);
}

#define THREAD_SLEEP_TIME_USEC 500000
void *
screen_updater_thread(void *arg)
{
	static int go_right = 1;
	static char *string_collection[] =
	{
		"Things you own end up owning you.",
		"Be a better person than you were yesterday.",
		"Welcome to the desert of the real.",
		"Where others have failed, I will not fail.",
		"We're the all-singing, all-dancing crap of the world.",
		"Never send a human to do a machine's job.",
		"There is nothing so eternally adhesive as the memory of power.",
		"We're all living in each other's paranoia.",
		"Somewhere, something incredible is waiting to be known.",
		"To the poet a pearl is a tear of the sea.",
		NULL
	};
	static int string_idx = 0;
	static int max_right;
	static size_t len;

	len = strlen(string_collection[0]);
	max_right = (OUTPUT_TABLE_COLUMNS - (int)len);

	while (!screen_updater_stop)
	{
		usleep(THREAD_SLEEP_TIME_USEC);

		pthread_mutex_lock(&screen_mutex);

		reset_left();
		up(1);
		clear_line();
		right(go_right);
		fprintf(stderr, "%s%.*s%s", COL_DARKCYAN, (int)len, string_collection[string_idx], COL_END);
		reset_left();
		down(1);

		pthread_mutex_unlock(&screen_mutex);

		++go_right;

		if (go_right > max_right)
		{
			--len;

			if ((ssize_t)len < 0)
			{
				go_right = 1;
				++string_idx;

				if (string_collection[string_idx] == NULL)
					string_idx = 0;

				len = strlen(string_collection[string_idx]);

				max_right = (OUTPUT_TABLE_COLUMNS - (int)len);

				sleep(1);
			}
		}
	}

	pthread_exit((void *)0);
}

/*
 * Catch SIGINT
 */
sigjmp_buf main_env;
struct sigaction new_act;
struct sigaction old_sigint;
struct sigaction old_sigquit;

static void
__noret usage(int exit_status)
{
	fprintf(stderr,
		"webreaper <url> [options]\n\n"
		"-T/--tls              use a TLS connection\n"
		"-oH/--req-head        show the request header (\"out header\")\n"
		"-iH/--res-head        show the response header (\"in header\")\n"
		"-D/--depth            maximum crawl-depth\n"
		"    (each URL cache clear + sibling URL cache (re)fill == 1)\n"
		"-cD/--crawl-delay     delay (seconds) between each request\n"
		"    (default is 3 seconds)\n"
		"-fm/--fast-mode       Request more than one URL per second\n"
		"    (this option supercedes any crawl delay specified)\n"
		"-X/--xdomain          follow URLs into other domains\n"
		"-B/--blacklist        blacklist tokens in URLs\n"
		"--help/-h             display this information\n");

	exit(exit_status);
}


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
		case HTTP_ALREADY_EXISTS:
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

static void
__print_information_layout(void)
{
	fprintf(stderr,
		"%s"
		"\n\n"
		"                                                                                 ,`.               \n"
		"  @  @  @   @@@@@  @@@@@@   @@@@@@    @@@@@   @@@@@   @@@@@@    @@@@@  @@@@@@   , ,        @@@@@   \n"
		"  @  @  @  @@      @@   @@  @@   @@  @@      @@   @@  @@   @@  @@      @@   @@  ' '       /'       \n"
		"  @  @  @  @@@@@@  @@@@@@   @@@@@@   @@@@@@  @@@@@@@  @@@@@@   @@@@@@  @@@@@@   ` `      ' '       \n"
		"   @ @ @   @@      @@   @@  @@  @@   @@      @@   @@  @@       @@      @@  @@    ` ` . .' .        \n"
		"   *oOo*    @@@@@  @@@@@@   @@   @@   @@@@@  @@   @@  @@        @@@@@  @@   @@    ` . _ .'         \n"
		"\n"
		"   %sv%s%s\n\n",
		COL_DARKGREY,
		COL_DARKRED,
		WEBREAPER_BUILD,
		COL_END);
/*       15               15                 22                  17             13
 *"===============|===============|======================|=================|============="
 */
#define COL_HEADINGS COL_DARKORANGE
	fprintf(stderr,
	" ==========================================================================================\n"
	"  %sDisconnected%s\n"
	" ==========================================================================================\n"
  "  %sCache 1%s: %4d | %sCache 2%s: %4d | %sData%s: %12lu B | %sCrawl-Delay%s: %ds | %sStatus%s: %d\n"
	"   %s%10s%s   | %s%10s%s    |                      |                 |                     \n"
	" ------------------------------------------------------------------------------------------\n"
	"\n"
	"\n" /* current URL goes here */
	"\n" /* general status messages can go here */
	" ==========================================================================================\n\n",
	COL_LIGHTGREY, COL_END,
	COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (size_t)0,
	COL_HEADINGS, COL_END, crawl_delay(wrctx), COL_HEADINGS, COL_END, 0,
	COL_DARKGREEN, "(filling)", COL_END, COL_LIGHTGREY, "(empty)", COL_END);

	return;
}

char *no_url_files[] =
{
	".jpg",
	".jpeg",
	".png",
	".gif",
	".js",
	".css",
	".pdf",
	".svg",
	".ico",
	NULL
};

static int
__url_parseable(char *url)
{
	int i;

	for (i = 0; no_url_files[i] != NULL; ++i)
	{
		if (strstr(url, no_url_files[i]))
			return 0;
	}

	return 1;
}

#if 0
/**
 * __handle301 - handle 301 Moved Permanently
 * @conn: struct holding connection context
 */
static int
__handle301(connection_t *conn)
{
	http_header_t *location = NULL;
	buf_t tmp_url;
	buf_t tmp_full;
	buf_t tmp_local;
	int fd = -1;
	int xdomain = 0;
	char *p;
	char *q;
	char *new_page_end;
	char *old_page_end;
	char *new_page_start;
	size_t old_page_len = strlen(http->page);
	int archive_redirected = 0;
	int rv = 0;
	static char tmp[HTTP_URL_MAX];

	//fprintf(stderr, "allocating header obj LOCATION @ %p\n", &location);

	location = (http_header_t *)wr_cache_alloc(http_hcache, &location);
	if (!http_fetch_header(&http_rbuf(http), "Location", location, (off_t)0))
	{
		wr_cache_dealloc(http_hcache, (void *)location, &location);
		put_error_msg("__handle301: Failed to allocate header cache object");
		return -1;
	}

/*
 * The redirect may simply be that the server wants
 * the page with a trailing slash. In that case, we
 * don't want to archive the redirected page to avoid
 * asking for it in the future because we won't be
 * able to archive the actual page. So compare the
 * Location header value with our page.
 */

	if (location->value[0])
	{
		strcpy(tmp, location->value);
		new_page_end = tmp + strlen(tmp);

		new_page_start = tmp;
		HTTP_SKIP_HOST_PART(new_page_start, tmp);

		old_page_end = http->page + old_page_len;

		if (*(new_page_end - 1) == '/' && *(old_page_end - 1) != '/')
		{
			*old_page_end = '/';
			++old_page_end;
		}

		assert(new_page_start);
		assert(http->page);

		if (strcmp(new_page_start, http->page))
			archive_redirected = 1;
	}

/*
 * Create the file locally anyway in order to avoid
 * sending requests to the webserver for these same
 * URLs that get redirected elsewhere.
 */
	if (archive_redirected)
	{
		buf_init(&tmp_full, HTTP_URL_MAX);
		buf_init(&tmp_local, path_max);

		buf_append(&tmp_full, http->full_url);
		make_local_url(conn, &tmp_full, &tmp_local);
		buf_collapse(&tmp_local, (off_t)0, strlen("file://"));
		fd = open(tmp_local.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
		close(fd);
		fd = -1;

		buf_destroy(&tmp_local);
		buf_destroy(&tmp_full);
	}

	update_operation_status("Redirecting to %s", location->value);

	assert(location->vlen < HTTP_URL_MAX);

	if (location->value[location->vlen - 1] == '/')
		trailing_slash_on(wrctx);

	if (strncmp("http://", location->value, 7) && strncmp("https://", location->value, 8))
	{
		buf_init(&tmp_url, HTTP_URL_MAX);
		buf_init(&tmp_full, HTTP_URL_MAX);

		buf_append(&tmp_url, location->value);
		make_full_url(conn, &tmp_url, &tmp_full);

		http_parse_host(tmp_full.buf_head, http->host);
		http_parse_page(tmp_full.buf_head, http->page);

		strncpy(http->full_url, tmp_full.buf_head, tmp_full.data_len);
		http->full_url[tmp_full.data_len] = 0;

		buf_destroy(&tmp_url);
		buf_destroy(&tmp_full);

#if 0
		if (got_token_graph(wrctx))
		{
			if (!robots_eval_url(allowed, forbidden, http->page))
			{
				rv = HTTP_FORBIDDEN;
				goto out_dealloc;
			}
		}
#endif
	}
	else
	{
	/*
	 * Some servers erroneously send the Location header as such:
	 *
	 * Location: https://host-name.comhttps/page-we-requested/host-name.com/page-to-direct-to
	 *
	 * Check for this. Find matching "http" after start of header value. Then find next '/'
 	 * char, then jump forward strlen(page) bytes.
	 */
		q = (location->value + 1);
		if ((p = strstr(q, "http")))
		{
			put_error_msg("Received mangle Location header");
			rv = FL_HTTP_SKIP_LINK;
			goto out_dealloc;
		}
		else
		{
			buf_init(&tmp_full, HTTP_URL_MAX);
			buf_append(&tmp_full, location->value);

			xdomain = is_xdomain(conn, &tmp_full);
			buf_destroy(&tmp_full);

			if (xdomain && !option_set(OPT_ALLOW_XDOMAIN))
			{
				wr_cache_dealloc(http_hcache, (void *)location, &location);
				return HTTP_IS_XDOMAIN;
			}

			http_parse_host(location->value, http->host);
			http_parse_page(http->full_url, http->page);
			strncpy(http->full_url, location->value, location->vlen);
			http->full_url[location->vlen] = 0;

#if 0
			if (got_token_graph(wrctx))
			{
				if (!robots_eval_url(allowed, forbidden, http->page))
				{
					rv = HTTP_FORBIDDEN;
					goto out_dealloc;
				}
			}
#endif
		}
	}

	assert(!memchr(http->host, '/', strlen(http->host)));
	update_current_url(http->full_url);

	if (!strncmp("https", http->full_url, 5))
	{
		if (!option_set(OPT_USE_TLS))
			conn_switch_to_tls(conn);
	}

	out_dealloc:
	wr_cache_dealloc(http_hcache, (void *)location, &location);

	return rv;
}
#endif

static void
deconstruct_btree(http_link_t *root, wr_cache_t *cache)
{
	if (!root)
	{
#ifdef DEBUG
		fprintf(stderr, "deconstruct_btree: root is NULL\n");
#endif
		return;
	}

	if (((char *)root - (char *)cache->cache) >= cache->cache_size)
	{
#ifdef DEBUG
		fprintf(stderr, "node @ %p is beyond our cache... (cache %p to %p)\n",
		root,
		ctx->cache->cache,
		(void *)((char *)cache->cache + cache->cache_size));
#endif

		assert(0);
	}

	if (root->left)
	{
#ifdef DEBUG
		fprintf(stderr, "Going left from %p to %p\n", root, root->left);
#endif
		deconstruct_btree(root->left, ctx->cache);
	}

	if (root->right)
	{
#ifdef DEBUG
		fprintf(stderr, "Going right from %p to %p\n", root, root->right);
#endif
		deconstruct_btree(root->right, cache);
	}

#ifdef DEBUG
	fprintf(stderr, "Setting left/right/parent to NULL in node %p\n", root);
#endif
	root->left = NULL;
	root->right = NULL;
	root->parent = NULL;

	return;
}

/**
 * reap - archive the pages in the link cache,
 *    choose one at random and return that choice. That will be
 *    our next page from which to parse links.
 * @cachep: the cache of parsed links
 * @conn: our struct with connection context
 */
static int
reap(struct http_t *http)
{
	assert(http);

	int nr_links = 0;
	int nr_links_sibling;
	int fill = 1;
	int status_code = 0;
	int i;
	size_t len;
	http_link_t *link;
	buf_t *wbuf = &http_wbuf(http);
	buf_t *rbuf = &http_rbuf(http);

	trailing_slash_off(wrctx);
/*
 * As we archive the pages from URLs stored in one cache,
 * we fill the sibling cache with URLs to follow in the next
 * iteration of the while loop. We use the CACHE_SWITCH flag
 * for using one while filling the other. Fill until we pass
 * a threshold number of URLs we wish to have for archiving
 * next. Stop filling when FILL == 0.
 *
 * Base case for the loop is our 'crawl depth' being equal
 * to CRAWL_DEPTH (#iterations of while loop).
 */

	while (1)
	{
		fill = 1;

		if (cache1.state == DRAINING)
		{
			link = (http_link_t *)cache1.cache;
			nr_links = wr_cache_nr_used(cache1.cache);

#ifdef DEBUG
			fprintf(stderr, "Deconstructing binary tree in cache 2\n");
#endif
			deconstruct_btree(cache2.root, cache2.cache);

			wr_cache_clear_all(cache2.cache);
			if (cache2.cache->nr_assigned > 0)
				cache2.cache->nr_assigned = 0;

			assert(wr_cache_nr_used(cache2.cache) == 0);
			cache2.root = NULL;

			update_cache_status(1, FL_CACHE_STATUS_DRAINING);

			if (fill)
				update_cache_status(2, FL_CACHE_STATUS_FILLING);

			update_operation_status("Draining URL cache 1");
		}
		else
		{
			link = (http_link_t *)cache2.cache;
			nr_links = wr_cache_nr_used(cache2.cache);

#ifdef DEBUG
			fprintf(stderr, "Deconstructing binary tree in cache 1\n");
#endif
			deconstruct_btree(cache1.root, cache1.cache);

			wr_cache_clear_all(cache1.cache);
			if (cache1.cache->nr_assigned > 0)
				cache1.cache->nr_assigned = 0;

			assert(wr_cache_nr_used(cache1.cache) == 0);
			cache1.root = NULL;

			update_cache_status(2, FL_CACHE_STATUS_DRAINING);

			if (fill)
				update_cache_status(1, FL_CACHE_STATUS_FILLING);

			update_operation_status("Draining URL cache 2");
		}

		if (!nr_links)
			break;

		url_cnt = nr_links;

		for (i = 0; i < nr_links; ++i)
		{
			buf_clear(wbuf);
			len = strlen(link->url);

			if (!len)
			{
				++link;
				continue;
			}

			assert(len < HTTP_URL_MAX);

			strcpy(http->full_url, link->url);

			if (!http_parse_page(http->full_url, http->page))
				continue;

			BLOCK_SIGNAL(SIGINT);
			sleep(crawl_delay(wrctx));
			UNBLOCK_SIGNAL(SIGINT);

			http_check_host(conn);

			resend:
			if (link->nr_requests > 2) /* loop */
			{
				++link;
				continue;
			}

			update_current_url(http->full_url);

			status_code = do_request(conn);

			if (status_code < 0)
				goto fail;

			++(link->nr_requests);

			switch((unsigned int)status_code)
			{
				case HTTP_OK:
				case HTTP_GONE:
				case HTTP_NOT_FOUND: /* don't want to keep requesting the link and getting 404, so just archive it */
					break;
				case HTTP_BAD_REQUEST:
					//__show_request_header(wbuf);

					if (wr_cache_nr_used(cookies) > 0)
						wr_cache_clear_all(cookies);

					buf_clear(wbuf);
					buf_clear(rbuf);

					http_reconnect(http);

					goto next;
					break;
				case HTTP_METHOD_NOT_ALLOWED:
				case HTTP_FORBIDDEN:
				case HTTP_INTERNAL_ERROR:
				case HTTP_BAD_GATEWAY:
				case HTTP_SERVICE_UNAV:
				case HTTP_GATEWAY_TIMEOUT:
					//__show_response_header(rbuf);

					if (wr_cache_nr_used(cookies) > 0)
						wr_cache_clear_all(cookies);

					buf_clear(wbuf);
					buf_clear(rbuf);

					http_reconnect(http);

					goto next;
					break;
				case HTTP_IS_XDOMAIN:
				case HTTP_ALREADY_EXISTS:
				case FL_HTTP_SKIP_LINK:
					goto next;
				case HTTP_OPERATION_TIMEOUT:

					buf_clear(rbuf);

					if (!http->host[0])
						strcpy(http->host, http->primary_host);

					http_reconnect(http);

					goto next;
					break;
				default:
					put_error_msg("Unknown HTTP status code returned (%d)", status_code);
					goto fail;
			}

			if (fill)
			{
				if (__url_parseable(http->full_url))
				{
					if (cache1.state == DRAINING)
					{
/*
 * parse_links(struct http_t *, struct cache_ctx *FCTX, struct cache_ctx *DCTX)
 */
						parse_links(http, &cache2, &cache1);
						nr_links_sibling = wr_cache_nr_used(cache2.cache);
						update_cache2_count(nr_links_sibling);
					}
					else
					{
						parse_links(http, &cache1, &cache2);
						nr_links_sibling = wr_cache_nr_used(cache1.cache);
						update_cache1_count(nr_links_sibling);
					}

					if (nr_links_sibling >= NR_LINKS_THRESHOLD)
					{
						fill = 0;
/*
 * if cache1 is draining, then it's cache2 that's full, and vice versa.
 */
						update_cache_status(cache1.state == DRAINING ? 2 : 1, FL_CACHE_STATUS_FULL);
					}
				}
			}

			archive_page(http);

			next:
			++link;
			--url_cnt;

			if (cache1.state == FILLING)
				update_cache1_count(url_cnt);
			else
				update_cache2_count(url_cnt);

			clear_error_msg();

			trailing_slash_off(wrctx);
		} /* for (i = 0; i < nr_links; ++i) */

		++current_depth;

		flip_cache_state(cache1);
		flip_cache_state(cache2);

		if (current_depth >= crawl_depth(wrctx))
		{
			update_operation_status("Reached maximum crawl depth");
			break;
		}
	} /* while (1) */

	return 0;

	fail:
	return -1;
}

static void
catch_signal(int signo)
{
	if (signo != SIGINT && signo != SIGQUIT)
		return;

	siglongjmp(main_env, 1);
}

#if 0
static void
__dump_links(wr_cache_t *cachep)
{
	http_link_t *lp = NULL;
	int nr_used = wr_cache_nr_used(cachep);
	int i;

	lp = (http_link_t *)cachep->cache;
	for (i = 0; i < nr_used; ++i)
	{
		while (!wr_cache_obj_used(cachep, (void *)lp))
			++lp;

		printf("link>>%s\n", lp->url);
		++lp;
	}

	return;
}
#endif

static void
__check_directory(void)
{
	char *home = getenv("HOME");
	buf_t tmp;

	buf_init(&tmp, path_max);
	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR);

	if (access(tmp.buf_head, F_OK) != 0)
		mkdir(tmp.buf_head, S_IRWXU);

	buf_destroy(&tmp);

	return;
}

#if 0
static int
__get_robots(connection_t *conn)
{
	assert(http);

	int status_code = 0;

	update_operation_status("Requesting robots.txt file from server");

	strcpy(http->page, "robots.txt");

	buf_t full_url;

	buf_init(&full_url, HTTP_URL_MAX);

	if (option_set(OPT_USE_TLS))
		buf_append(&full_url, "https://");
	else
		buf_append(&full_url, "http://");

	assert(http->host[0]);
	buf_append(&full_url, http->host);
	buf_append(&full_url, "/robots.txt");

	assert(full_url.data_len < HTTP_URL_MAX);
	strcpy(http->full_url, full_url.buf_head);

	buf_destroy(&full_url);
	wrctx.got_token_graph = 0;

	status_code = __do_request(conn);

	switch(status_code)
	{
		case HTTP_OK:
			update_operation_status("Got robots.txt file");
			break;
		default:
			update_operation_status("No robots.txt file");
	}

/*
 * This initialises the graphs.
 */
	allowed = NULL;
	forbidden = NULL;

	if (create_token_graphs(&allowed, &forbidden, &http_rbuf(http)) < 0)
	{
		put_error_msg("Failed to create graph for URL tokens");
		goto out_destroy_graphs;
	}

	wrctx.got_token_graph = 1;
	return 0;

	out_destroy_graphs:

	if (allowed)
		destroy_graph(allowed);

	if (forbidden)
		destroy_graph(forbidden);

	return 0;
}
#endif

static int
__valid_url(char *url)
{
	assert(url);

	if (!strstr(url, "http://") && !strstr(url, "https://"))
		return 0;

	if (!memchr(url, '.', strlen(url)))
		return 0;

	return 1;
}

/*
 * ./webreaper <url> [options]
 */
int
main(int argc, char *argv[])
{
	if (argc < 2)
	{
		usage(EXIT_FAILURE);
	}

	if (get_opts(argc, argv) < 0)
	{
		fprintf(stderr, "main: failed to parse program options\n");
		goto fail;
	}

	if (!__valid_url(argv[1]))
	{
		fprintf(stderr, "\"%s\" is not a valid URL\n", argv[1]);
		goto fail;
	}

	srand(time(NULL));

	/*
	 * Must be done here and not in the constructor function
	 * because the dimensions are not known before main()
	 */
	clear_struct(&winsize);
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);

	pthread_attr_setdetachstate(&thread_screen_attr, PTHREAD_CREATE_DETACHED);

/*
 * Print the operation display box.
 */
	__print_information_layout();

	pthread_create(&thread_screen_tid, &thread_screen_attr, screen_updater_thread, NULL);


	if (option_set(FAST_MODE))
	{
		http_delete(http);
		do_fast_mode(argv[1]);
		goto out;
	}

/*
 * Set up signal handlers for SIGINT and SIGQUIT
 * to avoid segmentation faults when the user
 * does ctrl^C/ctrl^\ at a bad time.
 */
	clear_struct(&new_act);
	clear_struct(&old_sigint);
	clear_struct(&old_sigquit);

	new_act.sa_flags = 0;
	new_act.sa_handler = catch_signal;
	sigemptyset(&new_act.sa_mask);

	if (sigaction(SIGINT, &new_act, &old_sigint) < 0)
	{
		put_error_msg("main: failed to set SIGINT handler (%s)", strerror(errno));
		goto fail;
	}

	if (sigaction(SIGQUIT, &new_act, &old_sigquit) < 0)
	{
		put_error_msg("main: failed to set SIGQUIT handler (%s)", strerror(errno));
		goto fail;
	}

/*
 * Check for existence of the WR_Reaped directory
 * in the user's home directory.
 */
	__check_directory();

	struct http_t *http;
	int status_code;
	int do_not_archive = 0;
	int rv;
	size_t url_len;
	buf_t *rbuf = NULL;
	buf_t *wbuf = NULL;

	if (!(http = http_new()))
	{
		fprintf(stderr, "reap: failed to obtain new HTTP object\n");
		goto fail;
	}

	http_parse_host(argv[1], http->host);
	strcpy(http->primary_host, http->host);

	if (http_connect(http) < 0)
		goto fail;

	rbuf = &http_rbuf(http);
	wbuf = &http_wbuf(http);

	/*
	 * Create a new cache for http_link_t objects.
	 */
	cache1.cache = wr_cache_create(
			"http_link_cache",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	cache2.cache = wr_cache_create(
			"http_link_cache2",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	/*
	 * Catch SIGINT and SIGQUIT so we can release cache memory, etc.
	 */
	if (sigsetjmp(main_env, 0) != 0)
	{
		fprintf(stderr, "%c%c%c%c%c%c", 0x08, 0x20, 0x08, 0x08, 0x20, 0x08);
		put_error_msg("Signal caught");
		goto out_disconnect;
	}

	/*
	 * Check if the webserver has a robots.txt file
	 * and if so, use it to create a directed network
	 * of URL tokens.
	 */
	//if (__get_robots(&conn) < 0)
		//put_error_msg("No robots.txt file");

	http_parse_page(argv[1], http->page);
	url_len = strlen(argv[1]);

	assert(url_len < HTTP_URL_MAX);

	strcpy(http->full_url, argv[1]);

	buf_clear(rbuf);
	buf_clear(wbuf);

	update_current_url(http->full_url);

/*
 * We no longer check here for any 3xx status codes
 * that result in a Location header field being sent
 * because it makes much more sense for that to be
 * dealt with behind the scenes within the HTTP
 * module.
 *
 * TODO: still learn, however, when we got a location
 * header sent to us so that we can save an empty file
 * for the name of the redirected URL in order that we
 * stop requesting it in the future.
 */
	resend:
	status_code = do_request(http);

	switch(status_code)
	{
		case HTTP_OK:
			break;
		case HTTP_ALREADY_EXISTS:
			do_not_archive = 1;
			status_code = http_send_request(http, HTTP_GET); /* in this case we still need to get it to extract URLs */
			update_status_code(status_code);
			break;
		case HTTP_BAD_REQUEST:
			//__show_request_header(wbuf);
			break;
		case HTTP_FORBIDDEN:
		case HTTP_METHOD_NOT_ALLOWED:
		case HTTP_GONE:
		case HTTP_GATEWAY_TIMEOUT:
		case HTTP_BAD_GATEWAY:
		case HTTP_INTERNAL_ERROR:
			__show_response_header(rbuf);
		default:
			goto out_disconnect;
	}

	parse_links(http, &cache1, &cache2);
	update_cache1_count(wr_cache_nr_used(cache1.cache));

	if (!do_not_archive)
	{
		archive_page(http);
	}

	if (!wr_cache_nr_used(cache1.cache))
	{
		update_operation_status("Parsed no URLs from page (already archived)");
		goto out_disconnect;
	}

	rv = reap(http);

	if (rv < 0)
	{
		goto fail_disconnect;
	}

	update_operation_status("Finished crawling site");

	out_disconnect:
	screen_updater_stop = 1;
	http_disconnect(http);

	if (wr_cache_nr_used(cache1.cache) > 0)
		wr_cache_clear_all(cache1.cache);
	if (wr_cache_nr_used(cache2.cache) > 0)
		wr_cache_clear_all(cache2.cache);

	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);

	if (allowed)
		destroy_graph(allowed);

	if (forbidden)
		destroy_graph(forbidden);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	out:
	exit(EXIT_SUCCESS);

	fail_disconnect:
	screen_updater_stop = 1;
	http_disconnect(http);

	if (wr_cache_nr_used(cache1.cache) > 0)
		wr_cache_clear_all(cache1.cache);
	if (wr_cache_nr_used(cache2.cache) > 0)
		wr_cache_clear_all(cache2.cache);

	wr_cache_destroy(cache1.cache);
	wr_cache_destroy(cache2.cache);

	if (allowed)
		destroy_graph(allowed);

	if (forbidden)
		destroy_graph(forbidden);

	fail:
	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_FAILURE);
}

int
get_opts(int argc, char *argv[])
{
	int		i;

	USER_BLACKLIST_NR_TOKENS = 0;

	for (i = 1; i < argc; ++i)
	{
		while (i < argc && argv[i][0] != '-')
			++i;

		if (i == argc)
			break;

		if (!strcmp("--help", argv[i])
			|| !strcmp("-h", argv[i]))
		{
			usage(EXIT_SUCCESS);
		}
		else
		if (!strcmp("--depth", argv[i])
		|| !strcmp("-D", argv[i]))
		{
			++i;

			if (i == argc || argv[i][0] == '-')
			{
				fprintf(stderr, "-D/--depth requires an argument\n");
				usage(EXIT_FAILURE);
			}

			crawl_depth(wrctx) = atoi(argv[i]);
			assert(crawl_depth(wrctx) > 0);
			assert(crawl_depth(wrctx) <= INT_MAX);
		}
		else
		if (!strcmp("--crawl-delay", argv[i])
		|| !strcmp("-cD", argv[i]))
		{
			++i;

			if (i == argc || argv[i][0] == '-')
			{
				fprintf(stderr, "-cD/--crawl-delay requires an argument\n");
				usage(EXIT_FAILURE);
			}

			crawl_delay(wrctx) = atoi(argv[i]);
			assert(crawl_delay(wrctx) >= 0);
			assert(crawl_delay(wrctx) < MAX_CRAWL_DELAY);
		}
		else
		if (!strcmp("--fast-mode", argv[i])
		|| !strcmp("-fm", argv[i]))
		{
			o.flags |= FAST_MODE;
		}
		else
		if (!strcmp("--blacklist", argv[i])
		|| !strcmp("-B", argv[i]))
		{
			int nr_tokens = 10;
			int idx = 0;
			size_t token_len;
			USER_BLACKLIST_NR_TOKENS = 0;

			++i;

			if (i == argc || !strncmp("--", argv[i], 2) || !strncmp("-", argv[i], 1))
			{
				fprintf(stderr, "--blacklist/-B requires an argument\n");
				usage(EXIT_FAILURE);
			}

			MATRIX_INIT(user_blacklist, nr_tokens, TOKEN_MAX, char);

			while (i < argc && strncmp("--", argv[i], 2) && strncmp("-", argv[i], 1))
			{
				token_len = strlen(argv[i]);
				assert(token_len < TOKEN_MAX);

				MATRIX_CHECK_CAPACITY(user_blacklist, idx, nr_tokens, TOKEN_MAX, char);

				strncpy(user_blacklist[idx], argv[i], token_len);
				user_blacklist[idx][token_len] = 0;

				++USER_BLACKLIST_NR_TOKENS;
				++idx;
				++i;
			}

			--i;
		}
		else
		if (!strcmp("--xdomain", argv[i])
			|| !strcmp("-X", argv[i]))
		{
			set_option(OPT_ALLOW_XDOMAIN);
		}
		else
		if (!strcmp("-oH", argv[i])
			|| !strcmp("--req-head", argv[i]))
		{
			set_option(OPT_SHOW_REQ_HEADER);
		}
		else
		if (!strcmp("-iH", argv[i])
			|| !strcmp("--res-head", argv[i]))
		{
			set_option(OPT_SHOW_RES_HEADER);
		}
		else
		if (!strcmp("-T", argv[i])
			|| strcmp("--tls", argv[i]))
		{
			set_option(OPT_USE_TLS);
		}
		else
		{
			continue;
		}
	}

	if (crawl_delay(wrctx) > 0 && (o.flags & FAST_MODE))
	{
			craw_delay(wrctx) = 0;
	}

	if (!crawl_depth(wrctx))
		crawl_depth(wrctx) = CRAWL_DEPTH_DEFAULT;

	return 0;
}
