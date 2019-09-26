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

int crawl_delay = 0;
int crawl_depth = 0;

static sigset_t oldset;
static sigset_t newset;

#define BLOCK_SIGNAL(signal)\
do {\
	sigemptyset(&newset);\
	sigaddset(&newset, (signal));\
	sigprocmask(SIG_BLOCK, &newset, &oldset);\
} while (0)

#define UNBLOCK_SIGNAL(signal) sigprocmask(SIG_SETMASK, &oldset, NULL)

#if 0
static sigjmp_buf __ICL_TIMEOUT__;

static void __handle_icl_timeout(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__ICL_TIMEOUT__, 1);
}
#endif

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global variables.
 */
uint32_t runtime_options = 0;
wr_cache_t *http_hcache;
wr_cache_t *http_lcache;
wr_cache_t *http_lcache2;
wr_cache_t *cookies;
int TRAILING_SLASH = 0;
size_t httplen;
size_t httpslen;
char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;
volatile int cache_switch = 0;
static int nr_reaped = 0;
static int current_depth = 0;
http_link_t *cache1_url_root;
http_link_t *cache2_url_root;
size_t TOTAL_BYTES_RECEIVED = 0;
struct winsize winsize;
int url_cnt = 0;
pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;
static volatile sig_atomic_t screen_updater_stop = 0;

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

	hh_loop = malloc(sizeof(http_header_t *));
	hl_loop = malloc(sizeof(http_link_t *));
	hc_loop = malloc(sizeof(struct http_cookie_t *));

	assert(hh_loop);
	assert(hl_loop);
	assert(hc_loop);

	httplen = strlen("http://");
	httpslen = strlen("https://");

/*
 * For calling fcntl() once only in buf_read_socket/tls()
 * to set O_NONBLOCK flag. On a reconnect, reset to zero.
 */
	SET_SOCK_FLAG_ONCE = 0;
	SET_SSL_SOCK_FLAG_ONCE = 0;

	return;
}

static void
__dtor __wr_fini(void)
{
	if (hh_loop)
		free(hh_loop);

	if (hl_loop)
		free(hl_loop);

	if (hc_loop)
		free(hc_loop);
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
			fprintf(stderr, "%s (filling)%s", COL_DARKGREEN, COL_END);
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

	va_end(args);

	out_release_lock:
	reset_left();
	down(UPDATE_OP_STATUS_UP);

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

static void
__print_information_layout(connection_t *conn)
{
	assert(conn);

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
  "  %sCache 1%s: %4d | %sCache 2%s: %4d | %sData%s: %12lu B | %sCrawl-Delay%s: %ds | %sStatus%s: %d\n"
	"   %s%10s%s   | %s%10s%s    |                      |                 |                     \n"
	" ------------------------------------------------------------------------------------------\n"
	"  Server: %s%s%s [@ %s]\n"
	"\n" /* current URL goes here */
	"\n" /* locally created file goes here */
	"\n"
	"\n" /* general status messages can go here */
	" ==========================================================================================\n\n",
	COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (size_t)0,
	COL_HEADINGS, COL_END, crawl_delay, COL_HEADINGS, COL_END, 0,
	COL_DARKGREEN, "(filling)", COL_END, COL_LIGHTGREY, "(empty)", COL_END,
	COL_RED, conn->host, COL_END, conn->host_ipv4);

	return;
}

static void
__extract_cookie_info(struct http_cookie_t *dest, http_header_t *src)
{
	assert(dest);
	assert(src);

	strncpy(dest->data, src->value, src->vlen);
	dest->data[src->vlen] = 0;
	dest->data_len = src->vlen;

	char *p;
	char *e;
	char *start = dest->data;
	size_t data_len = dest->data_len;

/*
 * Some cookie values do not end with ';' but instead end with '\r\n'.
 * \r\n is not included in the http_header_t->value, so if no ';', just
 * go to the null byte.
 */

	p = strstr(start, "path");

	if (p)
	{
		p += strlen("path=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->path, p, (e - p));
		dest->path_len = (e - p);
		dest->path[dest->path_len] = 0;
	}
	else
	{
		dest->path[0] = 0;
	}

	p = strstr(start, "domain");

	if (p)	
	{
		p += strlen("domain=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->domain, p, (e - p));
		dest->domain_len = (e - p);
		dest->domain[dest->domain_len] = 0;
	}
	else
	{
		dest->domain[0] = 0;
	}

	p = strstr(start, "expires");

	if (p)
	{
		p += strlen("expires=");
		e = memchr(p, ';', data_len - (p - start));

		if (!e)
			e = start + data_len;

		strncpy(dest->expires, p, (e - p));
		dest->expires_len = (e - p);
		dest->expires[dest->expires_len] = 0;
	}
	else
	{
		dest->expires[0] = 0;
	}

	dest->expires_ts = (time(NULL) + ((time_t)86400 * 7));

	return;
}

/**
 * __check_cookies - check for Set-Cookie headers; extract and append to outgoing header if any
 * @conn: struct holding connection context
 */
static void
__check_cookies(connection_t *conn)
{
	assert(conn);

	off_t offset = 0;
	struct http_cookie_t *cookie = NULL;
	http_header_t *tmp;

	//fprintf(stderr, "allocating header obj to TMP @ %p\n", &tmp);

	tmp = (http_header_t *)wr_cache_alloc(http_hcache, &tmp);

	/*
	 * If there is a Set-Cookie header, then clear all
	 * previously-cached cookies. Otherwise, if no such
	 * header and we have cached cookies, append them
	 * to the buffer. Otherwise, do nothing.
	 */
	if (http_check_header(&conn->read_buf, "Set-Cookie", (off_t)0, &offset))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		offset = 0;

		while(http_check_header(&conn->read_buf, "Set-Cookie", offset, &offset))
		{
			http_fetch_header(&conn->read_buf, "Set-Cookie", tmp, offset);

			if (!tmp->name[0] && !tmp->value[0])
			{
				fprintf(stderr, "%sEMPTY VALUES FOR COOKIE FROM HEADER...%s\n", COL_ORANGE, COL_END);
				break;
			}

			http_append_header(&conn->write_buf, tmp);

			//fprintf(stderr, "allocating cookie obj to HC_LOOP @ %p\n", hc_loop);
			*hc_loop = (struct http_cookie_t *)wr_cache_alloc(cookies, hc_loop);

			__extract_cookie_info(*hc_loop, tmp);

			++offset;
		}
	}
	else
	{
		int nr_used = wr_cache_nr_used(cookies);
		int i;

		if (!nr_used)
			goto out_dealloc;

		cookie = (struct http_cookie_t *)cookies->cache;

		for (i = 0; i < nr_used; ++i)
		{
			while (!wr_cache_obj_used(cookies, (void *)cookie))
				++cookie;

#if 0
			if (__cookie_expired(cookie))
			{
				printf("cookie \"%s\" expired\n", cookie->data);
				wr_cache_dealloc(cookies, (void *)cookie);
				++cookie;
			}
#endif

			strncpy(tmp->value, cookie->data, cookie->data_len);
			tmp->value[cookie->data_len] = 0;
			tmp->vlen = cookie->data_len;
			strcpy(tmp->name, "Cookie");

			http_append_header(&conn->write_buf, tmp);

			++cookie;
		}
	}

	out_dealloc:
	//fprintf(stderr, "deallocating header object TMP @ %p\n", &tmp);
	wr_cache_dealloc(http_hcache, (void *)tmp, &tmp);

	return;
}

static int
__connection_closed(connection_t *conn)
{
	assert(conn);

	http_header_t *connection;
	buf_t *buf = &conn->read_buf;
	int rv = 0;

	//fprintf(stderr, "allocating header obj in CONNECTION @ %p\n", &connection);

	connection = wr_cache_alloc(http_hcache, &connection);
	assert(connection);

	http_fetch_header(buf, "Connection", connection, (off_t)0);

	if (connection->value[0])
	{
		if (!strcasecmp("close", connection->value))
			rv = 1;
	}

	//fprintf(stderr, "deallocting header obj CONNECTION @ %p\n", &connection);

	wr_cache_dealloc(http_hcache, connection, &connection);
	return rv;
}

static void
__show_request_header(buf_t *buf)
{
	assert(buf);

	fprintf(stderr, "%s%s%s", COL_RED, buf->buf_head, COL_END);
	return;
}

static void
__show_response_header(buf_t *buf)
{
	assert(buf);

	char *p = HTTP_EOH(buf);

	if (!p)
	{
		fprintf(stderr, "__show_response_header: failed to find end of HTTP header\n");
		fprintf(stderr, "%s", buf->buf_head);
		
		errno = EPROTO;
		return;
	}

	fprintf(stderr, "%s%.*s%s", COL_RED, (int)(p - buf->buf_head), buf->buf_head, COL_END);

	return;
}

static void
__check_host(connection_t *conn)
{
	assert(conn);

	static char old_host[HTTP_HNAME_MAX];

	if (!conn->full_url[0])
		return;

	assert(strlen(conn->host) < HTTP_HNAME_MAX);
	strcpy(old_host, conn->host);
	http_parse_host(conn->full_url, conn->host);

	if (strcmp(conn->host, old_host))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		update_operation_status("Changing host: %s ==> %s", old_host, conn->host);
		reconnect(conn);
	}

	return;
}

static int
__send_head_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	update_operation_status("Sending HEAD request to server");

	__check_host(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"HEAD %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			conn->full_url, HTTP_VERSION,
			HTTP_USER_AGENT,
			conn->host,
			HTTP_EOH_SENTINEL);

	buf_append(wbuf, tmp_cbuf);

	__check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (option_set(OPT_SHOW_REQ_HEADER))
		__show_request_header(wbuf);

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	if (option_set(OPT_SHOW_RES_HEADER))
		__show_response_header(rbuf);

	status_code = http_status_code_int(rbuf);

	return status_code;

	fail_free_bufs:
	if (tmp_cbuf)
	{
		free(tmp_cbuf);
		tmp_cbuf = NULL;
	}

	fail:
	return rv;
}

static int
__send_get_request(connection_t *conn)
{
	assert(conn);

	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;
	char *tmp_cbuf = NULL;
	int status_code = 0;
	int rv;

	buf_clear(wbuf);

	update_operation_status("Sending GET request to server");

	__check_host(conn);

	if (!(tmp_cbuf = wr_calloc(8192, 1)))
		goto fail_free_bufs;

	sprintf(tmp_cbuf,
			"GET %s HTTP/%s\r\n"
			"User-Agent: %s\r\n"
			"Host: %s\r\n"
			"Connection: keep-alive%s",
			conn->full_url, HTTP_VERSION,
			HTTP_USER_AGENT,
			conn->host,
			HTTP_EOH_SENTINEL);

	buf_append(wbuf, tmp_cbuf);

	__check_cookies(conn);

	buf_clear(rbuf);

	free(tmp_cbuf);
	tmp_cbuf = NULL;

	if (option_set(OPT_SHOW_REQ_HEADER))
		__show_request_header(wbuf);

	if (http_send_request(conn) < 0)
		goto fail;

	rv = http_recv_response(conn);

	if (rv < 0 || FL_OPERATION_TIMEOUT == rv)
		goto fail;

	if (option_set(OPT_SHOW_RES_HEADER))
		__show_response_header(rbuf);

	status_code = http_status_code_int(rbuf);

	return status_code;

	fail_free_bufs:
	if (tmp_cbuf)
	{
		free(tmp_cbuf);
		tmp_cbuf = NULL;
	}

	fail:
	return rv;
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

static int
__check_local_dirs(connection_t *conn, buf_t *filename)
{
	assert(conn);
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
	p = strstr(name, WEBREAPER_DIR);

	if (!p)
	{
		fprintf(stderr, "__check_local_dirs: failed to find webreaper directory in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	e = ++p;

	e = memchr(p, '/', (end - p));

	if (!e)
	{
		fprintf(stderr, "__check_local_dirs: failed to find necessary '/' character in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	p = ++e;

/*
 * e.g. /home/johndoe/WR_Reaped/favourite-site.com/categories/best-rated
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
				update_operation_status("Failed to create directory: %s", strerror(errno));
		}

		p = ++e;
		buf_clear(&_tmp);
	}

	buf_destroy(&_tmp);
	return 0;
}

static void
__replace_with_local_urls(connection_t *conn, buf_t *buf)
{
	assert(conn);
	assert(buf);

	char *tail = buf->buf_tail;
	char *p;
	char *savep;
	char *url_start;
	char *url_end;
	off_t url_start_off;
	off_t url_end_off;
	off_t savep_off;
	off_t poff;
	size_t range;
	buf_t url;
	buf_t path;
	buf_t full;
	int url_type_idx;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&path, HTTP_URL_MAX);
	buf_init(&full, HTTP_URL_MAX);

#define save_pointers()\
do {\
	savep_off = (savep - buf->buf_head);\
	poff = (savep - buf->buf_head);\
	url_start_off = (url_start - buf->buf_head);\
	url_end_off = (url_end - buf->buf_head);\
} while (0)

#define restore_pointers()\
do {\
	savep = (buf->buf_head + savep_off);\
	p = (buf->buf_head + poff);\
	url_start = (buf->buf_head + url_start_off);\
	url_end = (buf->buf_head + url_end_off);\
} while (0)

	savep = buf->buf_head;
	url_type_idx = 0;

	while (1)
	{
		buf_clear(&url);

		assert(buf->buf_tail <= buf->buf_end);
		assert(buf->buf_head >= buf->data);

		p = strstr(savep, url_types[url_type_idx].string);

		if (!p || p >= tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_start = (p += url_types[url_type_idx].len);
		url_end = memchr(url_start, url_types[url_type_idx].delim, (tail - url_start));

		if (!url_end)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		assert(buf->buf_tail <= buf->buf_end);
		assert(url_start < buf->buf_tail);
		assert(url_end < buf->buf_tail);
		assert(p < buf->buf_tail);
		assert(savep < buf->buf_tail);
		assert((tail - buf->buf_head) == (buf->buf_tail - buf->buf_head));

		range = (url_end - url_start);

		if (!range)
		{
			++savep;
			continue;
		}

		if (!strncmp("http://", url_start, range) || !strncmp("https://", url_start, range))
		{
			savep = ++url_end;
			continue;
		}

		if (range >= HTTP_URL_MAX)
		{
			savep = ++url_end;
			continue;
		}

		assert(range < HTTP_URL_MAX);

		buf_append_ex(&url, url_start, range);
		BUF_NULL_TERMINATE(&url);

		if (range)
		{
			//fprintf(stderr, "turning %s into full url\n", url.buf_head);
			make_full_url(conn, &url, &full);
			//fprintf(stderr, "made %s\n", full.buf_head);

			if (make_local_url(conn, &full, &path) == 0)
			{
				//fprintf(stderr, "made local url %s\n", path.buf_head);
				buf_collapse(buf, (off_t)(url_start - buf->buf_head), range);
				tail = buf->buf_tail;

				save_pointers();

				assert(path.data_len < path_max);
				buf_shift(buf, (off_t)(url_start - buf->buf_head), path.data_len);
				tail = buf->buf_tail;

				restore_pointers();

				assert((url_start - buf->buf_head) == url_start_off);
				assert((url_end - buf->buf_head) == url_end_off);
				assert((p - buf->buf_head) == poff);
				assert((savep - buf->buf_head) == savep_off);

				strncpy(url_start, path.buf_head, path.data_len);
			}
		}

		assert(buf_integrity(&url));
		assert(buf_integrity(&full));
		assert(buf_integrity(&path));

		//++savep;
		savep = ++url_end;

		if (savep >= tail)
			break;
	}
}

static int
__archive_page(connection_t *conn)
{
	int fd = -1;
	buf_t *buf = &conn->read_buf;
	buf_t tmp;
	buf_t local_url;
	char *p;
	int rv;

	update_operation_status("Archiving file...");

	p = HTTP_EOH(buf);

	if (p)
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));

	if (__url_parseable(conn->full_url))
		__replace_with_local_urls(conn, buf);

	buf_init(&tmp, HTTP_URL_MAX);
	buf_init(&local_url, 1024);

	buf_append(&tmp, conn->full_url);
	make_local_url(conn, &tmp, &local_url);

/* Now we have "file:///path/to/file.extension" */
	buf_collapse(&local_url, (off_t)0, strlen("file://"));

	rv = __check_local_dirs(conn, &local_url);

	if (rv < 0)
		goto fail_free_bufs;

	if (access(local_url.buf_head, F_OK) == 0)
	{
		//update_operation_status("Already archived local copy", 1);
		goto out_free_bufs;
	}

	fd = open(local_url.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd == -1)
	{
		update_operation_status("Failed to create local copy (%s)", strerror(errno));
		goto fail_free_bufs;
	}

	update_current_local(local_url.buf_head);
	//update_operation_status("Page archived", 1);
	++nr_reaped;

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

	return -1;
}

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
	size_t old_page_len = strlen(conn->page);
	int archive_redirected = 0;
	static char tmp[HTTP_URL_MAX];

	//fprintf(stderr, "allocating header obj LOCATION @ %p\n", &location);

	location = (http_header_t *)wr_cache_alloc(http_hcache, &location);
	if (!http_fetch_header(&conn->read_buf, "Location", location, (off_t)0))
	{
		wr_cache_dealloc(http_hcache, (void *)location, &location);
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

		old_page_end = conn->page + old_page_len;

		if (*(new_page_end - 1) == '/' && *(old_page_end - 1) != '/')
		{
			*old_page_end = '/';
			++old_page_end;
		}

		assert(new_page_start);
		assert(conn->page);

		if (strcmp(new_page_start, conn->page))
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

		buf_append(&tmp_full, conn->full_url);
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
		TRAILING_SLASH = 1;

	if (strncmp("http://", location->value, 7) && strncmp("https://", location->value, 8))
	{
		buf_init(&tmp_url, HTTP_URL_MAX);
		buf_init(&tmp_full, HTTP_URL_MAX);

		buf_append(&tmp_url, location->value);
		make_full_url(conn, &tmp_url, &tmp_full);

		http_parse_host(tmp_full.buf_head, conn->host);
		http_parse_page(tmp_full.buf_head, conn->page);
		strncpy(conn->full_url, tmp_full.buf_head, tmp_full.data_len);
		conn->full_url[tmp_full.data_len] = 0;

		buf_destroy(&tmp_url);
		buf_destroy(&tmp_full);
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
			//fprintf(stderr, "%s%sMangled location header! (%s)%s\n", COL_RED, ATTENTION_STR, location->value, COL_END);
			return -1;
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

			http_parse_host(location->value, conn->host);
			http_parse_page(conn->full_url, conn->page);
			strncpy(conn->full_url, location->value, location->vlen);
			conn->full_url[location->vlen] = 0;
		}
	}

	assert(!memchr(conn->host, '/', strlen(conn->host)));

	update_current_url(conn->full_url);

	//fprintf(stderr, "deallocating header obj LOCATION @ %p\n", &location);

	wr_cache_dealloc(http_hcache, (void *)location, &location);

	if (!strncmp("https", conn->full_url, 5))
	{
		if (!option_set(OPT_USE_TLS))
			conn_switch_to_tls(conn);
	}

	return 0;
}

#if 0
static void
__check_for_connection_upgrade(connection_t *conn)
{
	assert(conn);

	http_header_t *connection = wr_cache_alloc(http_hcache, &connection);
	http_header_t *keep_alive = wr_cache_alloc(http_hcache, &keep_alive);
	buf_t *rbuf = &conn->read_buf;

	if (!http_fetch_header(rbuf, "Connection", connection, (off_t)0))
		goto out_dealloc;

	fprintf(stderr, "%s%s%s\n", COL_LIGHTBLUE, connection->value, COL_END);

	if (!connection->value[0])
		goto out_dealloc;

	if (!http_fetch_header(rbuf, "Keep-Alive", keep_alive, (off_t)0))
		goto out_dealloc;

	fprintf(stderr, "%s%s%s\n", COL_LIGHTBLUE, keep_alive->value, COL_END);

	char *p = keep_alive->value;
	char *e;
	char *end = keep_alive->value + keep_alive->vlen;
	static char tmp[16];
	int old_delay = crawl_delay;

	if (!strncmp("timeout", p, strlen("timeout")))
	{
		e = memchr(p, '=', (end - p));

		if (!e)
			goto out_dealloc;

		p = ++e;

		e = memchr(p, ',', (end - p));

		if (!e)
			e = memchr(p, ' ', (end - p));

		if (!e)
			goto out_dealloc;

		strncpy(tmp, p, (e - p));
		tmp[e - p] = 0;

		int timeout = atoi(tmp);

		assert(timeout > 0);

		if (timeout > MAX_CRAWL_DELAY)
		{
			if ((timeout - MAX_CRAWL_DELAY) > MAX_CRAWL_DELAY)
			{
				fprintf(stdout, "%s%sServer requested large timeout value: %d seconds! Setting to %d%s\n",
					COL_RED,
					ACTION_DONE_STR,
					timeout,
					MAX_CRAWL_DELAY,
					COL_END);
			}

			crawl_delay = MAX_CRAWL_DELAY;
		}
		else
		{
			crawl_delay = timeout;
		}
	}
	else
	{
		goto out_dealloc;
	}

	if (crawl_delay != old_delay)
		fprintf(stdout, "%s%s%s[Crawl-Delay set to %d second%s]\n",
				COL_ORANGE,
				STATISTICS_STR,
				COL_END,
				crawl_delay,
				crawl_delay == 1 ? "" : "s");

	out_dealloc:
	wr_cache_dealloc(http_hcache, (void *)connection, &connection);
	wr_cache_dealloc(http_hcache, (void *)keep_alive, &keep_alive);
	return;
}
#endif

static int
__do_request(connection_t *conn)
{
	assert(conn);

	int status_code = 0;
	int rv;

	//if (local_archive_exists(conn->full_url))
		//return HTTP_ALREADY_EXISTS;
	/*
	 * Save bandwidth: send HEAD first.
	 */
	resend_head:
	status_code = __send_head_request(conn);

	update_status_code(status_code);

	switch(status_code)
	{
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_FOUND:
		case HTTP_SEE_OTHER:
			//fprintf(stdout, "%s%s (%s)\n", ACTION_ING_STR, http_status_code_string(status_code), conn->full_url);
			rv = __handle301(conn);

			if (HTTP_IS_XDOMAIN == (unsigned int)rv)
				return rv;
			else
			if (rv < 0)
				return -1;
/*
 * Check here too because 301 may send different
 * spelling (upper-case vs lower-case... etc)
 */
			if (local_archive_exists(conn->full_url))
				return HTTP_ALREADY_EXISTS;
			goto resend_head;
			break;
		case HTTP_OK:
		case HTTP_METHOD_NOT_ALLOWED:
			break;
		default:
			return status_code;
	}

	if (__connection_closed(conn))
	{
		//fprintf(stdout, "%s%sRemote peer closed connection%s\n", COL_RED, ACTION_DONE_STR, COL_END);
		//__show_response_header(&conn->read_buf);
		update_operation_status("Remove peer closed connection");
		reconnect(conn);
	}

	status_code &= ~status_code;
	status_code = __send_get_request(conn);

	update_status_code(status_code);

	return status_code;
}


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
		cache->cache,
		(void *)((char *)cache->cache + cache->cache_size));
#endif

		assert(0);
	}

	if (root->left)
	{
#ifdef DEBUG
		fprintf(stderr, "Going left from %p to %p\n", root, root->left);
#endif
		deconstruct_btree(root->left, cache);
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
reap(wr_cache_t *cachep, wr_cache_t *cachep2, connection_t *conn)
{
	assert(cachep);
	assert(cachep2);
	assert(conn);

	int nr_links = 0;
	int nr_links_sibling;
	int fill = 1;
	int status_code = 0;
	int i;
	size_t len;
	http_link_t *link;
	buf_t *wbuf = &conn->write_buf;
	buf_t *rbuf = &conn->read_buf;

	TRAILING_SLASH = 0;
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

	if (!wr_cache_nr_used(cachep))
		cache_switch = 1;
	else
		cache_switch = 0;


	while (1)
	{
		fill = 1;

		if (!cache_switch)
		{
			link = (http_link_t *)cachep->cache;
			nr_links = wr_cache_nr_used(cachep);

#ifdef DEBUG
			fprintf(stderr, "Deconstructing binary tree in cache 2\n");
#endif
			deconstruct_btree(cache2_url_root, http_lcache2);

			wr_cache_clear_all(cachep2);
			if (cachep2->nr_assigned > 0)
				cachep2->nr_assigned = 0;

			assert(wr_cache_nr_used(cachep2) == 0);
			cache2_url_root = NULL;

			update_cache_status(1, FL_CACHE_STATUS_DRAINING);

			if (fill)
				update_cache_status(2, FL_CACHE_STATUS_FILLING);

			update_operation_status("Draining URL cache 1");
		}
		else
		{
			link = (http_link_t *)cachep2->cache;
			nr_links = wr_cache_nr_used(cachep2);

#ifdef DEBUG
			fprintf(stderr, "Deconstructing binary tree in cache 1\n");
#endif
			deconstruct_btree(cache1_url_root, http_lcache);

			wr_cache_clear_all(cachep);
			if (cachep->nr_assigned > 0)
				cachep->nr_assigned = 0;

			assert(wr_cache_nr_used(cachep) == 0);
			cache1_url_root = NULL;

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

			strncpy(conn->full_url, link->url, len);
			conn->full_url[len] = 0;

			if (!http_parse_page(conn->full_url, conn->page))
				continue;

			BLOCK_SIGNAL(SIGINT);
			sleep(crawl_delay);
			UNBLOCK_SIGNAL(SIGINT);

			__check_host(conn);

			resend:
			if (link->nr_requests > 2) /* loop */
			{
				++link;
				continue;
			}

			update_current_url(conn->full_url);
			update_current_local("");

			status_code = __do_request(conn);

			if (HTTP_IS_XDOMAIN != (unsigned int)status_code && status_code < 0)
				goto fail;

			++(link->nr_requests);

			switch((unsigned int)status_code)
			{
				case HTTP_OK:
				case HTTP_NOT_FOUND: /* don't want to keep requesting the link and getting 404, so just archive it */
					break;
				case HTTP_MOVED_PERMANENTLY:
				/*
				 * Shouldn't get here, because __do_request() first
				 * sends a HEAD request, and handles 301/302 for us.
				 */
					__handle301(conn);
					buf_clear(wbuf);
					goto resend;
					break;
				case HTTP_BAD_REQUEST:
					__show_request_header(wbuf);

					if (wr_cache_nr_used(cookies) > 0)
						wr_cache_clear_all(cookies);

					buf_clear(wbuf);
					buf_clear(rbuf);

					reconnect(conn);

					goto next;
					break;
				case HTTP_FORBIDDEN:
				case HTTP_INTERNAL_ERROR:
				case HTTP_BAD_GATEWAY:
				case HTTP_SERVICE_UNAV:
				case HTTP_GATEWAY_TIMEOUT:
					__show_response_header(rbuf);

					if (wr_cache_nr_used(cookies) > 0)
						wr_cache_clear_all(cookies);

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
				case HTTP_METHOD_NOT_ALLOWED:
					goto next;
				case FL_OPERATION_TIMEOUT:

					buf_clear(rbuf);

					if (!conn->host[0])
						strcpy(conn->host, conn->primary_host);

					reconnect(conn);

					goto next;
					break;
				default:
					goto fail;
			}

			if (fill)
			{
				if (__url_parseable(conn->full_url))
				{
					if (!cache_switch)
					{
						parse_links(cachep2, cachep, &cache2_url_root, conn);
						nr_links_sibling = wr_cache_nr_used(cachep2);
						update_cache2_count(nr_links_sibling);
					}
					else
					{
						parse_links(cachep, cachep2, &cache1_url_root, conn);
						nr_links_sibling = wr_cache_nr_used(cachep);
						update_cache1_count(nr_links_sibling);
					}

					if (nr_links_sibling >= NR_LINKS_THRESHOLD)
					{
						fill = 0;
						update_cache_status(!cache_switch ? 2 : 1, FL_CACHE_STATUS_FULL);
					/*fprintf(stdout, "%s%sURL threshold reached%s\n",
						COL_DARKORANGE,
						ACTION_DONE_STR,
						COL_END);*/
					}
				}
			}

			__archive_page(conn);

			next:
			++link;
			--url_cnt;
			if (!cache_switch)
				update_cache1_count(url_cnt);
			else
				update_cache2_count(url_cnt);

			TRAILING_SLASH = 0;
		} /* for (i = 0; i < nr_links; ++i) */

		++current_depth;

		if (cache_switch)
			cache_switch = 0;
		else
			cache_switch = 1;

		if (current_depth >= crawl_depth)
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

#if 0
	if (!valid_url(argv[1]))
		goto fail;
#endif

	srand(time(NULL));

	clear_struct(&new_act);
	clear_struct(&old_sigint);
	clear_struct(&old_sigquit);

	new_act.sa_flags = 0;
	new_act.sa_handler = catch_signal;
	sigemptyset(&new_act.sa_mask);

	if (sigaction(SIGINT, &new_act, &old_sigint) < 0)
	{
		fprintf(stderr, "main: failed to set SIGINT handler (%s)\n", strerror(errno));
		goto fail;
	}

	if (sigaction(SIGQUIT, &new_act, &old_sigquit) < 0)
	{
		fprintf(stderr, "main: failed to set SIGQUIT handler (%s)\n", strerror(errno));
		goto fail;
	}

	__check_directory();

	connection_t conn;
	int status_code;
	int do_not_archive = 0;
	int rv;
	size_t url_len;
	buf_t *rbuf = NULL;
	buf_t *wbuf = NULL;

	conn_init(&conn);

	http_parse_host(argv[1], conn.host);
	http_parse_page(argv[1], conn.page);

	url_len = strlen(argv[1]);

	assert(url_len < HTTP_URL_MAX);

	strncpy(conn.full_url, argv[1], url_len);
	conn.full_url[url_len] = 0;

	strcpy(conn.primary_host, conn.host);

	/*
	 * Initialises read/write buffers in conn.
	 */
	if (open_connection(&conn) < 0)
		goto fail;

	/*
	 * Must be done here and not in the constructor function
	 * because the dimensions are not known before main()
	 */
	clear_struct(&winsize);
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);

	__print_information_layout(&conn);

	rbuf = &conn.read_buf;
	wbuf = &conn.write_buf;

	/*
	 * Create a new cache for http_link_t objects.
	 */
	http_lcache = wr_cache_create(
			"http_link_cache",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	http_lcache2 = wr_cache_create(
			"http_link_cache2",
			sizeof(http_link_t),
			0,
			wr_cache_http_link_ctor,
			wr_cache_http_link_dtor);

	/*
	 * Create a cache for HTTP header fields.
	 */
	http_hcache = wr_cache_create(
			"http_header_field_cache",
			sizeof(http_header_t),
			0,
			wr_cache_http_header_ctor,
			wr_cache_http_header_dtor);

	/*
	 * Create a cache for cookies; separate cache because we want
	 * a different struct to separate and easily access cookie
	 * params (like domain, path, etc).
	 */
	cookies = wr_cache_create(
			"cookie_cache",
			sizeof(struct http_cookie_t),
			0,
			http_cookie_ctor,
			http_cookie_dtor);

	/*
	 * Catch SIGINT and SIGQUIT so we can release cache memory, etc.
	 */
	if (sigsetjmp(main_env, 0) != 0)
	{
		fprintf(stderr, "%c%c%c%c%c%c", 0x08, 0x20, 0x08, 0x08, 0x20, 0x08);
		update_operation_status("Signal caught");
		goto out_disconnect;
	}

	buf_clear(rbuf);
	buf_clear(wbuf);

	update_current_url(conn.full_url);

	pthread_mutex_init(&screen_mutex, NULL);
	pthread_attr_setdetachstate(&thread_screen_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_screen_tid, &thread_screen_attr, screen_updater_thread, NULL);

	resend:
	status_code = __do_request(&conn);

	//__update_status_code(status_code);
	//fprintf(stdout, "%s%s\n", ACTION_ING_STR, http_status_code_string(status_code));

	switch(status_code)
	{
		case HTTP_OK:
			break;
		case HTTP_MOVED_PERMANENTLY:
		case HTTP_FOUND:
		case HTTP_SEE_OTHER:
			__handle301(&conn);
			goto resend;
			break;
		case HTTP_ALREADY_EXISTS:
			do_not_archive = 1;
			status_code = __send_get_request(&conn); /* in this case we still need to get it to extract URLs */
			update_status_code(status_code);
			break;
		case HTTP_BAD_REQUEST:
			__show_request_header(wbuf);
			break;
		case HTTP_FORBIDDEN:
		case HTTP_METHOD_NOT_ALLOWED:
		case HTTP_GATEWAY_TIMEOUT:
		case HTTP_BAD_GATEWAY:
		case HTTP_INTERNAL_ERROR:
			__show_response_header(rbuf);
		default:
			//fprintf(stderr, "%s%sDisconnecting...%s\n", COL_RED, ACTION_ING_STR, COL_END);
			update_operation_status("Disconnecting...");
			goto out_disconnect;
	}

	parse_links(http_lcache, http_lcache2, &cache1_url_root, &conn);
	update_cache1_count(wr_cache_nr_used(http_lcache));

	if (!do_not_archive)
	{
		__archive_page(&conn);
	}

	if (!wr_cache_nr_used(http_lcache))
	{
		reset_left();
		goto out_disconnect;
	}

	rv = reap(http_lcache, http_lcache2, &conn);

	if (rv < 0)
	{
		goto fail_disconnect;
	}

	update_operation_status("Finished crawling site");

/*	fprintf(stdout, "%s%s%s[Reaped %s%d%s pages: crawl_depth=%s%d%s]\n",
		COL_DARKORANGE,
		STATISTICS_STR,
		COL_END,
		COL_LIGHTRED,
		nr_reaped,
		COL_END,
		COL_LIGHTRED,
		current_depth,
		COL_END);*/

	out_disconnect:
	screen_updater_stop = 1;
	close_connection(&conn);
	conn_destroy(&conn);

	if (wr_cache_nr_used(http_lcache) > 0)
		wr_cache_clear_all(http_lcache);
	if (wr_cache_nr_used(http_lcache2) > 0)
		wr_cache_clear_all(http_lcache2);
	if (wr_cache_nr_used(http_hcache) > 0)
		wr_cache_clear_all(http_hcache);
	if (wr_cache_nr_used(cookies) > 0)
		wr_cache_clear_all(cookies);

	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_lcache2);
	wr_cache_destroy(http_hcache);
	wr_cache_destroy(cookies);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_SUCCESS);

	fail_disconnect:
	close_connection(&conn);
	conn_destroy(&conn);

	if (wr_cache_nr_used(http_lcache) > 0)
		wr_cache_clear_all(http_lcache);
	if (wr_cache_nr_used(http_lcache2) > 0)
		wr_cache_clear_all(http_lcache2);
	if (wr_cache_nr_used(http_hcache) > 0)
		wr_cache_clear_all(http_hcache);
	if (wr_cache_nr_used(cookies) > 0)
		wr_cache_clear_all(cookies);

	wr_cache_destroy(http_lcache);
	wr_cache_destroy(http_lcache2);
	wr_cache_destroy(http_hcache);
	wr_cache_destroy(cookies);

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

			crawl_depth = atoi(argv[i]);
			assert(crawl_depth > 0);
			assert(crawl_depth <= INT_MAX);
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

			crawl_delay = atoi(argv[i]);
			assert(crawl_delay > 0);
			assert(crawl_delay < MAX_CRAWL_DELAY);
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

	if (!crawl_delay)
		crawl_delay = CRAWL_DELAY_DEFAULT;

	if (!crawl_depth)
		crawl_depth = CRAWL_DEPTH_DEFAULT;

	return 0;
}
