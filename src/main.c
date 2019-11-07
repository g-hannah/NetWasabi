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
#include <time.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "fast_mode.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "screen_utils.h"
#include "utils_url.h"
#include "webreaper.h"

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * Global vars.
 */
struct webreaper_ctx wrctx = {0};
uint32_t runtime_options = 0;

size_t httplen;
size_t httpslen;

char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;

pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;

static volatile sig_atomic_t screen_updater_stop = 0;

struct winsize winsize;
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

static void
catch_signal(int signo)
{
	if (signo != SIGINT && signo != SIGQUIT)
		return;

	siglongjmp(main_env, 1);
}

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

/*
 * Print the operation display box.
 */
	__print_information_layout();

	pthread_attr_setdetachstate(&thread_screen_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_screen_tid, &thread_screen_attr, screen_updater_thread, NULL);

	if (option_set(FAST_MODE))
	{
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

	url_len = strlen(argv[1]);
	assert(url_len < HTTP_URL_MAX);
	strcpy(http->full_url, argv[1]);

	http_parse_host(argv[1], http->host);
	http_parse_page(argv[1], http->page);

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
			http_link_cache_ctor,
			http_link_cache_dtor);

	cache2.cache = wr_cache_create(
			"http_link_cache2",
			sizeof(http_link_t),
			0,
			http_link_cache_ctor,
			http_link_cache_dtor);

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

	buf_clear(rbuf);
	buf_clear(wbuf);

	update_current_url(http->full_url);

	status_code = do_request(http);
	update_status_code(status_code);

	switch(status_code)
	{
		case HTTP_OK:
			break;
		case HTTP_ALREADY_EXISTS:
			do_not_archive = 1;
			http_send_request(http, HTTP_GET); /* in this case we still need to get it to extract URLs */
			status_code = http_recv_response(http);
			update_status_code(status_code);
			break;
		case HTTP_BAD_REQUEST:
			break;
		case HTTP_FORBIDDEN:
		case HTTP_METHOD_NOT_ALLOWED:
		case HTTP_GONE:
		case HTTP_GATEWAY_TIMEOUT:
		case HTTP_BAD_GATEWAY:
		case HTTP_INTERNAL_ERROR:
		default:
			update_status_code(status_code);
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
		//update_operation_status("Parsed no URLs from page (already archived)");
		goto out_disconnect;
	}

	cache1.state = DRAINING;
	cache2.state = FILLING;

	rv = reap(http, &cache1, &cache2);

	if (rv < 0)
	{
		goto fail_disconnect;
	}

	update_operation_status("Finished crawling site");

	out_disconnect:
	http_disconnect(http);
	http_delete(http);

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
	screen_updater_stop = 1;
	exit(EXIT_SUCCESS);

	fail_disconnect:
	screen_updater_stop = 1;
	http_disconnect(http);
	http_delete(http);

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
			set_option(FAST_MODE);
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

	if (crawl_delay(wrctx) > 0 && option_set(FAST_MODE))
	{
			crawl_delay(wrctx) = 0;
	}

	if (!crawl_depth(wrctx))
		crawl_depth(wrctx) = CRAWL_DEPTH_DEFAULT;

	return 0;
}
