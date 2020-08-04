#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "btree.h"
#include "buffer.h"
#include "cache.h"
#include "cache_management.h"
#include "fast_mode.h"
#include "hash_bucket.h"
#include "http.h"
#include "malloc.h"
#include "netwasabi.h"
#include "queue.h"
#include "screen_utils.h"
#include "utils_url.h"
#include "xml.h"

static char *home_dir = NULL;

/*
 * Globally visible, so threads in fast_mode.c
 * can get a copy of these runtime options.
 */
struct netwasabi_ctx nwctx = {0};

size_t httplen; // length of "http://"
size_t httpslen; // length of "https://"

pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;

static queue_obj_t *URL_queue = NULL;
static btree_obj_t *tree_archived = NULL;
static bucket_obj_t *bObj_hashed_opts = NULL;

static int FAST_MODE = 0;

static volatile sig_atomic_t screen_updater_stop = 0;

struct winsize winsize;

struct url_types url_types[] =
{
	{ "href=\"", '"', 6 },
	{ "src=\"", '"', 5 },
	{ "href=\'", '\'', 6 },
	{ "src=\'", '\'', 5 },
	{ "", 0, 0 }
};

int path_max = 0;

static void
__ctor __wr_init(void)
{
	path_max = pathconf("/", _PC_PATH_MAX);

	if (!path_max)
		path_max = 1024;

	httplen = strlen("http://");
	httpslen = strlen("https://");

	char *h = getenv("HOME");

	if (NULL == h)
	{
		fprintf(stderr, "Could not get home directory from HOME environment variable\n");
		return;
	}

	home_dir = strdup(h);
	pthread_mutex_init(&screen_mutex, NULL);

	return;
}

static void
__dtor __wr_fini(void)
{
	if (NULL != home_dir)
		free(home_dir);

	pthread_mutex_destroy(&screen_mutex);
}

/*
#define THREAD_SLEEP_TIME_USEC 500000
void *
screen_updater_thread(void *arg)
{
	int go_right = 1;

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

	int string_idx = 0;
	int max_right;
	size_t len;

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
*/

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
		"netwasabi <url> [options]\n\n"
		"\n"
		"NetWasabi crawls websites and archives the pages on the local machine.\n"
		"URLs embedded within HTML documents are modified to use the \"file://\"\n"
		"protocol and point to the absolute path of the document on the local\n"
		"machine.\n"
		"\n"
		"Runtime options can be set in the config.xml file in ${HOME}/.NetWasabi\n"
		"directory. Runtime options include:\n"
		"\n"
		"crawlDelay: the number of seconds to wait before sending another GET\n"
		"request to the remote web server;\n"
		"\n"
		"crawlDepth: the depth at which NetWasabi should stop crawling. For example,\n"
		"when all the URLs that were parsed from a downloaded document have been\n"
		"visited, that increments the current depth by 1.\n"
		"\n"
		"queueMax: This is the maximum number of URLs allowed to be in the queue\n"
		"at any one time waiting to be downloaded from the webserver.\n"
		"\n"
		"fastMode: this option makes requests to the remote web server as fast as\n"
		"possible using multiple threads. The crawlDelay option is ignored when\n"
		"this is set to true.\n"
		"\n"
		"xdomain: setting this to true means NetWasabi will make requests to URLs\n"
		"embedded within an HTML document that belong to another remote web server.\n"
		"This can result in arching pages from unwanted ads.\n"
		"\n"
		"An example of a config.xml file is the following:\n"
		"\n"
		"<options>\n"
		"\t<crawlDelay>0</crawlDelay>\n"
		"\t<crawlDepth>10</crawlDepth>\n"
		"\t<queueMax>100</queueMax>\n"
		"\t<xdomain>false</xdomain>\n"
		"\t<fastMode>false</fastMode>\n"
		"</options>\n\n"
		"* There is no need for the <?xml version=\"1.0\" ?> line in the config file.\n\n");

	exit(exit_status);
}

static void
__print_information_layout(void)
{
	fprintf(stderr,
		"\n\n"
		"         ;;;   ;;  ;;;;; ;;;;;;;;   ,; ;; ;,   ;;;;    ;;;;;   ;;;;    ;;;;;;   ,;,  \n"
		"         ;;;;  ;; ;;        ;;      ;; ;; ;;  ;;  ;;  ;;      ;;  ;;  ;;;    ;  ;;;  \n"
		"         ;; ;; ;; ;;;;;;    ;;      ;; ;; ;;  ;;;;;;  ;;;;;   ;;;;;;  ;;;;;;;   ;;;  \n"
		"         ;;   ;;; ;;        ;;      ;; ;; ;;  ;;  ;;      ;;  ;;  ;;  ;;;    ;  ;;;  \n"
		"         ;;    ;;  ;;;;;    ;;       ;;;;;;   ;;  ;;  ;;;;;   ;;  ;;   ;;;;;;   ;;;  \n\n"
		"   %sv%s%s\n\n",
		COL_DARKRED,
		NETWASABI_BUILD,
		COL_END);

#define COL_HEADINGS COL_DARKORANGE
if (!FAST_MODE)
{
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
	COL_HEADINGS, COL_END, nwctx.config.crawl_delay, COL_HEADINGS, COL_END, 0,
	COL_DARKGREEN, "(filling)", COL_END, COL_LIGHTGREY, "(empty)", COL_END);
}
else
{
	fprintf(stderr,
	" ==========================================================================================\n"
	"  %sDisconnected%s\n"
	" ==========================================================================================\n"
  "  %sCache 1%s: %4d | %sCache 2%s: %4d | %sData%s: %12lu B | %s🗲%s  FAST MODE %s🗲%s  | %sStatus%s: %d\n"
	"   %s%10s%s   | %s%10s%s    |                      |   (%d threads)   |                     \n"
	" ------------------------------------------------------------------------------------------\n"
	"\n"
	"\n" /* current URL goes here */
	"\n" /* general status messages can go here */
	" ==========================================================================================\n\n",
	COL_LIGHTGREY, COL_END,
	COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (int)0, COL_HEADINGS, COL_END, (size_t)0,
	COL_HEADINGS, COL_END, COL_HEADINGS, COL_END, COL_HEADINGS, COL_END, 0,
	COL_DARKGREEN, "(filling)", COL_END, COL_LIGHTGREY, "(empty)", COL_END,
	FAST_MODE_NR_WORKERS);
}

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
check_directory(void)
{
	buf_t tmp;

	buf_init(&tmp, path_max);
	buf_append(&tmp, home_dir);
	buf_append(&tmp, "/" NETWASABI_DIR);

	if (access(tmp.buf_head, F_OK) != 0)
		mkdir(tmp.buf_head, S_IRWXU);

	buf_destroy(&tmp);

	return;
}

static int
valid_url(char *url)
{
	assert(url);

	if (strlen(url) >= HTTP_URL_MAX)
		return 0;

	if (!strstr(url, "http://") && !strstr(url, "https://"))
		return 0;

	if (!memchr(url, '.', strlen(url)))
		return 0;

	if (strstr(url, "mailto"))
		return 0;

	return 1;
}

/**
 * Callback for XML_for_each_child()
 */
static void
_config_hash_options(xml_node_t *node)
{
	if (NULL == node->value)
		return;

	BUCKET_put_data(bObj_hashed_opts, node->name, (void *)node->value, strlen(node->value), 0);
	return;
}

/**
 * Parse the config.xml file and add runtime
 * options to hash bucket to retrieve when needed.
 */
#define CONFIG_FILENAME "config.xml"
static void
get_configuration(void)
{
	char config_file[1024];

	sprintf(config_file, "%s/.NetWasabi/" CONFIG_FILENAME, home_dir);
	bObj_hashed_opts = NULL;

	if (access(config_file, F_OK) != 0)
		goto _default;

	struct XML *xml = XML_new();

	if (0 != XML_parse_file(xml, config_file))
		goto _default;

	xml_node_t *n = XML_find_by_path(xml, "options");
	if (!n)
		goto _default;

	bObj_hashed_opts = BUCKET_object_new();
	assert(bObj_hashed_opts);

	/*
	 * Iterate child nodes of <options> tag and hash the data.
	 */
	XML_for_each_child(n, _config_hash_options);
	XML_free(xml);

	return;

_default:
	CONFIG_CRAWL_DELAY(&nwctx, DEFAULT_CRAWL_DELAY);
	CONFIG_CRAWL_DEPTH(&nwctx, DEFAULT_CRAWL_DEPTH);
	CONFIG_MAX_QUEUE(&nwctx, DEFAULT_MAX_QUEUE);
	FAST_MODE = 0;

	XML_free(xml);
	return;
}

int
main(int argc, char *argv[])
{
	if (argc < 2) // netwasabi <url>
	{
		usage(EXIT_FAILURE);
	}

	if (!valid_url(argv[1]))
	{
		fprintf(stderr, "\"%s\" is not a valid URL\n", argv[1]);
		goto fail;
	}

	get_configuration();
	check_directory();

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

	//pthread_attr_setdetachstate(&thread_screen_attr, PTHREAD_CREATE_DETACHED);
	//pthread_create(&thread_screen_tid, &thread_screen_attr, screen_updater_thread, NULL);

	if (FAST_MODE)
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

	struct http_t *http;
	int rv;
	size_t url_len;
	buf_t *rbuf = NULL;
	buf_t *wbuf = NULL;

/*
 * HTTP objects have an ID associated with them
 * for logging purposes (i.e., if using fast
 * mode there are multiple threads so we can
 * differentiate between them).
 */
#define MAIN_THREAD_ID 0x4e49414du
	if (!(http = HTTP_new(MAIN_THREAD_ID)))
	{
		fprintf(stderr, "main: failed to obtain new HTTP object\n");
		goto fail;
	}

	http->followRedirects = 1; // Tell the HTTP module to automatically follow 3XX redirects.
	http->usingSecure = 1; // Tell the HTTP module to use TLS.
	http->verb = GET; // We will only be using GET requests anyway.

#ifdef DEBUG
	fprintf(stderr, "Created HTTP object with ID %u\n", MAIN_THREAD_ID);
#endif

	url_len = strlen(argv[1]);
	assert(url_len < HTTP_URL_MAX);

	strcpy(http->URL, argv[1]);
	http->URL_len = url_len;

	http->ops->URL_parse_host(argv[1], http->host);
	http->ops->URL_parse_page(argv[1], http->page);

#ifdef DEBUG
	fprintf(stderr, "Host: %s\n", http->host);
	fprintf(stderr, "Page: %s\n", http->page);
#endif

	strcpy(http->primary_host, http->host);

	if (http_connect(http) < 0)
		goto fail;

	rbuf = &http_rbuf(http);
	wbuf = &http_wbuf(http);

	/*
	 * Catch SIGINT and SIGQUIT so we can release memory.
	 */
	if (sigsetjmp(main_env, 0) != 0)
	{
		fprintf(stderr, "%c%c%c%c%c%c", 0x08, 0x20, 0x08, 0x08, 0x20, 0x08);
		put_error_msg("Signal caught");
		goto out_disconnect;
	}

	buf_clear(rbuf);
	buf_clear(wbuf);

	update_current_url(http->URL);

	/*
	 * When we parse URLs from an HTML document, we will
	 * add those to the back of the queue to be crawled later.
	 */
	URL_queue = QUEUE_object_new();
	assert(URL_queue);

	/*
	 * Keep a binary tree of already-archived URLs so that
	 * we can avoid duplicate crawling. We query the tree
	 * when we take a URL from the queue to see if we already
	 * downloaded it.
	 */
	tree_archived = BTREE_object_new();
	assert(tree_archived);

	http->ops->send_request(http);
	http->ops->recv_response(http);

	update_status_code(http->code);

	if (HTTP_OK != http->code)
	{
		fprintf(stderr, "Error (%d %s)\n", http->code, http->ops->code_as_string(http));
		goto out_disconnect;
	}

	BTREE_put_data(tree_archived, (void *)http->URL, http->URL_len);

	/*
	 * i.e., it's not an image file or something
	 * else that has no HTML structure.
	 */
	if (URL_parseable(http->URL))
	{
#ifdef DEBUG
		fprintf(stderr, "URL is parseable - calling parse_URLs()\n");
#endif
		parse_URLs(http, URL_queue, tree_archived);
		transform_document_URLs(http); // turn href links into file://<path to local dir for pages crawled from this site>
		archive_page(http);
	}
	else
	{
		update_operation_status("No URLs to parse from document");
		goto out_disconnect;
	}

	rv = Crawl_WebSite(http, URL_queue, tree_archived);

	if (rv < 0)
	{
		goto fail_disconnect;
	}

	update_operation_status("Finished crawling site");

out_disconnect:

	http_disconnect(http);
	HTTP_delete(http);

	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

out:

	screen_updater_stop = 1;

	usleep(100000);
	exit(EXIT_SUCCESS);

fail_disconnect:

	screen_updater_stop = 1;
	http_disconnect(http);
	HTTP_delete(http);

fail:

	fprintf(stderr, "Failed...\n");
	sigaction(SIGINT, &old_sigint, NULL);
	sigaction(SIGQUIT, &old_sigquit, NULL);

	exit(EXIT_FAILURE);
}

int
get_opts(int argc, char *argv[])
{
	int		i;

	CONFIG_MAX_QUEUE(&nwctx, DEFAULT_MAX_QUEUE);

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
#if 0
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
#endif
		else
		{
			continue;
		}
	}

	return 0;
}
