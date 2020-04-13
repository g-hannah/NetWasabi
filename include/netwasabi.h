#ifndef NETWASABI_H
#define NETWASABI_H 1

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include "btree.h"
#include "buffer.h"
#include "cache.h"
#include "graph.h"
#include "http.h"

#define NETWASABI_BUILD		"0.0.3"
#define NETWASABI_DIR		"NetWasabi_Crawled"

#define COL_ORANGE	"\x1b[38;5;208m"
#define COL_RED		"\x1b[38;5;9m"
#define COL_BLUE	"\x1b[38;5;12m"
#define COL_PINK	"\x1b[38;5;13m"
#define COL_GREEN	"\x1b[38;5;10m"
#define COL_BROWN	"\x1b[38;5;130m"
#define COL_DARKCYAN	"\x1b[38;5;23m"
#define COL_PURPLE	"\x1b[38;5;5m"
#define COL_LEMON	"\x1b[38;5;228m"
#define COL_LIGHTRED	"\x1b[38;5;204m"
#define COL_LIGHTBLUE	"\x1b[38;5;27m"
#define COL_LIGHTGREEN	"\x1b[38;5;46m"
#define COL_LIGHTGREY	"\x1b[38;5;250m"
#define COL_LIGHTPURPLE	"\x1b[38;5;141m"
#define COL_DARKRED	"\x1b[38;5;160m"
#define COL_DARKGREY	"\x1b[38;5;243m"
#define COL_DARKBLUE	"\x1b[38;5;20m"
#define COL_DARKORANGE	"\x1b[38;5;202m"
#define COL_DARKGREEN	"\x1b[38;5;28m"
#define COL_END		"\x1b[m"

/*
 * For correct drawing to the screen
 */
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

#define clear_struct(s) memset((s), 0, sizeof(*(s)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define __ALIGN(size) (((size) + 0xf) & ~(0xf))

#define MATRIX_INIT(PTR, NUM, ALEN, TYPE) \
do {\
	int i;\
	(PTR) = calloc((NUM), sizeof(TYPE *));\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = (TYPE *)NULL;\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = calloc(ALEN+1, sizeof(TYPE));\
} while (0)

#define MATRIX_DESTROY(PTR, NUM) \
do { \
	int i;\
	if ((PTR))\
	{\
		for (i = 0; i < (NUM); ++i)\
		{\
			if ((PTR)[i])\
				free((PTR)[i]);\
		}\
		free((PTR));\
	}\
} while (0)

#define MATRIX_CHECK_CAPACITY(PTR, CUR_IDX, NUM, SIZE, TYPE)\
do {\
	size_t ____i;\
	size_t ____old_size;\
	if ((PTR))\
	{\
		if ((CUR_IDX) >= (NUM))\
		{\
			____old_size = (NUM);\
			(NUM) *= 2;\
			(PTR) = realloc((PTR), ((NUM) * sizeof(TYPE *)));\
			for (____i = ____old_size; ____i < (NUM); ++____i)\
			{\
				(PTR)[____i] = NULL;\
				(PTR)[____i] = calloc((SIZE), sizeof(TYPE));\
			}\
		}\
	}\
} while (0)

#define DEFAULT_MATRIX_SIZE 256

#define SKIP_CRNL(____p) do { while ((*____p) == 0x0a || (*____p) == 0x0d) { ++(____p); }; } while (0)

#define __noret __attribute__((__noreturn__))
#define __ctor __attribute__((constructor))
#define __dtor __attribute__((destructor))

#ifndef offsetof
# define offsetof(type, member) ((size_t)((type *)0)->member)
#endif

#define __container_of(ptr, type, member)\
({\
	const void *__mptr = (void *)(ptr);\
	(type *)((char *)__mptr - offsetof(type, member));\
})

#define OPT_ALLOW_XDOMAIN 0x1
#define OPT_USE_TLS 0x2
#define OPT_FAST_MODE 0x4
#define OPT_CACHE_THRESHOLD 0x8
#define OPT_CRAWL_DELAY 0x10

#define option_set(o) ((o) & runtime_options)
#define set_option(o) (runtime_options |= (o))
#define unset_option(o) (runtime_options &= ~(o))

struct netwasabi_ctx nwctx;
uint32_t runtime_options;

#define CRAWL_DELAY_DEFAULT 3
#define MAX_CRAWL_DELAY 30
#define CRAWL_DEPTH_DEFAULT 50
#define MAX_TIME_WAIT 8
#define MAX_FAILS 10
#define RESET_DELAY 3

struct url_types
{
	char *string;
	char delim;
	size_t len;
};

#define CACHE_DEFAULT_THRESHOLD 500

#define stats_nr_bytes(n) ((n)->stats.nr_bytes)
#define stats_nr_requests(n) ((n)->stats.nr_requests)
#define stats_nr_archived(n) ((n)->stats.nr_archived)
#define stats_nr_errors(n) ((n)->stats.nr_errors)

#define crawl_delay(n) ((n)->config.crawl_delay)
#define crawl_depth(n) ((n)->config.crawl_depth)
#define cache_thresh(n) ((n)->config.cache_thresh)
#define have_rgraph(n) ((n)->config.have_rgraph)

#define STATS_ADD_BYTES(n, b) ((n)->stats.nr_bytes += (b))
#define STATS_INC_REQS(n) ++((n)->stats.nr_requests)
#define STATS_INC_ARCHIVED(n) ++((n)->stats.nr_archived)
#define STATS_INC_ERRORS(n) ++((n)->stats.nr_errors)

#define keep_tslash(n) ((n)->config.tslash)
#define tslash_on(n) ((n)->config.tslash = 1)
#define tslash_off(n) ((n)->config.tslash = 0)

typedef struct URL_t
{
	char *URL;
	size_t URL_len;
	int nr_requests;
	struct URL_t *left;
	struct URL_t *right;
} URL_t;

typedef struct Dead_URL
{
	char *URL;
	int code;
	time_t timestamp;
	int times_seen;
} Dead_URL_t;

typedef struct Redirected_URL
{
	char *fromURL; // The URL that elicits an HTTP redirect
	char *toURL; // The URL found in the Location header field
	time_t when; // When we first encountered the original URL
} Redirected_URL_t;

enum state
{
	DRAINING = 0,
	FILLING
};

struct cache_ctx
{
	cache_t *cache;
	//btree_obj_t *btree;
	URL_t *root;
	enum state state;
};

struct netwasabi_ctx
{
	struct
	{
		unsigned int crawl_delay;
		unsigned int crawl_depth;
		unsigned int cache_thresh;
		unsigned int have_rgraph; /* did we build a token graph with robots.txt? */
		unsigned int tslash;
	} config;

	struct
	{
		size_t nr_bytes;
		unsigned int nr_requests;
		unsigned int nr_archived;
		unsigned int nr_errors;
		uint16_t depth; /* current depth */
	} stats;
};

#define flip_cache_state(c) ((c).state == DRAINING ? (c).state = FILLING : (c).state = DRAINING)

#define NR_URL_TYPES 11

/*
 * Global vars
 */

int url_cnt;

/* Defined in main */
struct url_types url_types[NR_URL_TYPES];
int path_max;

struct winsize winsize;
struct graph_ctx *allowed;
struct graph_ctx *forbidden;

size_t httplen;
size_t httpslen;

#define FL_HTTP_SKIP_LINK 0x1

#define FL_CACHE_STATUS_FILLING 0x1
#define FL_CACHE_STATUS_DRAINING 0x2
#define FL_CACHE_STATUS_FULL 0x4

#define FL_CONNECTION_CONNECTED 0x1
#define FL_CONNECTION_DISCONNECTED 0x2
#define FL_CONNECTION_CONNECTING 0x4

void update_operation_status(const char *, ...) __nonnull((1));
void update_connection_state(struct http_t *, int) __nonnull((1));
void update_current_url(const char *) __nonnull((1));
void update_current_local(const char *) __nonnull((1));
void update_status_code(int);
void update_bytes(size_t);
void update_cache1_count(int);
void update_cache2_count(int);
void update_cache_status(int, int);
void put_error_msg(const char *, ...) __nonnull ((1));

int check_local_dirs(struct http_t *, buf_t *) __nonnull((1,2)) __wur;
void replace_with_local_urls(struct http_t *, buf_t *) __nonnull((1,2));
int archive_page(struct http_t *) __nonnull((1)) __wur;
int parse_links(struct http_t *, struct cache_ctx *, struct cache_ctx *) __nonnull((1,2,3)) __wur;
void deconstruct_btree(URL_t *, cache_t *) __nonnull((1,2));
int do_request(struct http_t *) __nonnull((1)) __wur;

int crawl(struct http_t *, struct cache_ctx *, struct cache_ctx *) __nonnull((1,2,3)) __wur;

#define TOKEN_MAX 64

pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;

#define ACTION_ING_STR ">>> "
#define ACTION_DONE_STR "@@@ "

/*
 * For paths that are forbidden as
 * layed out in the robots.txt file.
 */
extern char **forbidden_tokens;

#endif /* !defined NETWASABI_H */
