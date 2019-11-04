#ifndef WEBREAPER_H
#define WEBREAPER_H 1

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include "buffer.h"
#include "cache.h"
#include "graph.h"
#include "http.h"

#define WEBREAPER_BUILD		"0.0.2"
#define WEBREAPER_DIR			"WR_Reaped"

#define COL_ORANGE	"\x1b[38;5;208m"
#define COL_RED			"\x1b[38;5;9m"
#define COL_BLUE		"\x1b[38;5;12m"
#define COL_PINK		"\x1b[38;5;13m"
#define COL_GREEN		"\x1b[38;5;10m"
#define COL_BROWN		"\x1b[38;5;130m"
#define COL_DARKCYAN "\x1b[38;5;23m"
#define COL_PURPLE	"\x1b[38;5;5m"
#define COL_LEMON		"\x1b[38;5;228m"
#define COL_LIGHTRED "\x1b[38;5;204m"
#define COL_LIGHTBLUE "\x1b[38;5;27m"
#define COL_LIGHTGREEN "\x1b[38;5;46m"
#define COL_LIGHTGREY "\x1b[38;5;250m"
#define COL_LIGHTPURPLE "\x1b[38;5;141m"
#define COL_DARKRED "\x1b[38;5;160m"
#define COL_DARKGREY "\x1b[38;5;243m"
#define COL_DARKBLUE "\x1b[38;5;20m"
#define COL_DARKORANGE "\x1b[38;5;202m"
#define COL_DARKGREEN "\x1b[38;5;28m"
#define COL_END			"\x1b[m"

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

#ifndef container_of
# define container_of(ptr, type, member) \
({\
	const void *__mptr = (void *)(ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); \
})
#endif

#define OPT_USE_TLS	0x1
#define OPT_SHOW_REQ_HEADER 0x2
#define OPT_SHOW_RES_HEADER 0x4
#define OPT_ALLOW_XDOMAIN 0x8 /* if not set, ignore URLs that are a different host */

#define CRAWL_DELAY_DEFAULT 3
#define MAX_CRAWL_DELAY 30
#define CRAWL_DEPTH_DEFAULT 50
#define MAX_TIME_WAIT 8
#define MAX_FAILS 10
#define RESET_DELAY 3
#define NR_LINKS_THRESHOLD 500

struct url_types
{
	char *string;
	char delim;
	size_t len;
};

struct webreaper_ctx
{
	pthread_mutex_t lock;
	unsigned char trailing_slash;
	unsigned int crawl_delay;
	unsigned int crawl_depth;
	unsigned char got_token_graph;
	size_t nr_bytes_received;
	unsigned int nr_requests;
	unsigned int nr_pages;
	unsigned int nr_errors;
};

#define flip_cache_state(c) ((c).state == (enum state) DRAINING ? (c).state = (enum state) FILLING : (c).state = (enum state) DRAINING)

enum state
{
	DRAINING = 0,
	FILLING = 1
};

struct cache_ctx
{
	wr_cache_t *cache;
	http_link_t *root;
	enum state state;
};

#define keep_trailing_slash(w) ((w).trailing_slash)
#define trailing_slash_off(w) ((w).trailing_slash &= ~((w).trailing_slash))
#define trailing_slash_on(w) ((w).trailing_slash = 1)
#define got_token_graph(w) ((w).got_token_graph)
#define crawl_delay(w) ((w).crawl_delay)
#define crawl_depth(w) ((w).crawl_depth)
#define total_bytes(w) ((w).nr_bytes_received)
#define total_requests(w) ((w).nr_requests)
#define total_pages(w) ((w).nr_pages)
#define total_errors(w) ((w).nr_errors)
#define wrstats_lock(w) (pthread_mutex_lock(&(w).lock))
#define wrstats_unlock(w) (pthread_mutex_unlock(&(w).lock))

#define STATS_INC_ERRORS(w) ++((w).nr_errors)
#define STATS_INC_PAGES(w) ++((w).nr_pages)
#define STATS_INC_REQS(w) ++((w).nr_requests)
#define STATS_ADD_BYTES(w, b) (wrstats_lock(w); ((w).nr_bytes_received += (b); wrstats_unlock(w))

#define NR_URL_TYPES 11

/*
 * Global vars
 */

int nr_reaped;
int current_depth;
int url_cnt;

struct cache_ctx cache1;
struct cache_ctx cache2;

/* Defined in main */

struct url_types url_types[NR_URL_TYPES];
int path_max;
char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;

struct webreaper_ctx wrctx;
uint32_t runtime_options;

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
void deconstruct_btree(http_link_t *, wr_cache_t *) __nonnull((1,2));
int do_request(struct http_t *) __nonnull((1)) __wur;

int reap(struct http_t *) __nonnull((1)) __wur;

#define TOKEN_MAX 64

uint32_t runtime_options;
pthread_t thread_screen_tid;
pthread_attr_t thread_screen_attr;
pthread_mutex_t screen_mutex;

#define FAST_MODE 0x100

#define option_set(o) ((o) & runtime_options)
#define set_option(o) (runtime_options |= (o))
#define unset_option(o) (runtime_options &= ~(o))

#define ACTION_ING_STR ">>> "
#define ACTION_DONE_STR "@@@ "
#define ATTENTION_STR "!!! "
#define STATISTICS_STR "+++ "

#define FL_RESET 0x1

/*
 * For paths that are forbidden as
 * layed out in the robots.txt file.
 */
extern char **forbidden_tokens;

#endif /* !defined WEBREAPER_H */
