#ifndef WEBREAPER_H
#define WEBREAPER_H 1

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#define WEBREAPER_BUILD		"0.0.1"
#define WEBREAPER_DIR			"WR_Reaped"

#define COL_ORANGE	"\x1b[38;5;208m"
#define COL_RED			"\x1b[38;5;9m"
#define COL_BLUE		"\x1b[38;5;12m"
#define COL_PINK		"\x1b[38;5;13m"
#define COL_GREEN		"\x1b[38;5;10m"
#define COL_BROWN		"\x1b[38;5;130m"
#define COL_LIGHTRED "\x1b[38;5;204m"
#define COL_LIGHTBLUE "\x1b[38;5;27m"
#define COL_LIGHTGREEN "\x1b[38;5;46m"
#define COL_LIGHTGREY "\x1b[38;5;250m"
#define COL_DARKRED "\x1b[38;5;160m"
#define COL_DARKGREY "\x1b[38;5;240m"
#define COL_DARKBLUE "\x1b[38;5;20m"
#define COL_DARKORANGE "\x1b[38;5;202m"
#define COL_DARKGREEN "\x1b[38;5;28m"
#define COL_END			"\x1b[m"

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

struct url_types
{
	char *string;
	char delim;
	size_t len;
};

#define NR_URL_TYPES 11
struct url_types url_types[NR_URL_TYPES];
extern uint32_t runtime_options;
int TRAILING_SLASH;
int path_max;
char **user_blacklist;
int USER_BLACKLIST_NR_TOKENS;

int SET_SOCK_FLAG_ONCE;
int SET_SSL_SOCK_FLAG_ONCE;
size_t TOTAL_BYTES_RECEIVED;
struct winsize winsize;

#define UPDATE_BYTES_UP 10
#define UPDATE_CACHE1_COUNT_UP 10
#define UPDATE_CACHE2_COUNT_UP 10
#define UPDATE_CACHE_STATUS_UP 9
#define UPDATE_CURRENT_URL_UP 6
#define UPDATE_CURRENT_LOCAL_UP 5
#define UPDATE_STATUS_CODE_UP 7
#define UPDATE_OP_STATUS_UP 3
#define UPDATE_BYTES_RIGHT 40
#define UPDATE_CACHE1_COUNT_RIGHT 11
#define UPDATE_CACHE2_COUNT_RIGHT 27
#define UPDATE_CACHE1_STATUS_RIGHT 3
#define UPDATE_CACHE2_STATUS_RIGHT 18
#define UPDATE_CURRENT_URL_RIGHT 1
#define UPDATE_CURRENT_LOCAL_RIGHT 1
#define UPDATE_STATUS_CODE_RIGHT 2
#define UPDATE_OP_STATUS_RIGHT 2
#define CACHE_STATUS_LEN 10
#define OUTPUT_TABLE_COLUMNS 90

#define FL_CACHE_STATUS_FILLING 0x1
#define FL_CACHE_STATUS_DRAINING 0x2
#define FL_CACHE_STATUS_FULL 0x4

void update_operation_status(const char *, int) __nonnull((1));
void update_current_url(const char *) __nonnull((1));
void update_current_local(const char *) __nonnull((1));
void update_bytes(size_t);
void update_cache1_count(int);
void update_cache2_count(int);
void update_cache_status(int, int);

#define TOKEN_MAX 64

#define option_set(o) ((o) & runtime_options)
#define set_option(o) (runtime_options |= (o))
#define unset_option(o) (runtime_options &= ~(o))

#define ACTION_ING_STR ">>> "
#define ACTION_DONE_STR "@@@ "
#define ATTENTION_STR "!!! "
#define STATISTICS_STR "+++ "

#define FL_RESET 0x1
#define FL_OPERATION_TIMEOUT 0x2

/*
 * For paths that are forbidden as
 * layed out in the robots.txt file.
 */
extern char **forbidden_tokens;

#endif /* !defined WEBREAPER_H */
