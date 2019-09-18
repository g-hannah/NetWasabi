#ifndef WEBREAPER_H
#define WEBREAPER_H 1

#include <stdint.h>
#include <string.h>

#define WEBREAPER_BUILD		"0.0.1"
#define WEBREAPER_DIR			"WR_Reaped"

#define COL_ORANGE	"\x1b[38;5;208m"
#define COL_RED			"\x1b[38;5;9m"
#define COL_GREEN		"\x1b[38;5;40m"
#define COL_END			"\x1b[m"

#define clear_struct(s) memset((s), 0, sizeof(*(s)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

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

#define SKIP_CRNL(____p) do { while ((*____p) == 0x0a || (*____p) == 0x0d) { ++(____p); }; } while (0)

#define OPT_USE_TLS	0x1
#define OPT_SHOW_REQ_HEADER 0x2
#define OPT_SHOW_RES_HEADER 0x4
#define OPT_ALLOW_XDOMAIN 0x8 /* if not set, ignore URLs that are a different host */

extern uint32_t runtime_options;

#define option_set(o) ((o) & runtime_options)
#define set_option(o) (runtime_options |= (o))
#define unset_option(o) (runtime_options &= ~(o))

/*
 * For paths that are forbidden as
 * layed out in the robots.txt file.
 */
extern char **forbidden_tokens;

#endif /* !defined WEBREAPER_H */
