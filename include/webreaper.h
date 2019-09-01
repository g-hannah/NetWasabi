#ifndef WEBREAPER_H
#define WEBREAPER_H 1

#include <stdint.h>
#include <string.h>

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

#define OPT_USE_TLS	0x1

extern uint32_t runtime_options;

#define option_set(o) ((o) & runtime_options)
#define set_option(o) (runtime_options |= (o))
#define unset_option(o) (runtime_options &= ~(o))

extern char **forbidden_tokens;

#endif /* !defined WEBREAPER_H */
