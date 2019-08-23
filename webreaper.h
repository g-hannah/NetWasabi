#ifndef WEBREAPER_H
#define WEBREAPER_H 1

#define clear_struct(s) memset((s), 0, sizeof(*(s)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif /* !defined WEBREAPER_H
