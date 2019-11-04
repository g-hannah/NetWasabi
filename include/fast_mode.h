#ifndef FAST_MODE_H
#define FAST_MODE_H 1

#include "cache.h"
#include "http.h"

#define FAST_MODE_NR_WORKERS 4

int do_fast_mode(char *) __nonnull((1)) __wur;

#endif /* !defined FAST_MODE_H */
