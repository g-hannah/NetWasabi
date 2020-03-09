#ifndef MALLOC_H
#define MALLOC_H

#include <stdlib.h>

void *nw_malloc(size_t) __wur;
void *nw_zmalloc(size_t) __wur;
void *nw_calloc(int, size_t) __wur;
void *nw_realloc(void *, size_t) __nonnull((1)) __wur;
char *nw_strdup(const char *) __nonnull((1)) __wur;

#endif /* !defined MALLOC_H */
