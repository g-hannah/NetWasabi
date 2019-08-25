#ifndef MALLOC_H
#define MALLOC_H

void *wr_malloc(size_t) __wur;
void *wr_zmalloc(size_t) __wur;
void *wr_calloc(int, size_t) __wur;
void *wr_realloc(void *, size_t) __nonnull((1)) __wur;

#endif /* !defined MALLOC_H */
