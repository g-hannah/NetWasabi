#ifndef WR_CACHE_H
#define WR_CACHE_H 1

#include "webreaper.h"

/*
 * 31 ..... 16 15 ..... 0
 *   cache nr     obj nr
 */
#define WR_CACHE_SIZE 4096
#define WR_CACHE_MAX_NAME 64

#define WR_CACHE_INC_FREE(c) ++((c)->nr_free)
#define WR_CACHE_DEC_FREE(c) --((c)->nr_free)

typedef int (*wr_cache_ctor_t)(void *);
typedef void (*wr_cache_dtor_t)(void *);

typedef struct wr_cache_t
{
	void *cache;
	unsigned char *free_bitmap;
	int capacity;
	int nr_free;
	size_t objsize;
	size_t cache_size;
	uint16_t bitmap_size;
	char *name;
	wr_cache_ctor_t ctor;
	wr_cache_dtor_t dtor;
} wr_cache_t;

wr_cache_t *wr_cache_create(char *, size_t, int, wr_cache_ctor_t, wr_cache_dtor_t);
void wr_cache_destroy(wr_cache_t *) __nonnull((1));
void *wr_cache_alloc(wr_cache_t *) __nonnull((1)) __wur;
void wr_cache_dealloc(wr_cache_t *, void *) __nonnull((1,2));
int wr_cache_obj_used(wr_cache_t *, void *) __nonnull((1,2)) __wur;
int wr_cache_nr_used(wr_cache_t *) __nonnull((1)) __wur;
int wr_cache_capacity(wr_cache_t *) __nonnull((1)) __wur;
void wr_cache_clear_all(wr_cache_t *) __nonnull((1));

#endif /* WR_CACHE_H */
