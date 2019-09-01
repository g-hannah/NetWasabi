#ifndef WR_CACHE_H
#define WR_CACHE_H 1

#include "webreaper.h"

#define WR_CACHE_SIZE	4096
#define WR_CACHE_BITMAP_SIZE 512 /* Unlikely, but could have 512 objects of one byte each */
#define WR_CACHE_NR_SHIFT 24
#define WR_CACHE_NR_MASK (255 << WR_CACHE_NR_SHIFT)

typedef int (*wr_cache_ctor_t)(void *);
typedef void (*wr_cache_dtor_t)(void *);

typedef struct wr_cache_t
{
	void *cache;
	unsigned char *free_bitmap;
	int capacity;
	int nr_free;
	size_t objsize;
	char *name;
	wr_cache_ctor_t ctor;
	wr_cache_dtor_t dtor;
	struct wr_cache_t *next;
	//struct list_head *list;
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
