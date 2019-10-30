#ifndef WR_CACHE_H
#define WR_CACHE_H 1

#include <pthread.h>
#include <sys/types.h>
#include "webreaper.h"

#define WR_CACHE_SIZE 4096
#define WR_CACHE_MAX_NAME 64

typedef int (*wr_cache_ctor_t)(void *);
typedef void (*wr_cache_dtor_t)(void *);

struct wr_cache_obj_ctx
{
	int in_cache; /* active pointer resides in cache */
	void *ptr_addr; /* the address of the active pointer (it holds the address of a cache object) */
	off_t obj_offset; /* offset of cache object from start of cache */
	off_t ptr_offset; /* offset of the active pointer if it resides in the cache */
};

typedef struct wr_cache_t
{
	void *cache;
	struct wr_cache_obj_ctx *assigned_list;
	int nr_assigned;
	unsigned char *free_bitmap;
	int capacity;
	int nr_free;
	size_t objsize;
	size_t cache_size;
	uint16_t bitmap_size;
	char *name;
	pthread_spinlock_t lock;
	wr_cache_ctor_t ctor;
	wr_cache_dtor_t dtor;
} wr_cache_t;

wr_cache_t *wr_cache_create(char *, size_t, int, wr_cache_ctor_t, wr_cache_dtor_t);
void wr_cache_destroy(wr_cache_t *) __nonnull((1));
void *wr_cache_alloc(wr_cache_t *, void *) __nonnull((1,2)) __wur;
void wr_cache_dealloc(wr_cache_t *, void *, void *) __nonnull((1,2,3));
int wr_cache_obj_used(wr_cache_t *, void *) __nonnull((1,2)) __wur;
void *wr_cache_next_used(wr_cache_t *) __nonnull((1)) __wur;
int wr_cache_nr_used(wr_cache_t *) __nonnull((1)) __wur;
int wr_cache_capacity(wr_cache_t *) __nonnull((1)) __wur;
void wr_cache_clear_all(wr_cache_t *) __nonnull((1));

#endif /* WR_CACHE_H */
