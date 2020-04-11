#ifndef CACHE_H
#define CACHE_H 1

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#define CACHE_SIZE 4096
#define CACHE_MAX_NAME 64

typedef int (*cache_ctor_t)(void *);
typedef void (*cache_dtor_t)(void *);

struct cache_obj_ctx
{
	int in_cache; /* active pointer resides in cache */
	void *ptr_addr; /* the address of the active pointer (it holds the address of a cache object) */
	off_t obj_offset; /* offset of cache object from start of cache */
	off_t ptr_offset; /* offset of the active pointer if it resides in the cache */
};

typedef struct cache_t
{
	void *cache;
	struct cache_obj_ctx *assigned_list;
	int nr_assigned;
	unsigned char *free_bitmap;
	int capacity;
	int nr_free;
	size_t objsize;
	size_t cache_size;
	uint16_t bitmap_size;
	char *name;
	pthread_mutex_t lock;
	cache_ctor_t ctor;
	cache_dtor_t dtor;
} cache_t;

cache_t *cache_create(char *, size_t, int, cache_ctor_t, cache_dtor_t);
void cache_destroy(cache_t *) __nonnull((1));
void *cache_alloc(cache_t *, void *) __nonnull((1,2)) __wur;
void cache_dealloc(cache_t *, void *, void *) __nonnull((1,2));
int cache_obj_used(cache_t *, void *) __nonnull((1,2)) __wur;
void *cache_next_used(cache_t *) __nonnull((1)) __wur;
int cache_nr_used(cache_t *) __nonnull((1)) __wur;
int cache_capacity(cache_t *) __nonnull((1)) __wur;
void cache_clear_all(cache_t *) __nonnull((1));
void cache_lock(cache_t *) __nonnull((1));
void cache_unlock(cache_t *) __nonnull((1));

#endif /* CACHE_H */
