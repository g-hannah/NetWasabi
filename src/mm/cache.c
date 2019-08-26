#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "cache.h"
#include "malloc.h"

/**
 * __wr_cache_next_free_idx - get index of next free object
 * @cachep: pointer to our &wr_cache_t
 */
static inline int __wr_cache_next_free_idx(wr_cache_t *cachep)
{
	unsigned char *bm = cachep->free_bitmap;
	unsigned char bit = 128;
	int idx = 0;

	while (bm && (*bm & bit))
	{
		bit >>= 1;

		++idx;

		if (!bit)
		{
			++bm;
			bit = 128;
		}
	}

	if (bm)
		return idx;
	else
		return -1;
}

/**
 * __wr_cache_mark_used - mark an object as used
 * @c: pointer to wr_cache_t
 * @i: the index of the object in the cache
 */
#define __wr_cache_mark_used(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm |= (unsigned char)(128 >> ((i) & 7)));						\
} while(0)

/**
 * __wr_cache_mark_unused - mark an object as unused
 * @c: pointer to wr_cache_t
 * @i: the index of the object in the cache
 */
#define __wr_cache_mark_unused(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm &= (unsigned char)~(128 >> ((i) & 7)));					\
} while(0)

wr_cache_t *
wr_cache_create(char *name,
		size_t size,
		int alignment,
		wr_cache_ctor_t ctor,
		wr_cache_dtor_t dtor)
{
	wr_cache_t	*cachep = malloc(sizeof(wr_cache_t));
	clear_struct(cachep);

	cachep->cache = wr_calloc(WR_CACHE_SIZE, 1);
	cachep->objsize = size;
	cachep->free_bitmap = wr_calloc(WR_CACHE_BITMAP_SIZE, 1);

	int capacity = WR_CACHE_SIZE / size;
	int	i;

	for (i = 0; i < capacity; ++i)
	{
		void *obj = (void *)((char *)cachep->cache + (size * i));
		ctor(obj);
	}

	cachep->capacity = cachep->nr_free = capacity;
	cachep->ctor = ctor;
	cachep->dtor = dtor;

#ifdef DEBUG
	printf(
			"Created cache \"%s\"\n"
			"Size of each object=%lu bytes\n"
			"Capacity of cache=%d objects\n"
			"%s\n"
			"%s\n",
			name,
			size,
			capacity,
			ctor ? "constructor provided\n" : "constructor not provided\n",
			dtor ? "destructor provided\n" : "destructor not provided\n");
#endif

	return cachep;
}

void
wr_cache_destroy(wr_cache_t *cachep)
{
	int	i;
	int	capacity = cachep->capacity;
	void *cur_obj = NULL;
	size_t objsize = cachep->objsize;

	for (i = 0; i < capacity; ++i)
	{
		cur_obj = (void *)((char *)cachep->cache + (objsize * i));

		if (cachep->dtor)
			cachep->dtor(cur_obj);
	}

	free(cachep->cache);
	free(cachep->free_bitmap);
	free(cachep);

	return;
}

void *
wr_cache_alloc(wr_cache_t *cachep)
{
	assert(cachep);

	void *cache = cachep->cache;
	int idx = __wr_cache_next_free_idx(cachep);
	if (idx == -1)
		return NULL;

	void *slot = (void *)((char *)cache + (cachep->objsize * idx));
	__wr_cache_mark_used(cachep, idx);

	return slot;
}

void
wr_cache_dealloc(wr_cache_t *cachep, void *slot)
{
	assert(cachep);
	assert(slot);

	off_t obj_off;
	size_t objsize = cachep->objsize;

	obj_off = (off_t)(((char *)slot - (char *)cachep->cache) / objsize);

	__wr_cache_mark_unused(cachep, obj_off);

	return;
}

