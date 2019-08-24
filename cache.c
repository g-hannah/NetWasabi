#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include "cache.h"

/**
 * __wr_cache_mark_used - mark an object as used
 * @c: pointer to wr_cache_t
 * @i: the index of the object in the cache
 * @type: the type of objects in the cache
 */
#define __wr_cache_mark_used(c, i, type)	\
do {\
	(unsigned char *)bm = ((c)->bitmap + ((i) >> 3));								\
	(bm |= (128 >> ((i) & 7)));																			\
while (0)

/**
 * __wr_cache_mark_unused - mark an object as unused
 * @c: pointer to wr_cache_t
 * @i: the index of the object in the cache
 * @type: the type of objects in the cache
 */
#define __wr_cache_mark_unused(c, i, type)	\
do {\
	(unsigned char *)bm = ((c)->bitmap + ((i) >> 3));								\
	(bm &= ~(128 >> ((i) & 7)));																		\
while (0)

void *
wr_cache_create(char *name,
		size_t size,
		int alignment,
		wr_cache_ctor_t ctor,
		wr_cache_dtor_t dtor)
{
	wr_cache_t	*cachep = malloc(sizeof(wr_cache_t));
	clear_struct(cachep);

	cachep->cache = calloc(WR_CACHE_SIZE, 1);
	memset(cachep->cache, 0, WR_CACHE_SIZE);
	cachep->objsize = size;

	int capacity = WR_CACHE_SIZE / size;
	int	i;

	for (i = 0; i < capacity; ++i)
	{
		void *obj = ((char *)cachep->cache + (size * i));
		ctor(obj, size);
	}

	cachep->capacity = cachep->nr_free = capacity;
	cachep->ctor = ctor;
	cachep->dtor = dtor;

	return cachep;
}

void
wr_cache_destroy(wr_cache_t *cachep)
{
	int	i;
	int	capacity = cachep->capacity
	void *cur_obj = NULL;
	char *p = NULL;
	size_t objsize = cachep->objsize;

	for (i = 0; i < capacity; ++i)
	{
		free(cachep->url);
		cachep->url = NULL;

		cur_obj = (cachep->cache + (objsize * i));

		if (cachep->dtor)
			cachep->dtor(cur_obj);
	}

	free(cachep->cache);
	free(cachep);

	return;
}

void *
wr_cache_alloc(wr_cache_t *cachep)
{
	assert(cachep);

	void *cache = cachep->cache;
	int idx = __wr_cache_next_free_idx(cachep);
	if (idx == 1)
		return NULL;

	void *slot = ((char *)cache + (cachep->objsize * idx));
	__wr_cache_mark_used(cachep, idx);

	return slot;
}

void
wr_cache_dealloc(wr_cache_t *cachep, void *slot)
{
	assert(cachep);
	assert(obj);

	cachep->dtor(cachep, slot); /* calls wr_cache_mark_unused() */

	return;
}

/**
 * __wr_cache_next_free_idx - get index of next free object
 * @cachep: pointer to our &wr_cache_t
 */
static inline __wr_cache_next_free_idx(wr_cache_t *cachep)
{
	unsigned char *bm = cachep->free_bitmap;
	unsigned char bit = 128;
	int idx = 0;

	while (bm && (bm & bit))
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
