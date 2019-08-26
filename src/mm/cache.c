#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "cache.h"
#include "http.h"
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
	int	cache_nr = 0;
	wr_cache_t *ptr = cachep;

	while (bm && (*bm & bit))
	{
		bit >>= 1;

		++idx;

		if (!bit)
		{
			++bm;
			bit = 128;
		}

		if (!bm)
		{
			if (ptr->next)
			{
				ptr = ptr->next;
				bm = ptr->free_bitmap;
				bit = 128;
				++cache_nr;
			}
		}
	}

	/* Use the 8 most significant bits to indicate to which cache the slot belongs */
	assert(cache_nr < 256);
	idx &= ~(WR_CACHE_NR_MASK);
	idx |= (cache_nr << WR_CACHE_NR_SHIFT);

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
	(*bm &= (unsigned char) ~(128 >> ((i) & 7)));					\
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
	int	i;
	int capacity = (WR_CACHE_SIZE / size);

	for (i = 0; i < capacity; ++i)
	{
		void *obj = (void *)((char *)cachep->cache + (size * i));

		if (ctor)
			ctor(obj);
	}

	cachep->capacity = capacity;
	cachep->next = NULL;
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
	assert(cachep);

	int	i;
	int	capacity;
	void *cur_obj = NULL;
	size_t objsize = cachep->objsize;
	wr_cache_t *ptr = cachep;
	wr_cache_t *tmp = NULL;

	while (ptr)
	{
		capacity = ptr->capacity;
		for (i = 0; i < capacity; ++i)
		{
			cur_obj = (void *)((char *)ptr->cache + (objsize * i));

			if (ptr->dtor)
				ptr->dtor(cur_obj);

			free(ptr->free_bitmap);

			tmp = ptr->next;

			free(ptr->cache);
			free(ptr);
			ptr = tmp;
		}
	}

	return;
}

void *
wr_cache_alloc(wr_cache_t *cachep)
{
	assert(cachep);

	void *cache = cachep->cache;
	void *slot = NULL;
	int idx = __wr_cache_next_free_idx(cachep);
	int cache_nr = 0;
	size_t objsize = cachep->objsize;

	cache_nr = (idx >> WR_CACHE_NR_SHIFT);
	cache_nr &= 255;
	idx &= ~(WR_CACHE_NR_MASK);

	/*
	 * Get a new cache block.
	 */
	if (idx == -1)
	{
		wr_cache_t *ptr = cachep;

		while (ptr->next)
			ptr = ptr->next;

		ptr->next = wr_cache_create(
				cachep->name,
				WR_CACHE_SIZE,
				0,
				cachep->ctor,
				cachep->dtor);

		slot = ptr->next->cache;

		return slot;
	}

	wr_cache_t *ptr = cachep;

	while (cache_nr--)
		ptr = ptr->next;

	cache = ptr->cache;
	slot = (void *)((char *)cache + (objsize * idx));
	__wr_cache_mark_used(ptr, idx);

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

