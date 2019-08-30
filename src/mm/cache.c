#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "cache.h"
#include "http.h"
#include "malloc.h"

/**
 * __wr_cache_next_free_idx - get index of next free object
 * @cachep: pointer to the metadata cache structure
 */
static inline int __wr_cache_next_free_idx(wr_cache_t *cachep)
{
	unsigned char *bm = cachep->free_bitmap;
	unsigned char bit = 1;
	int idx = 0;
	int	cache_nr = 0;
	wr_cache_t *ptr = cachep;

	while (bm && (*bm & bit))
	{
		bit <<= 1;

		++idx;

		if (!bit)
		{
			++bm;
			bit = 1;
		}

		if (!bm)
		{
			if (ptr->next)
			{
				ptr = ptr->next;
				bm = ptr->free_bitmap;
				bit = 1;
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
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __wr_cache_mark_used(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm |= (unsigned char)(1 << ((i) & 7)));							\
} while(0)

/**
 * __wr_cache_mark_unused - mark an object as unused
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __wr_cache_mark_unused(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm &= (unsigned char) ~(1 << ((i) & 7)));						\
} while(0)

/**
 * wr_cache_nr_used - return the number of objects used
 * @cachep: pointer to the metadata cache structure
 */
inline int wr_cache_nr_used(wr_cache_t *cachep)
{
	return (cachep->capacity - cachep->nr_free);
}

/**
 * wr_cache_capacity - return capacity of the cache
 * @cachep: pointer to the metadata cache structure
 */
inline int wr_cache_capacity(wr_cache_t *cachep)
{
	return cachep->capacity;
}

/**
 * wr_cache_obj_used - determine if an object is active or not.
 * @cachep: pointer to the metadata cache structure
 * @obj pointer to the queried cache object
 */
inline int
wr_cache_obj_used(wr_cache_t *cachep, void *obj)
{
	off_t offset;
	int capacity;
	size_t objsize = cachep->objsize;
	wr_cache_t *ptr = cachep;

	capacity = cachep->capacity;
	offset = (((char *)obj - (char *)ptr->cache) / objsize);

	/*
	 * Then the obj belongs to another cache in the linked list.
	 */
	if (offset > (off_t)capacity)
	{
		while (offset > (off_t)capacity)
		{
			ptr = ptr->next;
			offset = ((char *)obj - (char *)ptr->cache);
		}
	}

	unsigned char *bm = ptr->free_bitmap;

	/*
	 * If the object is the, say, 10th object,
	 * then bit 9 represents it, so go up
	 * 9/8 bytes = 1 byte; then move up the
	 * remaining bit.
	 */
	bm += (offset >> 3);

	return (*bm & (1 << (offset & 7))) ? 1 : 0;
}

/**
 * wr_cache_create - create a new cache
 * @name: name of the cache for statistics
 * @size: size of the type of object that will be stored in the cache
 * @alignment: minimum alignment of the cache objects
 * @ctor: pointer to a constructor function called on each object
 * @dtor: pointer to a destructor function called on each dealloc()
 */
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
	cachep->nr_free = capacity;
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

/**
 * wr_cache_destroy - destroy a cache
 * @cachep: pointer to the metadata cache structure
 */
void
wr_cache_destroy(wr_cache_t *cachep)
{
	assert(cachep);

	int	i;
	int capacity = wr_cache_capacity(cachep);
	void *cur_obj = NULL;
	size_t objsize = cachep->objsize;
	wr_cache_t *ptr = cachep;
	wr_cache_t *tmp = NULL;

	while (ptr)
	{
		capacity = wr_cache_capacity(ptr);

		for (i = 0; i < capacity; ++i)
		{
			cur_obj = (void *)((char *)ptr->cache + (objsize * i));

			if (ptr->dtor)
				ptr->dtor(cur_obj);
		}

		tmp = ptr->next;

		free(ptr->cache);
		free(ptr->free_bitmap);
		free(ptr);

		ptr = tmp;
	}

	return;
}

/**
 * wr_cache_alloc - allocate an object from a cache
 * @cachep: pointer to the metadata cache structure
 */
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
		--(ptr->next->nr_free);
		__wr_cache_mark_used(ptr, (int)0);

		return slot;
	}

	wr_cache_t *ptr = cachep;

	while (cache_nr--)
		ptr = ptr->next;

	cache = ptr->cache;
	slot = (void *)((char *)cache + (objsize * idx));
	--(ptr->nr_free);
	__wr_cache_mark_used(ptr, idx);

	return slot;
}

/**
 * wr_cache_dealloc - return an object to the cache
 * @cachep: pointer to the metadata cache structure
 * @slot: the object to be returned
 */
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

