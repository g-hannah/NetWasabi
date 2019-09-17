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
	int capacity = cachep->capacity;
	int idx = 0;

	while (*bm & bit)
	{
		bit <<= 1;

		++idx;

		if (!bit)
		{
			++bm;
			bit = 1;
		}

		if (idx >= capacity)
			return -1;
	}

	return idx;
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
	unsigned char *bm = cachep->free_bitmap;

	capacity = cachep->capacity;
	offset = (((char *)obj - (char *)ptr->cache) / objsize);

	if (offset > (off_t)capacity)
		return -1;

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
	int capacity = (WR_CACHE_SIZE / size);
	int bitmap_size;
	int	i;

	bitmap_size = (capacity / 8);

	if (capacity & 0x7)
		++bitmap_size;

	cachep->free_bitmap = wr_calloc(bitmap_size, 1);

	for (i = 0; i < capacity; ++i)
	{
		void *obj = (void *)((char *)cachep->cache + (size * i));

		if (ctor)
			ctor(obj);
	}

	cachep->capacity = capacity;
	cachep->nr_free = capacity;
	cachep->cache_size = WR_CACHE_SIZE;
	cachep->bitmap_size = bitmap_size;
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
	void *obj = NULL;
	void *cache = NULL;
	size_t objsize = cachep->objsize;

	if (cachep->free_bitmap)
	{
		free(cachep->free_bitmap);
		cachep->free_bitmap = NULL;
	}

	cache = cachep->cache;

	for (i = 0; i < capacity; ++i)
	{
		obj = (void *)((char *)cache + (objsize * i));

		if (cachep->dtor)
			cachep->dtor(obj);
	}

	if (cachep->free_bitmap)
	{
		free(cachep->free_bitmap);
		cachep->free_bitmap = NULL;
	}

	free(cachep->cache);
	free(cachep);

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
	size_t objsize = cachep->objsize;
	size_t cache_size = cachep->cache_size;
	size_t new_size;
	uint16_t bitmap_size = cachep->bitmap_size;
	int idx = __wr_cache_next_free_idx(cachep);
	int old_capacity = cachep->capacity;
	int new_capacity;
	int added_capacity;
	int i;
	unsigned char *bm;

/*
 * Our bitmap can be deceiving and an index may be return
 * because it found a zero-bit but in fact that has gone
 * beyond the capacity of the cache.
 */
	if (idx != -1 && idx < old_capacity)
	{
		assert(idx < old_capacity);
		slot = (void *)((char *)cache + (idx * objsize));
		__wr_cache_mark_used(cachep, idx);
		WR_CACHE_DEC_FREE(cachep);
		assert(wr_cache_nr_used(cachep) > 0);
		return slot;
	}
	else
	{
		new_size = cache_size * 2;

		old_capacity = cachep->capacity;
		new_capacity = (new_size / objsize);
		added_capacity = (new_capacity - old_capacity);

		fprintf(stderr,
			"doubling cache size to %lu bytes\n"
			"old_capacity=%d\n"
			"new_capacity=%d\n"
			"added_capacity=%d\n",
			new_size,
			old_capacity,
			new_capacity,
			added_capacity);

		cachep->cache = wr_realloc(cachep->cache, cache_size * 2);
		cachep->free_bitmap = wr_realloc(cachep->free_bitmap, bitmap_size * 2);

		assert(cachep->cache);
		assert(cachep->free_bitmap);

		cachep->nr_free += added_capacity;
		cachep->capacity += added_capacity;
		cachep->cache_size = new_size;

		bm = (cachep->free_bitmap + bitmap_size);
		for (i = 0; i < bitmap_size; ++i)
			*bm++ = 0;

		cachep->bitmap_size *= 2;

		if (cachep->ctor)
		{
			slot = (void *)((char *)cachep->cache + (objsize * old_capacity));

			for (i = 0; i < added_capacity; ++i)
			{
				cachep->ctor(slot);
				slot = (void *)((char *)slot + objsize);
			}
		}

		idx = __wr_cache_next_free_idx(cachep);
		slot = (void *)((char *)cachep->cache + (idx * objsize));
		__wr_cache_mark_used(cachep, idx);
		WR_CACHE_DEC_FREE(cachep);
		assert(wr_cache_nr_used(cachep) > 0);
		return slot;
	}

	return NULL;
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
	WR_CACHE_INC_FREE(cachep);
	assert(wr_cache_nr_used(cachep) >= 0);

	return;
}

void
wr_cache_clear_all(wr_cache_t *cachep)
{
	void *obj;
	int i;
	int capacity = cachep->capacity;

	obj = cachep->cache;

	for (i = 0; i < capacity; ++i)
	{
		if (wr_cache_obj_used(cachep, obj))
			wr_cache_dealloc(cachep, obj);

		obj = (void *)((char *)obj + cachep->objsize);
	}

	return;
}
