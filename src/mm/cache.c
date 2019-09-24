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
	int obj_idx;
	int capacity = cachep->capacity;
	size_t objsize = cachep->objsize;
	unsigned char *bm = cachep->free_bitmap;

	obj_idx = (((char *)obj - (char *)cachep->cache) / objsize);

	if (obj_idx > capacity)
		return -1;

	/*
	 * If the object is the, say, 10th object,
	 * then bit 9 represents it, so go up
	 * 9/8 bytes = 1 byte; then move up the
	 * remaining bit.
	 */
	bm += (obj_idx >> 3);

	return (*bm & (1 << (obj_idx & 7))) ? 1 : 0;
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
	int capacity = (WR_CACHE_SIZE / size);
	int bitmap_size;
	int	i;
	void *slot;

	bitmap_size = (capacity / 8);
	if (capacity & 0x7)
		++bitmap_size;

	wr_cache_t	*cachep = malloc(sizeof(wr_cache_t));
	clear_struct(cachep);

	cachep->name = wr_calloc(WR_CACHE_MAX_NAME, 1);
	strcpy(cachep->name, name);

	cachep->cache = wr_calloc(WR_CACHE_SIZE, 1);
	cachep->objsize = size;

	cachep->assigned_list = wr_calloc(capacity * 2, sizeof(struct wr_cache_obj_ctx));
	cachep->nr_assigned = 0;

	cachep->free_bitmap = wr_calloc(bitmap_size, 1);

	for (i = 0; i < capacity; ++i)
	{
		slot = (void *)((char *)cachep->cache + (size * i));

		if (ctor)
			ctor(slot);
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
			"Capacity of cache=%d objects\n",
			name,
			size,
			capacity);
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
	void *slot = NULL;
	void *cache = NULL;
	size_t objsize = cachep->objsize;

#ifdef DEBUG
	fprintf(stderr,
		"Destroying cache \"%s\"\n"
		"Size of cache = %lu bytes\n"
		"Size of objects = %lu bytes\n"
		"Cache capacity = %d objects\n",
		cachep->name,
		cachep->cache_size,
		cachep->objsize,
		cachep->capacity);
#endif

	if (cachep->name)
	{
		free(cachep->name);
		cachep->name = NULL;
	}

	if (cachep->free_bitmap)
	{
		free(cachep->free_bitmap);
		cachep->free_bitmap = NULL;
	}

	cache = cachep->cache;

	for (i = 0; i < capacity; ++i)
	{
		slot = (void *)((char *)cache + (objsize * i));

		if (cachep->dtor)
			cachep->dtor(slot);
	}

	if (cachep->assigned_list)
	{
		free(cachep->assigned_list);
		cachep->assigned_list = NULL;
	}

	if (cachep->free_bitmap)
	{
		free(cachep->free_bitmap);
		cachep->free_bitmap = NULL;
	}

	if (cachep->cache)
	{
		free(cachep->cache);
		cachep->cache = NULL;
	}

	clear_struct(cachep);
	free(cachep);
	cachep = NULL;

	return;
}

/**
 * wr_cache_alloc - allocate an object from a cache
 * @cachep: pointer to the metadata cache structure
 */
void *
wr_cache_alloc(wr_cache_t *cachep, void *ptr_addr)
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
	int moved = 0;
	int in_cache = 0;
	unsigned char *bm;
	void *old_addr;
	void *active_ptr = ptr_addr;
	off_t active_off;

#ifdef DEBUG
	fprintf(stderr,
		"%sCACHE: %s\n"
		"number of active pointers = %d\n"
		"number of objects cache can hold = %d%s\n",
		COL_RED, cachep->name,
		cachep->nr_assigned,
		cachep->capacity,
		COL_END);
#endif

	assert(cachep->nr_assigned <= cachep->capacity);
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
		WR_CACHE_ASSIGN_PTR(cachep, ptr_addr, slot);
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

#ifdef DEBUG
		fprintf(stderr,
			"Extending cache \"%s\"\n"
			"Size of objects = %lu bytes\n"
			"Current cache size = %lu bytes\n"
			"Current capacity = %d objects\n"
			"New cache size = %lu bytes\n"
			"New capacity = %d objects\n"
			"Added capacity = %d objects\n",
			cachep->name,
			objsize,
			cache_size,
			old_capacity,
			new_size,
			new_capacity,
			added_capacity);

		fprintf(stderr, "%sExtending ->assigned_list (adding %lu bytes)%s\n",
			COL_RED, (added_capacity * sizeof(struct wr_cache_obj_ctx)), COL_END);
#endif

		cachep->assigned_list = wr_realloc(cachep->assigned_list, (new_capacity * sizeof(struct wr_cache_obj_ctx)));

		if ((unsigned long)active_ptr > (unsigned long)cachep->cache
		&& (((char *)active_ptr - (char *)cachep->cache) < cache_size))
		{
			active_off = (off_t)((char *)active_ptr - (char *)cachep->cache);
			in_cache = 1;
		}

		old_addr = cachep->cache;
#ifdef DEBUG
		fprintf(stderr, "%sCalling realloc() for ->cache%s\n", COL_RED, COL_END);
#endif
		cachep->cache = wr_realloc(cachep->cache, cache_size * 2);
#ifdef DEBUG
		fprintf(stderr, "%sCalling realloc() for ->free_bitmap%s\n", COL_RED, COL_END);
#endif
		cachep->free_bitmap = wr_realloc(cachep->free_bitmap, bitmap_size * 2);

/*
 * Patch all assigned pointers with the new
 * address in the case of our cache being
 * copied elsewhere in the heap.
 */
		if ((unsigned long)cachep->cache != (unsigned long)old_addr)
		{
			moved = 1;
			WR_CACHE_ADJUST_PTRS(cachep);
		}

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

		if (moved)
		{
			if (in_cache)
				active_ptr = (void *)((char *)cachep->cache + active_off);
		}

		WR_CACHE_ASSIGN_PTR(cachep, active_ptr, slot);
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
wr_cache_dealloc(wr_cache_t *cachep, void *slot, void *ptr_addr)
{
	assert(cachep);
	assert(slot);

	int obj_idx;
	int nr_assigned = cachep->nr_assigned;
	size_t objsize = cachep->objsize;

	obj_idx = (int)(((char *)slot - (char *)cachep->cache) / objsize);

/*
	fprintf(stderr,
			"Deallocating object #%d from cache \"%s\"\n",
			obj_idx, cachep->name);
*/

	if (ptr_addr)
	{
		WR_CACHE_REMOVE_PTR(cachep, ptr_addr);
		assert(cachep->nr_assigned < nr_assigned);
	}


	WR_CACHE_INC_FREE(cachep);
	__wr_cache_mark_unused(cachep, obj_idx);
	assert(wr_cache_nr_used(cachep) >= 0);

	return;
}

static void *
__get_assigned_list_ptr(wr_cache_t *cachep, void *slot)
{
	assert(cachep);
	assert(slot);

	struct wr_cache_obj_ctx *ctx = cachep->assigned_list;
	int nr_assigned = cachep->nr_assigned;
	int i;

	for (i = 0; i < nr_assigned; ++i)
	{
		if (*((unsigned long *)ctx->ptr_addr) == (unsigned long)slot)
			return ctx->ptr_addr;

		++ctx;
	}

	return NULL;
}

void
wr_cache_clear_all(wr_cache_t *cachep)
{
	void *slot;
	void *ptr_addr;
	size_t objsize = cachep->objsize;
	int capacity = cachep->capacity;
	int i;

#ifdef DEBUG
	fprintf(stderr,
			"%sClearing all objects from cache \"%s\"\n"
			"nr_assigned = %d%s\n",
			COL_DARKBLUE,
			cachep->name,
			cachep->nr_assigned,
			COL_END);
#endif

	for (i = 0; i < capacity; ++i)
	{
		slot = (void *)((char *)cachep->cache + (i * objsize));
		ptr_addr = __get_assigned_list_ptr(cachep, slot);

		if (wr_cache_obj_used(cachep, slot))
			wr_cache_dealloc(cachep, slot, ptr_addr);
	}

#ifdef DEBUG
	fprintf(stderr,
		"%sCleared objects\n"
		"nr_assigned = %d%s\n",
		COL_DARKBLUE,
		cachep->nr_assigned,
		COL_END);
#endif

	return;
}
