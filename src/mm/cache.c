#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "netwasabi.h"

#define BITS_PER_CHAR (sizeof(char) * 8)

inline void
cache_lock(cache_t *cachep)
{
	pthread_mutex_lock(&cachep->lock);
}

inline void
cache_unlock(cache_t *cachep)
{
	pthread_mutex_unlock(&cachep->lock);
}

/**
 * __cache_next_free_idx - get index of next free object
 * @cachep: pointer to the metadata cache structure
 */
static inline int __cache_next_free_idx(cache_t *cachep)
{
	unsigned char *bm = cachep->free_bitmap;
	unsigned char bit = 1;
	int capacity = cachep->capacity;
	int idx = 0;

	while (1)
	{
		while (bit && (*bm & bit) && idx < capacity)
		{
			bit <<= 1;
			++idx;
		}

		if (idx >= capacity)
			return -1;

		if (!bit)
		{
			++bm;
			bit = 1;
			continue;
		}
		else
		if (bit && !(*bm & bit))
		{
			if (idx >= capacity)
				return -1;

			return idx;
		}
	}

	return -1;
}

/**
 * __cache_mark_used - mark an object as used
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __cache_mark_used(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm |= (unsigned char)(1 << ((i) & 7)));							\
} while(0)

/**
 * __cache_mark_unused - mark an object as unused
 * @c: pointer to the metadata cache structure
 * @i: the index of the object in the cache
 */
#define __cache_mark_unused(c, i)	\
do {\
	unsigned char *bm = ((c)->free_bitmap + ((i) >> 3));	\
	(*bm &= (unsigned char) ~(1 << ((i) & 7)));						\
} while(0)

/**
 * cache_nr_used - return the number of objects used
 * @cachep: pointer to the metadata cache structure
 *
 *		The cache lock must be held before calling this
 *		because evidently the result of this call could
 *		be invalid soon as it returns due to another
 *		thread adding or removing objects.
 */
inline int cache_nr_used(cache_t *cachep)
{
	return (cachep->capacity - cachep->nr_free);
}

/**
 * cache_capacity - return capacity of the cache
 * @cachep: pointer to the metadata cache structure
 */
inline int cache_capacity(cache_t *cachep)
{
	return cachep->capacity;
}

static inline void *__cache_obj(cache_t *cachep, int idx)
{
	return ((char *)cachep->cache + (idx * cachep->objsize));
}

static inline off_t __cache_obj_offset(cache_t *cachep, void *obj)
{
	return (off_t)((char *)obj - (char *)cachep->cache);
}

static inline int __cache_obj_index(cache_t *cachep, void *obj)
{
	return (int)(__cache_obj_offset(cachep, obj) / cachep->objsize);
}

static inline int __owner_is_in_cache(cache_t *cachep, void *addr)
{
	int in_cache = 0;

	if ((unsigned long)addr >= (unsigned long)cachep->cache && (unsigned long)addr < (unsigned long)((char *)cachep->cache + (cachep->capacity * cachep->objsize)))
		in_cache = 1;

	return in_cache;
}

/*
 * Track assigned pointers, so that in case of a realloc
 * of the cache, we can adjust the address within the
 * object refered to by P.
 *
 * cookie_header = cache_alloc(cookie_cache, &cookie_header);
 *
 * cookie_header is assigned the slot, and we save &cookie_header
 * in the assigned list.
 *
 * Multiple instances of the same pointer to a cache object can
 * exist. In the case of wanting to save many URLs in the link
 * cache, we are not concerned with the pointer to the objects.
 * So we can use one single pointer in a loop to store the URLs.
 * However, in such cases, we CANNOT use a local var for this
 * in a loop. So we use a global pointer allocated on the heap.
 * That way, when we need to patch addresses of cache objects
 * due to a relocation on the heap, we don't need to worry about
 * trying to access an address somewhere on the stack that is
 * now out of scope and may cause a segfault (or worse).
 */

/*
 * TODO: use a binary tree for the assigned list to make
 * searching for an active pointer ~ O(log(N))
 */

#define CACHE_ASSIGN_PTR(c, p, s)\
do {\
	struct cache_obj_ctx *____ctx_p;\
	int __in_cache;\
	if ((p) && __owner_is_in_cache((c), (p)))\
		__in_cache = 1;\
	int ____nr_ = (c)->nr_assigned;\
	assert(____nr_ < (c)->capacity);\
	____ctx_p = ((c)->assigned_list + ____nr_);\
	____ctx_p->ptr_addr = (p);\
	____ctx_p->obj_offset = __cache_obj_offset((c), (s));\
	if (__in_cache)\
	{\
		____ctx_p->in_cache = 1;\
		____ctx_p->ptr_offset = (off_t)((char *)(p) - (char *)(c)->cache);\
	}\
	else\
	{\
		____ctx_p->in_cache = 0;\
		____ctx_p->ptr_offset = 0;\
	}\
	++((c)->nr_assigned);\
} while (0)

#define CACHE_REMOVE_PTR(c, p)\
do {\
	struct cache_obj_ctx *____ctx_p = (c)->assigned_list;\
	int ____nr_ = (c)->nr_assigned;\
	int ____i_d_x;\
	int ____k;\
	assert(____nr_ <= (c)->capacity);\
	for (____i_d_x = 0; ____i_d_x < ____nr_; ++____i_d_x)\
	{\
		if ((p) && ____ctx_p->ptr_addr == (p))\
		{\
			for (____k = ____i_d_x; ____k < (____nr_ - 1); ++____k)\
				memcpy((void *)&____ctx_p[____k], (void *)&____ctx_p[____k+1], sizeof(struct cache_obj_ctx));\
			--((c)->nr_assigned);\
			--____nr_;\
			memset((void *)&____ctx_p[____k], 0, sizeof(struct cache_obj_ctx));\
			--____i_d_x;\
		}\
		++____ctx_p;\
	}\
} while (0)

#define CACHE_ADJUST_PTRS(c)\
do {\
	struct cache_obj_ctx *____ctx_p;\
	int ____nr_ = (c)->nr_assigned;\
	int ____i_d_x;\
	assert(____nr_ <= (c)->capacity);\
	for (____ctx_p = (c)->assigned_list, ____i_d_x = 0;\
			____i_d_x < ____nr_;\
			++____i_d_x)\
	{\
		if (____ctx_p->in_cache)\
		{\
			____ctx_p->ptr_addr = (void *)((char *)(c)->cache + ____ctx_p->ptr_offset);\
		}\
		if (____ctx_p->ptr_addr)\
			*((unsigned long *)____ctx_p->ptr_addr) = (unsigned long)((char *)(c)->cache + ____ctx_p->obj_offset);\
		++____ctx_p;\
	}\
} while (0)

#define CACHE_INC_FREE(c) ++((c)->nr_free)
#define CACHE_DEC_FREE(c) --((c)->nr_free)

/**
 * cache_obj_used - determine if an object is active or not.
 * @cachep: pointer to the metadata cache structure
 * @obj pointer to the queried cache object
 */
inline int
cache_obj_used(cache_t *cachep, void *obj)
{
	int obj_idx;
	int capacity = cachep->capacity;
	unsigned char *bm = cachep->free_bitmap;

	obj_idx = __cache_obj_index(cachep, obj);

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

void *
cache_next_used(cache_t *cachep)
{
	int idx = 0;
	int capacity = cachep->capacity;

	while (!cache_obj_used(cachep, __cache_obj(cachep, idx)) && idx < capacity)
		++idx;

	if (idx == capacity)
		return (void *)NULL;
	else
		return __cache_obj(cachep, idx);
}

/**
 * cache_create - create a new cache
 * @name: name of the cache for statistics
 * @size: size of the type of object that will be stored in the cache
 * @alignment: minimum alignment of the cache objects
 * @ctor: pointer to a constructor function called on each object
 * @dtor: pointer to a destructor function called on each dealloc()
 */
cache_t *
cache_create(char *name,
		size_t size,
		int alignment,
		cache_ctor_t ctor,
		cache_dtor_t dtor)
{
	int capacity = (CACHE_SIZE / size);
	int bitmap_size;
	int	i;

	bitmap_size = (capacity / BITS_PER_CHAR);
	if (capacity & (BITS_PER_CHAR - 1))
		++bitmap_size;

	cache_t	*cachep = malloc(sizeof(cache_t));
	memset(cachep, 0, sizeof(*cachep));

	cachep->name = nw_calloc(CACHE_MAX_NAME, 1);
	strcpy(cachep->name, name);

	cachep->cache = nw_calloc(CACHE_SIZE, 1);
	cachep->objsize = size;

	cachep->assigned_list = nw_calloc(capacity, sizeof(struct cache_obj_ctx));
	cachep->nr_assigned = 0;

	cachep->free_bitmap = nw_calloc(bitmap_size, 1);

	if (ctor)
	{
		for (i = 0; i < capacity; ++i)
			ctor(__cache_obj(cachep, i));
	}

	cachep->capacity = capacity;
	cachep->nr_free = capacity;
	cachep->cache_size = CACHE_SIZE;
	cachep->bitmap_size = bitmap_size;
	cachep->ctor = ctor;
	cachep->dtor = dtor;

	pthread_mutex_init(&cachep->lock, NULL);

	return cachep;
}

/**
 * cache_destroy - destroy a cache
 * @cachep: pointer to the metadata cache structure
 */
void
cache_destroy(cache_t *cachep)
{
	assert(cachep);

	int	i;
	int capacity = cache_capacity(cachep);

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

	if (cachep->dtor)
	{
		cache_dtor_t dtor = cachep->dtor;
		for (i = 0; i < capacity; ++i)
			dtor(__cache_obj(cachep, i));
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

	pthread_mutex_destroy(&cachep->lock);

	memset(cachep, 0, sizeof(*cachep));
	free(cachep);
	cachep = NULL;

	return;
}

/**
 * cache_alloc - allocate an object from a cache
 * @cachep: pointer to the metadata cache structure
 */
void *
cache_alloc(cache_t *cachep, void *ptr_addr)
{
	assert(cachep);

	void *slot = NULL;
	size_t new_size;
	uint16_t bitmap_size = cachep->bitmap_size;
	uint16_t new_bitmap_size;
	int idx = __cache_next_free_idx(cachep);
	int old_capacity = cachep->capacity;
	int new_capacity;
	int added_capacity;
	int i;
	int in_cache = 0;
	unsigned char *bm;
	void *old_cache;
	void *owner_addr = ptr_addr;
	off_t owner_off;

/*
 * Our bitmap can be deceiving and an index may be return
 * because it found a zero-bit but in fact that has gone
 * beyond the capacity of the cache.
 */
	if (idx != -1 && idx < old_capacity && cachep->nr_assigned < old_capacity)
	{
		assert(idx < old_capacity);
		slot = __cache_obj(cachep, idx);

		__cache_mark_used(cachep, idx);
		CACHE_ASSIGN_PTR(cachep, owner_addr, slot);
		CACHE_DEC_FREE(cachep);
		assert(cache_nr_used(cachep) > 0);

		return slot;
	}
	else
	{
		old_capacity = cachep->capacity;
		new_capacity = (old_capacity * 2);
		added_capacity = (new_capacity - old_capacity);
		new_size = (new_capacity * cachep->objsize);
		new_bitmap_size = (new_capacity / BITS_PER_CHAR);
		if (new_capacity & (BITS_PER_CHAR - 1))
			++new_bitmap_size;

		cachep->assigned_list = realloc(cachep->assigned_list, (new_capacity * sizeof(struct cache_obj_ctx)));
		assert(cachep->assigned_list);

		if (owner_addr)
		{
			if (__owner_is_in_cache(cachep, owner_addr))
			{
				owner_off = (off_t)((char *)owner_addr - (char *)cachep->cache);
				in_cache = 1;
			}
		}

		old_cache = cachep->cache;

		cachep->cache = realloc(cachep->cache, new_size);
		assert(cachep->cache);

		cachep->free_bitmap = realloc(cachep->free_bitmap, new_bitmap_size);
		assert(cachep->free_bitmap);

		cachep->nr_free += added_capacity;
		cachep->capacity = new_capacity;
		cachep->cache_size = new_size;
		cachep->bitmap_size = new_bitmap_size;

/*
 * Patch all assigned pointers with the new
 * address in the case of our cache being
 * copied elsewhere in the heap.
 */
		if (old_cache != cachep->cache)
		{
			if (owner_addr && in_cache)
				owner_addr = (void *)((char *)cachep->cache + owner_off);

			CACHE_ADJUST_PTRS(cachep);
		}

		bm = (cachep->free_bitmap + bitmap_size);
		int added_bitmap_size = (new_bitmap_size - bitmap_size);
		for (i = 0; i < added_bitmap_size; ++i)
			*bm++ = 0;

		if (cachep->ctor)
		{
			cache_ctor_t ctor = cachep->ctor;
			for (i = old_capacity; i < new_capacity; ++i)
				ctor(__cache_obj(cachep, i));
		}

		idx = __cache_next_free_idx(cachep);
		slot = __cache_obj(cachep, idx);

		__cache_mark_used(cachep, idx);

		CACHE_ASSIGN_PTR(cachep, owner_addr, slot);
		CACHE_DEC_FREE(cachep);
		assert(cache_nr_used(cachep) > 0);

		return slot;
	}

	/* shouldn't reach here */
	return NULL;
}

/**
 * cache_dealloc - return an object to the cache
 * @cachep: pointer to the metadata cache structure
 * @slot: the object to be returned
 */
void
cache_dealloc(cache_t *cachep, void *slot, void *ptr_addr)
{
	assert(cachep);
	assert(slot);
	//assert(ptr_addr);

	int obj_idx;
	int nr_assigned = cachep->nr_assigned;

	obj_idx = __cache_obj_index(cachep, slot);

/*
	fprintf(stderr,
			"Deallocating object #%d from cache \"%s\"\n",
			obj_idx, cachep->name);
*/

	if (ptr_addr != NULL)
	{
		CACHE_REMOVE_PTR(cachep, ptr_addr);
		assert(cachep->nr_assigned < nr_assigned);

		if (cachep->nr_assigned >= nr_assigned)
		{
			fprintf(stderr, "cache \"%s\"; nr_assigned before=%d ; nr_assigned now=%d\n(cache capacity=%d)\n",
				cachep->name, nr_assigned, cachep->nr_assigned,
				cachep->capacity);
		}
	}

	CACHE_INC_FREE(cachep);
	__cache_mark_unused(cachep, obj_idx);
	assert(cache_nr_used(cachep) >= 0);

	return;
}

static void *
__cache_get_obj_owner(cache_t *cachep, void *slot)
{
	assert(cachep);
	assert(slot);

	struct cache_obj_ctx *ctx = cachep->assigned_list;
	int nr_assigned = cachep->nr_assigned;
	int i;

	for (i = 0; i < nr_assigned; ++i)
	{
		if (ctx->ptr_addr)
		{
			if (*((unsigned long *)ctx->ptr_addr) == (unsigned long)slot)
				return ctx->ptr_addr;
		}

		++ctx;
	}

	return NULL;
}

void
cache_clear_all(cache_t *cachep)
{
	void *slot;
	void *owner;
	int capacity = cachep->capacity;
	int i;

	for (i = 0; i < capacity; ++i)
	{
		slot = __cache_obj(cachep, i);
		owner = __cache_get_obj_owner(cachep, slot);

		if (cache_obj_used(cachep, slot))
			cache_dealloc(cachep, slot, owner);
	}

	return;
}
