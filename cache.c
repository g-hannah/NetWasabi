#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include "cache.h"

/**
 * __wr_cache_mark_used - mark an object as used
 * @c: pointer to wr_cache_t
 * @s: the slot in the cache
 * @type: the type of objects in the cache
 */
#define __wr_cache_mark_used(c, s, type)	\
	off_t ioff = (((char *)(s) - (char *)(c)->cache) / (c)->objsize);\
	(type)((type)(c)->cache + ioff)->used = 1;

/**
 * __wr_cache_mark_unused - mark an object as unused
 * @c: pointer to wr_cache_t
 * @s: the slot in the cache
 * @type: the type of objects in the cache
 */
#define __wr_cache_mark_unused(c, s, type) \
	off_t ioff = (((char *)(s) - (char *)(c)->cache) / (c)->objsize);\
	(type)((type)(c)->cache + ioff)->used = 0;

/**
 * __wr_cache_next_free_slot - get next free object from cache
 * @c: pointer to wr_cache_t
 * @type: type of objects stored in cache
 */
#define __wr_cache_next_free_slot(c, type)	\
do {																				\
	void *__slot;															\
	pthread_mutex_lock((c)->mutex);						\
	__slot = ((c)->cache + ((c)->objsize * (c)->next_free));\
	__wr_cache_mark_used(c, __slot, type);		\
	pthread_mutex_unlock((c)->mutex);					\
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

	void *slot = __wr_cache_next_free_obj(cachep);
	wr_cache_mark_used(cachep, slot);

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
