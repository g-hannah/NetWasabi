#include <assert.h>
#include <stdlib.h>
#include "cache.h"

void *
wr_cache_alloc(wr_cache_t *cachep)
{
	assert(cachep);

	void *slot = wr_cache_next_free_obj(cachep);
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

	int capacity = WR_CACHE_SIZE / size;
	int	i;

	for (i = 0; i < capacity; ++i)
	{
		void *obj = ((char *)cachep->cache + (size * i));
		ctor(obj, size);
	}

	cachep->nr_free = capacity;
}
