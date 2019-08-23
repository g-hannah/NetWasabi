#include <stdlib.h>
#include "malloc.h"

void *
wr_malloc(size_t size)
{
	if (size == 0)
		size = 1;

	void *mem = malloc(size);

	assert(mem != NULL);

	return mem;
}

void *
wr_zmalloc(size_t size)
{
	if (size == 0)
		size = 1;

	void *mem = malloc(size);

	assert(mem);

	memset(mem, 0, size);

	return mem;
}

void *
wr_calloc(int nr, size_t size)
{
	void *mem = calloc(nr, size);

	assert(mem);

	return mem;
}

void *
wr_realloc(void *old_ptr, size_t size)
{
	old_ptr = realloc(old_ptr, size);

	assert(old_ptr);

	return old_ptr;
}
