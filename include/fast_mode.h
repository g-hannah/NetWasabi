#ifndef FAST_MODE_H
#define FAST_MODE_H 1

#include "cache.h"

#define FAST_MODE_NR_WORKERS 4

struct worker_ctx
{
	wr_cache_t *cache1; /* shared */
	wr_cache_t *cache2; /* shared */
};

#endif /* !defined FAST_MODE_H */
