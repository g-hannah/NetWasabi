#ifndef FAST_MODE_H
#define FAST_MODE_H 1

#include "cache.h"
#include "http.h"

#define FAST_MODE_NR_WORKERS 4

struct worker_ctx
{
	wr_cache_t *cache1; /* shared */
	wr_cache_t *cache2; /* shared */
	struct http_t http; /* private */
};

struct cache_ctx
{
	wr_cache_t *cache;
	http_link_t *root;
};

#endif /* !defined FAST_MODE_H */
