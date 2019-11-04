#ifndef FAST_MODE_H
#define FAST_MODE_H 1

#include "cache.h"
#include "http.h"

#define FAST_MODE_NR_WORKERS 4

struct worker_ctx
{
	wr_cache_t *cache1; /* shared with other workers */
	wr_cache_t *cache2; /* shared with other workers */
	struct http_t *http; /* private */
};

int do_fast_mode(const char *) __nonnull((1)) __wur;

#endif /* !defined FAST_MODE_H */
