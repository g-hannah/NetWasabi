#ifndef MISC_H
#define MISC_H 1

#include "buffer.h"
#include "http.h"

int check_local_dirs(struct http_t *, buf_t *) __nonnull((1,2)) __wur;
void replace_with_local_urls(struct http_t *, buf_t *) __nonnull((1,2));
int archive_page(struct http_t *) __nonnull((1)) __wur;
int parse_links(struct http_t *, struct cache_ctx *, struct cache_ctx *) __nonnull((1,2,3)) __wur;

#endif /* !defined MISC_H */
