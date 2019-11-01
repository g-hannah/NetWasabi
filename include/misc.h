#ifndef MISC_H
#define MISC_H 1

#include "buffer.h"
#include "http.h"

void check_cookies(connection_t *) __nonnull((1));
int connection_closed(connection_t *) __nonnull((1)) __wur;
void check_host(connection_t *) __nonnull((1));
int check_local_dirs(connection_t *, buf_t *) __nonnull((1,2)) __wur;
void replace_with_local_urls(connection_t *, buf_t *) __nonnull((1,2));
int archive_page(connection_t *) __nonnull((1)) __wur;
int parse_links(struct http_t *, struct cache_ctx *, struct cache_ctx *) __nonnull((1,2,3)) __wur;

#endif /* !defined MISC_H */
