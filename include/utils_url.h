#ifndef UTILS_URL_H
#define UTILS_URL_H 1

#include "buffer.h"
#include "http.h"

int make_full_url(struct http_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
int make_local_url(struct http_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
void encode_url(buf_t *) __nonnull((1));
int is_xdomain(struct http_t *, buf_t *) __nonnull((1,2)) __wur;
int local_archive_exists(char *) __nonnull((1)) __wur;
int has_extension(char *) __nonnull((1)) __wur;

#endif /* !defined UTILS_URL_H */
