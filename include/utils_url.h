#ifndef UTILS_URL_H
#define UTILS_URL_H 1

#include "buffer.h"
#include "http.h"

int make_full_url(struct http_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
int make_local_url(struct http_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
void encode_url(buf_t *) __nonnull((1));
int is_xdomain(struct http_t *, buf_t *) __nonnull((1,2)) __wur;

/*
 * Check if we have already archived the document.
 * We need the HTTP object as an argument to access
 * the function pointers in http->ops.
 */
int local_archive_exists(struct http_t *, char *) __nonnull((1)) __wur;
int has_extension(char *) __nonnull((1)) __wur;

int URL_parseable(char *);
void transform_document_URLs(struct http_t *);

#endif /* !defined UTILS_URL_H */
