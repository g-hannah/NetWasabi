#ifndef UTILS_URL_H
#define UTILS_URL_H 1

#include "buffer.h"
#include "connection.h"

int make_full_url(connection_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
int make_local_url(connection_t *, buf_t *, buf_t *) __nonnull((1,2,3)) __wur;
int is_xdomain(connection_t *, buf_t *) __nonnull((1,2)) __wur;

#endif /* !defined UTILS_URL_H */