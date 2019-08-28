#ifndef ROBOTS_H
#define ROBOTS_H

#include "buffer.h"

#define TOK_MAXLEN 256
#define TOK_FORBID_DEFAULT_NR 128

int parse_robots(buf_t *) __nonnull((1)) __wur;

#endif /* !defined ROBOTS_H */
