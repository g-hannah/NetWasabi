#ifndef ROBOTS_H
#define ROBOTS_H

#include "buffer.h"
#include "cache.h"
#include "connection.h"

#define TOK_MAXLEN 256
#define TOK_FORBID_DEFAULT_NR 128

#define ROBOT_FILE "/robots.txt"

int parse_robots(buf_t *) __nonnull((1)) __wur;

#endif /* !defined ROBOTS_H */
