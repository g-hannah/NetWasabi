#ifndef ROBOTS_H
#define ROBOTS_H

#include "buffer.h"
#include "cache.h"
#include "connection.h"

#define MAX_TOKEN 512

int create_token_graph(struct graph_ctx *, buf_t *) __nonnull((1)) __wur;
int robots_page_permitted(struct graph_ctx *, char *) __nonnull((1,2)) __wur;

#endif /* !defined ROBOTS_H */
