#ifndef ROBOTS_H
#define ROBOTS_H

#include "buffer.h"
#include "cache.h"
#include "graph.h"

#define MAX_TOKEN 512

int create_token_graphs(struct graph_ctx **, struct graph_ctx **, buf_t *) __nonnull((1)) __wur;
int robots_eval_url(struct graph_ctx *, struct graph_ctx *, char *const) __nonnull((1,2,3)) __wur;

#endif /* !defined ROBOTS_H */
