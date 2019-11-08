#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "robots.h"
#include "netwasabi.h"

/**
 * __url_legality - check that each token in the URL
 * is connected to the next in the graph.
 *
 * @graph: the structure holding matrix and root node
 * @url: the page to verify
 * @test_forbidden: boolean to determine what the return means.
 *   if testing the forbidden graph, 1 == illegal, otherwise 1 == legal.
 */
static int
__url_legality(struct graph_ctx *graph, char *url_page, int test_forbidden)
{
	char *p;
	char *e;
	size_t url_len = strlen(url_page);
	char *end = url_page + url_len;
	struct graph_node *n1;
	struct graph_node *n2;
	static char token1[MAX_TOKEN];
	static char token2[MAX_TOKEN];
	int connected = 0;

	p = url_page;
	if (*p == '/')
		++p;

	e = memchr(p, '/', (end - p));

	if (!e)
		e = end;

/*
 * In some robots.txt files, there are pattern matching rules.
 * For example, "?api*action=". So in that case, we can't just
 * compare TOKEN1 and TOKEN2. Need to determine if our URL
 * token matches the pattern stipulated within the data node
 * of the graph. There will likely be no tokens after this any-
 * way since the pattern always seem to be in the params given
 * to the page.
 */

	while (1)
	{
		strncpy(token1, p, (e - p));
		token1[e - p] = 0;

		n1 = graph_get_node_by_data(graph, token1, (e - p));

/*
 * Only time this can happen is with the very first token, because
 * after checking connectedness of token1 and token2, token2 becomes
 * token1.
 */
		if (!n1)
			return 0;

		if (e == end)
			break;

		p = ++e;
		e = memchr(p, '/', (end - p));
		if (!e)
			e = end;

		strncpy(token2, p, (e - p));
		token2[e - p] = 0;

		n2 = graph_get_node_by_data(graph, token2, (e - p));

		if (!n2)
			return 0;

		connected = GRAPH_NODES_CONNECTED(graph, n1, n2);

		if (test_forbidden)
		{
			if (connected)
				return 1;
		}
		else
		{
			if (!connected)
				return 0;
		}

		if (e == end)
			break;
	}

	if (test_forbidden)
		return 0; /* No, it's not illegal */
	else
		return 1; /* Yes, it is legal */
}

int
robots_eval_url(struct graph_ctx *allowed, struct graph_ctx *forbidden, char *const url)
{
	int illegal = 0;
	int legal = 0;

	illegal = __url_legality(forbidden, url, 1);
	legal = __url_legality(allowed, url, 0);

/*
 * if (somehow) illegal && legal, or !illegal && !legal, default to LEGAL
 */
	if (illegal && !legal)
		return 0;
	else
		return 1;
}

int
create_token_graphs(struct graph_ctx **allowed, struct graph_ctx **forbidden, buf_t *buf)
{
	assert(buf);

	char *start;
	char *eol;
	char *tail = buf->buf_tail;
	char *ts;
	char *te;
	static char new[MAX_TOKEN];
	static char prev[MAX_TOKEN];
	struct graph_node *prev_node;
	struct graph_node *cur_node;
	int allow = 0;

	if (!(start = strstr(buf->buf_head, "User-agent: *")))
	{
		put_error_msg("Did not find User-Agent line in robots.txt");
		return -1;
	}

	eol = memchr(start, '\n', (tail - start));

	if (!eol)
		return -1;

	start = ++eol;

	if (!(graph_ctx_new(allowed)))
		return -1;

	if (!(graph_ctx_new(forbidden)))
		return -1;

	assert(*allowed);
	assert(*forbidden);

	prev_node = NULL;
	cur_node = NULL;

	while (1)
	{
		if (!strncasecmp("user-agent", start, 10))
			break;

		if (!strncasecmp("allow:", start, 6))
		{
			allow = 1;
		}
		else
		if (!strncasecmp("Disallow:", start, 9))
		{
			allow = 0;
		}
		else
		{
			eol = memchr(start, '\n', (tail - start));
			if (!eol || eol >= tail)
				break;

			start = ++eol;
			if (start >= tail)
				break;
			else
				continue;
		}

		eol = memchr(start, ' ', (tail - start));
		if (!eol || eol >= tail)
			break;

		start = ++eol;
		eol = memchr(start, '\n', (tail - start));
		if (!eol || eol >= tail)
			break;

		ts = start;
		if (*ts == '/')
			++ts;

		while (1)
		{
			te = memchr(ts, '/', (eol - ts));

			if (!te)
				te = eol;

			strncpy(new, ts, (te - ts));
			new[te - ts] = 0;

			cur_node = graph_node_insert(allow ? *allowed : *forbidden, (void *)new, strlen(new));

			if (cur_node && prev_node)
			{
				if (memcmp(cur_node->data, prev_node->data, strlen((char *)cur_node->data)))
				{
					if (!GRAPH_NODES_CONNECTED(allow ? *allowed : *forbidden, prev_node, cur_node))
					{
#ifdef DEBUG
						fprintf(stderr, "Connecting %s (node %d) to %s (node %d) in graph \"%s\"\n",
								prev, prev_node->node_idx, new, cur_node->node_idx, allow ? "allowed" : "forbidden");
#endif
						GRAPH_NODES_CONNECT(allow ? *allowed : *forbidden, prev_node, cur_node);
						assert(GRAPH_NODES_CONNECTED(allow ? *allowed : *forbidden, prev_node, cur_node));
					}
				}
			}

			if (te == eol)
				break;
			else
				ts = ++te;

			prev_node = cur_node;
			strcpy(prev, new);
		}

		start = ++eol;

		prev[0] = 0;
		new[0] = 0;
		prev_node = NULL;
		cur_node = NULL;

		if (start >= tail)
			break;
	}

#ifdef DEBUG
	put_error_msg("unique nodes: \"allowed\"=%d ; \"forbidden\"=%d", (*allowed)->nr_nodes, (*forbidden)->nr_nodes);
#endif

	return 0;
}
