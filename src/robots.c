#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "robots.h"
#include "webreaper.h"

/**
 * robots_page_permitted : check that each token in the URL
 * is connected to the next in the graph.
 *
 * @graph: the structure holding matrix and root node
 * @url: the page to verify
 */
int
robots_page_permitted(struct graph_ctx *graph, char *url_page)
{
	char *p;
	char *e;
	size_t url_len = strlen(url_page);
	char *end = url_page + url_len;
	struct graph_node *n1;
	struct graph_node *n2;
	static char token1[MAX_TOKEN];
	static char token2[MAX_TOKEN];

	p = url_page;
	if (*p == '/')
		++p;

	e = memchr(p, '/', (end - p));

	if (!e)
		e = end;

	while (1)
	{
		strncpy(token1, p, (e - p));
		token1[e - p] = 0;

		n1 = graph_get_node(graph, token1, (e - p));

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

		n2 = graph_get_node(graph, token2, (e - p));
		if (!n2)
			return 0;

		if (!GRAPH_NODES_CONNECTED(graph, n1, n2))
		{
			return 0;
		}

		if (e == end)
			break;
	}

	return 1;
}

int
create_token_graph(struct graph_ctx *graph, buf_t *buf)
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

	if (!(start = strstr(buf->buf_head, "User-agent: *")))
	{
		put_error_msg("Did not find User-Agent line in robots.txt");
		return -1;
	}

	eol = memchr(start, '\n', (tail - start));

	if (!eol)
		return -1;

	start = ++eol;

	if (!(graph_ctx_new(&graph)))
		return -1;

	prev_node = NULL;
	cur_node = NULL;

	while (1)
	{
		if (strncmp("Allow:", start, 6))
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

			cur_node = graph_node_insert(graph, (void *)new, strlen(new));

			if (cur_node && prev_node)
			{
				if (memcmp(cur_node->data, prev_node->data, strlen((char *)cur_node->data)))
				{
					if (!GRAPH_NODES_CONNECTED(graph, prev_node, cur_node))
					{
#ifdef DEBUG
						fprintf(stderr, "Connecting %s (node %d) to %s (node %d) in graph\n",
								prev, prev_node->node_idx, new, cur_node->node_idx);
#endif
						GRAPH_NODES_CONNECT(graph, prev_node, cur_node);

						if (!GRAPH_NODES_CONNECTED(graph, prev_node, cur_node))
						{
#ifdef DEBUG
							fprintf(stderr, "Failed to connect %s (%d) with %s (%d) (bit==%d)\n"
									"idx %% bits_per_int = %d\n",
									prev, prev_node->node_idx, new, cur_node->node_idx,
									GRAPH_NODES_CONNECTED(graph, prev_node, cur_node),
									(int)GRAPH_NODES_BIT_RESULT(cur_node));
							bitprint_int(GRAPH_NODES_INTEGER(graph, prev_node, cur_node));
#endif
						}
						assert(GRAPH_NODES_CONNECTED(graph, prev_node, cur_node));
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
	put_error_msg("%d unique nodes in graph", graph->nr_nodes);
#endif

	return 0;
}
