#include <assert.h>
#include <string.h>
#include "graph.h"
#include "malloc.h"

#define GRAPH_EXTEND_MATRIX(g)\
do {\
	int __i;\
	int __j;\
	int __old_rows = (g)->matrix_size;\
	int __new_rows = (g)->matrix_size * 2;\
	int __old_ints = (__old_rows / BITS_PER_INT);\
	int __new_ints = (__new_rows / BITS_PER_INT);\
	if ((__old_rows & (BITS_PER_INT - 1)))\
		++__old_rows;\
	if ((__new_rows & (BITS_PER_INT - 1)))\
		++__new_rows;\
	(g)->matrix = realloc((g)->matrix, (__new_rows * sizeof(int *)));\
	assert((g)->matrix);\
	for (__i = 0; __i < __old_rows; ++__i)\
	{\
		(g)->matrix[__i] = realloc((g)->matrix[__i], (__new_ints * sizeof(int)));\
		for (__j = __old_ints; __j < __new_ints; ++__j)\
			(g)->matrix[__j] = 0;\
	}\
	for (__i = __old_rows; __i < __new_rows; ++__i)\
	{\
		(g)->matrix[__i] = NULL;\
		(g)->matrix[__i] = calloc(__new_ints, sizeof(int));\
		for (__j = 0; __j < __new_ints; ++__j)\
		{\
			(g)->matrix[__i][__j] = 0;\
		}\
	}\
	(g)->matrix_size = (size_t)__new_rows;\
} while (0)

struct graph_ctx *
graph_ctx_new(struct graph_ctx **g)
{
	assert(g);

	*g = wr_malloc(sizeof(struct graph_ctx));

	if (!(*g))
		return NULL;

	(*g)->graph_root = NULL;
	(*g)->nr_nodes = 0;
	
	(*g)->matrix = wr_calloc(GRAPH_MATRIX_DEFAULT_SIZE, sizeof(int *));
	if (!(*g)->matrix)
		goto fail_destroy_graph;

	int i;
	int j;

	for (i = 0; i < GRAPH_MATRIX_DEFAULT_SIZE; ++i)
	{
		(*g)->matrix[i] = NULL;
		(*g)->matrix[i] = wr_calloc(GRAPH_MATRIX_DEFAULT_SIZE, sizeof(int));

		if (!(*g)->matrix[i])
			goto fail_destroy_graph;

		for (j = 0; j < GRAPH_MATRIX_DEFAULT_SIZE; ++j)
			(*g)->matrix[i][j] = 0;
	}

	(*g)->matrix_size = GRAPH_MATRIX_DEFAULT_SIZE;
	return *g;

	fail_destroy_graph:
	if ((*g)->matrix)
	{
		for (i = 0; i < GRAPH_MATRIX_DEFAULT_SIZE; ++i)
		{
			if ((*g)->matrix[i])
			{
				free((*g)->matrix[i]);
				(*g)->matrix[i] = NULL;
			}
		}

		free((*g)->matrix);
		(*g)->matrix = NULL;
	}

	free(*g);
	*g = NULL;

	return *g;
}

struct graph_node *
graph_node_init(struct graph_node **gn, size_t nr_members, size_t member_size)
{
	assert(gn);

	*gn = wr_malloc(sizeof(struct graph_node));

	if (!(*gn))
		return NULL;

	(*gn)->left = NULL;
	(*gn)->right = NULL;

	(*gn)->data = wr_calloc(nr_members+1, member_size);

	if (!(*gn)->data)
		goto fail_destroy_node;

	return *gn;

	fail_destroy_node:
	free(*gn);
	*gn = NULL;
	return NULL;
}

struct graph_node *
graph_node_insert(struct graph_ctx *g, void *data, size_t data_len)
{
	assert(g);
	assert(data);

	if (g->nr_nodes >= g->matrix_size)
		GRAPH_EXTEND_MATRIX(g);

	if (!g->graph_root)
	{
		if (!graph_node_init(&g->graph_root, data_len+1, (size_t)1))
			return NULL;

		memcpy(g->graph_root->data, data, data_len);
		*((char *)g->graph_root->data + data_len) = 0;
		g->graph_root->node_idx = g->nr_nodes;
		GRAPH_INC_NODES(g);
	}

	struct graph_node *nptr = g->graph_root;
	int cmp;

	assert(nptr);

	while (1)
	{
		cmp = memcmp(data, nptr->data, data_len);

		if (((char *)data)[0] && ((char *)nptr->data)[0] && !cmp) /* duplicate data */
		{
#ifdef DEBUG
			fprintf(stderr, "Duplicate data not inserted\n");
#endif
			return nptr;
		}
		else
		if (cmp < 0)
		{
			if (!nptr->left)
			{
				if (!graph_node_init(&nptr->left, data_len, (size_t)1))
					return NULL;

				memcpy(nptr->left->data, data, data_len);
				*((char *)nptr->left->data + data_len) = 0;
				nptr->left->node_idx = g->nr_nodes;
				GRAPH_INC_NODES(g);
				return nptr->left;
			}
			else
			{
				nptr = nptr->left;
				continue;
			}
		}
		else
		{
			if (!nptr->right)
			{
				if (!graph_node_init(&nptr->right, data_len, (size_t)1))
					return NULL;

				memcpy(nptr->right->data, data, data_len);
				*((char *)nptr->right->data + data_len) = 0;
				nptr->right->node_idx = g->nr_nodes;
				GRAPH_INC_NODES(g);
				return nptr->right;
			}
			else
			{
				nptr = nptr->right;
				continue;
			}
		}
	}

	return NULL;
}

static void
destroy_btree(struct graph_node *root)
{
	assert(root);

	if (root->left)
		destroy_btree(root->left);

	if (root->right)
		destroy_btree(root->right);

	free(root);
	root = NULL;

	return;
}

void
destroy_graph(struct graph_ctx *g)
{
	assert(g);

	int i;

	if (g->graph_root)
		destroy_btree(g->graph_root);

	if (g->matrix)
	{
		int matrix_size = g->matrix_size;
		for (i = 0; i < matrix_size; ++i)
		{
			if (g->matrix[i])
			{
				free(g->matrix[i]);
				g->matrix[i] = NULL;
			}
		}

		free(g->matrix);
		g->matrix = NULL;
	}

	free(g);
	g = NULL;
	return;
}

#ifdef DEBUG
void
bitprint_int(int _int)
{
	int bit = (1 << (BITS_PER_INT - 1));
	int bits = BITS_PER_INT;

	while (bits)
	{
		if (_int & bit)
			fputc(0x31, stderr);
		else
			fputc(0x30, stderr);

		--bits;
		_int <<= 1;
	}

	fputc(0x0a, stderr);

	return;
}

void
matrix_bitprint(struct graph_ctx *g)
{
	assert(g);
	assert(g->matrix);

	int matrix_y = g->matrix_size;
	int matrix_x = (g->matrix_size / BITS_PER_INT);
	int i;
	int j;
	int _int;
	int bits = BITS_PER_INT;
	int bit = (1 << (bits - 1));

	for (i = 0; i < matrix_y; ++i)
	{
		for (j = 0; j < matrix_x; ++j)
		{
			_int = g->matrix[i][j];
			bits = BITS_PER_INT;

			while (bits)
			{
				if (_int & bit)
					fputc(0x31, stderr);
				else
					fputc(0x30, stderr);

				_int <<= 1;
				--bits;
			}

			fputc(0x20, stderr);
		}

		fputc(0x0a, stderr);
	}

	return;
}
#endif

struct graph_node *
graph_get_node_by_data(struct graph_ctx *graph, void *data, size_t data_len)
{
	struct graph_node *nptr = graph->graph_root;
	int cmp;

	while (nptr)
	{
		cmp = memcmp(data, nptr->data, data_len);

		if (!cmp)
		{
			return nptr;
		}
		else
		if (cmp < 0)
		{
			nptr = nptr->left;
			continue;
		}
		else
		{
			nptr = nptr->right;
			continue;
		}
	}

	return NULL;
}

struct graph_node *
graph_get_node_by_index(struct graph_ctx *graph, int index)
{
	struct graph_node *nptr = graph->graph_root;
	int cmp;

	while (nptr)
	{
		cmp = (index - nptr->node_idx);

		if (!cmp)
		{
			return nptr;
		}
		else
		if (cmp < 0)
		{
			nptr = nptr->left;
			continue;
		}
		else
		{
			nptr = nptr->right;
			continue;
		}
	}

	return NULL;
}

/**
 * graph_get_all_nodes_by_data - get all nodes that match DATA;
 * since we compare the data in each node with the first DATA_LEN bytes
 * of DATA, there may be several matches. There are times when we need
 * to look at all matching nodes. For example, in the robots.txt files,
 * often there are rules such as:
 *
 * Allow: /api.php?
 * Allow: /api.php?action=
 * Allow: /api.php?*&action=
 *
 * We may have a URL that is "/api.php?param1=one&param2=two&action=some_action".
 * If we only returned the first match ("api.php?"), we couldn't determine
 * whether our URL is actually legitimate. We need to be able to say: it matches
 * the first node; it does not match the second; it matches the final node.
 * Otherwise, all URLs with params after api.php?, even if illegal, would be
 * deemed legitimate due to our successful match with the first node.
 *
 * @graph: the graph in which to search for matching nodes.
 * @data: the input data to match against
 * @data_len: the number of bytes of our input data
 */
struct graph_node_collection *
graph_get_all_nodes_by_data(struct graph_ctx *graph, void *data, size_t data_len)
{
	struct graph_node_collection *collection = NULL;
	struct graph_node *nptr;
	int cmp;

	assert(graph);

	nptr = graph->graph_root;
	if (!nptr)
		return NULL;

	while (nptr)
	{
		cmp = memcmp(data, nptr->data, data_len);
		if (((char *)data)[0] && ((char *)nptr->data)[0] && !cmp)
		{
			if (!collection)
			{
				collection = malloc(sizeof(struct graph_node_collection));
				assert(collection);
				collection->nr_nodes = 0;
				collection->nodes = calloc(1, sizeof(struct graph_node));
				assert(collection->nodes);
				memcpy(&collection->nodes[0], nptr, sizeof(struct graph_node));
				collection->nr_nodes = 1;
				collection->nodes[0].left = NULL;
				collection->nodes[0].right = NULL;
			}
			else
			{
				collection->nodes = realloc(collection->nodes, (collection->nr_nodes + 1) * sizeof(struct graph_node));
				assert(collection->nodes);
				memcpy(&collection->nodes[collection->nr_nodes], nptr, sizeof(struct graph_node));
				collection->nodes[collection->nr_nodes].left = NULL;
				collection->nodes[collection->nr_nodes].right = NULL;
			}

			++(collection->nr_nodes);
			nptr = nptr->right;
			continue;
		}
		else
		if (cmp < 0)
		{
			nptr = nptr->left;
			continue;
		}
		else
		{
			nptr = nptr->right;
			continue;
		}
	}

	return collection;
}
