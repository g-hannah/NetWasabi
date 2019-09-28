#ifndef GRAPH_H
#define GRAPH_H 1

#include "buffer.h"
#include "cache.h"

/*
 * The graph is directed; connections are:
 *
 * 1. Transitive: if A is connected to B, and B is connected to C, then A is connected to C.
 * 2. NON-abelian: A is connected to B =/= B is connected to A ("/fr/wiki": fr connected to wiki ; wiki not connected to fr)
 *
 *         bit representing node1
 *            v
 * [0][1]........[N]
 * [1] .
 * [2] .
 * [3] .      *<<< bit representing relationship between node1 and node2
 * [4] .
 * ...
 * [N] ...
 *
 * With N graph nodes, each graph node holds an index from 0 to (N-1). Comparing two nodes,
 * use node 1's index to get the int array in the matrix. Use node 2's index to get the bit
 * in the correct byte.
 *
 * E.g. node 1 = index 34, node 2 == index 10:
 *
 * byte == (index / (bits per int)) == 0
 * bit == (index & (bits per int - 1)) == 10
 *
 * (matrix[34][0] & (1 << 10)) ? connected : not-connected.
 *
 */

#define GRAPH_INC_NODES(g) ++((g)->nr_nodes)
#define GRAPH_DEC_NODES(g) --((g)->nr_nodes)

#define GRAPH_MATRIX_DEFAULT_SIZE 256
#define BITS_PER_INT (sizeof(int) * 8)

#define GRAPH_NODES_CONNECTED(g, n1, n2)\
({\
	(g)->matrix[(n1)->node_idx][((n2)->node_idx / BITS_PER_INT)] & (1 << ((n2)->node_idx & (BITS_PER_INT - 1)));\
})

#define GRAPH_NODES_CONNECT(g, n1, n2)\
do {\
	(g)->matrix[(n1)->node_idx][((n2)->node_idx / BITS_PER_INT)] |= (1 << ((n2)->node_idx & (BITS_PER_INT - 1)));\
} while (0)

struct graph_node
{
	void *data;
	int node_idx;
	struct graph_node *left;
	struct graph_node *right;
};

struct graph_ctx
{
	struct graph_node *graph_root;
	int nr_nodes;
	unsigned int **matrix;
	int matrix_size;
};

struct graph_ctx *graph_ctx_new(struct graph_ctx **) __nonnull((1)) __wur;
struct graph_node *graph_node_init(struct graph_node **, size_t, size_t) __nonnull((1)) __wur;
struct graph_node *graph_node_insert(struct graph_ctx *, void *, size_t) __nonnull((1,2)) __wur;
struct graph_node *graph_get_node_by_data(struct graph_ctx *, void *, size_t) __nonnull((1,2)) __wur;
struct graph_node *graph_get_node_by_index(struct graph_ctx *, int) __nonnull((1)) __wur;
void destroy_graph(struct graph_ctx *) __nonnull((1));

#endif /* !defined GRAPH_H */
