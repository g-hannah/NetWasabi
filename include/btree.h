#ifndef __BTREE_H__
#define __BTREE_H__ 1

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BTree_Node
{
	//void *key;
	void *data;
	size_t data_len;
	struct BTree_Node *left;
	struct BTree_Node *right;
} btree_node_t;

typedef struct BTree_Object
{
	btree_node_t *root;
	int nr_nodes;
} btree_obj_t;

btree_obj_t *BTREE_object_new(void);
void BTREE_object_destroy(btree_obj_t *);
int BTREE_put_data(btree_obj_t *, void *, size_t);
btree_node_t *BTREE_search_data(btree_obj_t *, void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* !defined __BTREE_H__ */
