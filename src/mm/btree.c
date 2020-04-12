#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "btree.h"

#define BTREE_ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

static void
free_nodes(btree_node_t *root)
{
	if (!root)
		return;

	if (root->left)
		free_nodes(root->left);

	if (root->right)
		free_nodes(root->right);

	free(root->data);
	root->data = NULL;
	root->left = NULL;
	root->right = NULL;

	free(root);

	return;
}

static btree_node_t *
new_node(void)
{
	btree_node_t *node = malloc(sizeof(btree_node_t));
	if (!node)
		return NULL;

	memset(node, 0, sizeof(*node));
	return node;
}

int
BTREE_put_data(btree_obj_t *btree_obj, void *data, size_t data_len)
{
	assert(btree_obj);
	assert(data);

	if (!data_len)
		return 0;

	btree_node_t *node = btree_obj->root;
	int cmp = 0;

	while (1)
	{
		cmp = memcmp(data, node->data, data_len);

		if (cmp < 0)
		{
			if (!node->left)
			{
				node->left = new_node();
				node->left->data = calloc(BTREE_ALIGN_SIZE(data_len), 1);
				if (!node->left->data)
					return -1;

				memcpy(node->left->data, data, data_len);
				node->left->data_len = data_len;

				return 0;
			}
			else
			{
				node = node->left;
				continue;
			}
		}
		else
		if (cmp > 0)
		{
			if (!node->right)
			{
				node->right = new_node();
				node->right->data = calloc(BTREE_ALIGN_SIZE(data_len), 1);
				if (!node->right->data)
					return -1;

				memcpy(node->right->data, data, data_len);
				node->right->data_len = data_len;

				return 0;
			}
			else
			{
				node = node->right;
				continue;
			}
		}
		else // data already in tree
		{
			return 0;
		}
	}
}

btree_node_t *
BTREE_search_data(btree_obj_t *btree_obj, void *data, size_t data_len)
{
	assert(btree_obj);
	assert(data);

	btree_node_t *node = btree_obj->root;
	int cmp;

	while (1)
	{
		if (!node)
			break;

		cmp = memcmp(data, node->data, data_len);

		if (!cmp)
		{
			return node;
		}
		else
		if (cmp < 0)
		{
			node = node->left;
			continue;
		}
		else
		if (cmp > 0)
		{
			node = node->right;
			continue;
		}
	}

	return NULL;
}

btree_obj_t *
BTREE_object_new(void)
{
	btree_obj_t *btree_obj = NULL;

	btree_obj = malloc(sizeof(btree_obj_t));
	if (!btree_obj)
		return NULL;

	memset(btree_obj, 0, sizeof(*btree_obj));

	return btree_obj;
}

void
BTREE_object_destroy(btree_obj_t *btree_obj)
{
	assert(btree_obj);

	free_nodes(btree_obj->root);
	free(btree_obj);

	return;
}
