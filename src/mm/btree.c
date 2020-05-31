#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "btree.h"

#define INC_NODES(b) ++((b)->nr_nodes)
#define DEC_NODES(b) --((b)->nr_nodes)
#define TREE_NR_NODES(b) ((b)->nr_nodes)

#ifdef DEBUG
# define BTREE_LOG_FILE "./btree_log.txt"
FILE *btree_logfp = NULL;
#endif

static void
Debug(char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);

	vfprintf(btree_logfp, fmt, args);
	fflush(btree_logfp);

	va_end(args);
#else
	(void)fmt;
#endif
}

static void
__attribute__((constructor)) BTREE_impl_init(void)
{
#ifdef DEBUG
	btree_logfp = fdopen(open(BTREE_LOG_FILE, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR), "r+");
	if (!btree_logfp)
		btree_logfp = stderr;
#endif

	return;
}

static void
__attribute__((destructor)) BTREE_impl_fini(void)
{
#ifdef DEBUG
	if (btree_logfp && btree_logfp != stderr)
		fclose(btree_logfp);
#endif

	return;
}

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

	Debug("Inserting data %s\n", (char *)data);

/*
 * This was missing before. Instant segfault.
 */
	if (!node)
	{
		node = new_node();

		node->data = calloc(BTREE_ALIGN_SIZE(data_len), 1);
		if (!node->data)
		{
			free(node);
			return -1;
		}

		memcpy(node->data, data, data_len);
		((char *)node->data)[data_len] = 0;
		node->data_len = data_len;

		btree_obj->root = node;

		INC_NODES(btree_obj);

		Debug("Placed data in root node\n");

		return 0;
	}

	while (1)
	{
		cmp = memcmp(data, node->data, data_len);

		if (cmp < 0)
		{
			if (!node->left)
			{
				Debug("Creating new node to the left of this node\n");

				node->left = new_node();
				node->left->data = calloc(BTREE_ALIGN_SIZE(data_len), 1);
				if (!node->left->data)
					return -1;

				memcpy(node->left->data, data, data_len);
				((char *)node->left->data)[data_len] = 0;
				node->left->data_len = data_len;

				break;
			}
			else
			{
				Debug("Going left\n");

				node = node->left;
				continue;
			}
		}
		else
		if (cmp > 0)
		{
			if (!node->right)
			{
				Debug("Creating new node to the right of this node\n");

				node->right = new_node();
				node->right->data = calloc(BTREE_ALIGN_SIZE(data_len), 1);
				if (!node->right->data)
					return -1;

				memcpy(node->right->data, data, data_len);
				((char *)node->right->data)[data_len] = 0;
				node->right->data_len = data_len;

				break;
			}
			else
			{
				Debug("Going right\n");

				node = node->right;
				continue;
			}
		}
		else // data already in tree
		{
			Debug("Data already in tree\n\n%s and %s match\n", (char *)data, (char *)node->data);
			return 0;
		}
	}

	INC_NODES(btree_obj);
	return 0;
}

btree_node_t *
BTREE_search_data(btree_obj_t *btree_obj, void *data, size_t data_len)
{
	assert(btree_obj);
	assert(data);

	if (!data_len)
		return NULL;

	int cmp;
	btree_node_t *node = btree_obj->root;

	Debug("Searching for data %s\n", (char *)data);

	while (1)
	{
		if (!node)
			break;

		Debug("Comparing with %s\n", (char *)node->data);

		cmp = memcmp(data, node->data, data_len);

		if (!cmp)
		{
			Debug("They match\n");

			return node;
		}
		else
		if (cmp < 0)
		{
			Debug("Going left\n");

			node = node->left;
		}
		else
		{
			Debug("Going right\n");

			node = node->right;
		}
	}

	Debug("No match\n");
	return NULL;
}

void
BTREE_remove_node(btree_obj_t *btree_obj, void *data, size_t data_len)
{
	return;
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
