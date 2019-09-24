#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "utils_url.h"
#include "webreaper.h"

static int nr_already = 0;
static int nr_sibling = 0;
static int nr_dups = 0;
static int nr_urls_call = 0;
static int nr_urls_total = 0;

static int
__url_acceptable(connection_t *conn, wr_cache_t *e_cache, wr_cache_t *f_cache, buf_t *url)
{
	assert(conn);
	assert(url);

	char *tail = url->buf_tail;

	if (url->data_len >= 256)
		return 0;

	if (!strncmp("http:", url->buf_head, 5)
	|| !strncmp("https:", url->buf_head, 6))
	{
		if (url->data_len < httplen || url->data_len < httpslen)
			return 0;
	}

	if (local_archive_exists(url->buf_head))
	{
		++nr_already;
		return 0;
	}

	if (memchr(url->buf_head, '#', tail - url->buf_head))
		return 0;

	if (strstr(url->buf_head, "javascript:"))
		return 0;

	if (strstr(url->buf_head, "data:image"))
		return 0;

	if (strstr(url->buf_head, ".exe"))
		return 0;

	if (strstr(url->buf_head, ".dll"))
		return 0;

	if (strstr(url->buf_head, "cgi-"))
		return 0;
	
	if (is_xdomain(conn, url))
	{
		if (!option_set(OPT_ALLOW_XDOMAIN))
			return 0;
	}

	int nr_urls = wr_cache_nr_used(f_cache);
	int i;
	http_link_t *link = (http_link_t *)f_cache->cache;

	for (i = 0; i < nr_urls; ++i)
	{
		while (!wr_cache_obj_used(f_cache, (void *)link))
			++link;

		if (!strcmp(link->url, url->buf_head))
		{
			++nr_sibling;
			return 0;
		}

		++link;
	}

	return 1;
}

#if 0
static unsigned long *visited_list;
static int visited_num = 0;

static int
__do_check(http_link_t *___root)
{
	int rv;

	if (___root->left)
		rv = __do_check(___root->left);

	if (rv < 0)
		return rv;

	if (___root->right)
		rv = __do_check(___root->right);

	if (rv < 0)
		return rv;

	int i;

	for (i = 0; i < visited_num; ++i)
	{
		if (visited_list[i] == (unsigned long)___root)
		{
			fprintf(stderr, "already visited node 0x%lx!!!\n", (unsigned long)___root);
			//assert(0);
		}
	}

	//fprintf(stderr, "visited_num=%d\n", visited_num);
	visited_list[visited_num++] = (unsigned long)___root;
	return 0;
}

static int
__check_tree_integrity(http_link_t *___root)
{
	int rv;

	visited_list = calloc(8192, sizeof(unsigned long));
	assert(visited_list);
	visited_num = 0;

	rv = __do_check(___root);

	free(visited_list);
	visited_list = NULL;

	return rv;
}
#endif

#if 0
static int rdepth = 0;

static void
__dump_tree(http_link_t *___root)
{
	if (!___root)
		return;

	/*
   * Check if the tree has turned into a graph. Compare ->left / ->right with ->parent. Make
	 * sure ->left / ->right not NULL otherwise the root node, before having any children
	 * would have ->left / ->right == NULL && ->parent == NULL.
	 */
	if ((___root->left && ___root->left  == ___root->parent) || (___root->right && ___root->right == ___root->parent))
	{
		fprintf(stderr, "Binary tree has turned into a graph...\n");

		http_link_t *nptr = ___root;
		while (nptr->parent != NULL)
		{
			nptr = nptr->parent;
			++rdepth;
			if (rdepth > 100)
			{
				fprintf(stderr, "Cannot find root node!!!\n");
				assert(0);
			}
		}

		wr_cache_t *cptr = container_of(nptr, wr_cache_t, cache);
		/* cptr = (wr_cache_t *)((char *)nptr - (size_t)((wr_cache_t *)0)->cache); */
		int nr_links = wr_cache_nr_used(cptr);
		int i;

		fprintf(stderr, "Cache is at %p (contains %d links)\n", cptr, nr_links);
		for (i = 0; i < nr_links; ++i)
		{
			fprintf(stderr,
				"#%d:\n\n"
				"   url = %s\n"
				"  left = %p\n"
				" right = %p\n"
				"parent = %p\n",
				i,
				nptr->url,
				nptr->left,
				nptr->right,
				nptr->parent);

				++nptr;
		}

		assert(0);
	}

	if (___root->left)
		__dump_tree(___root->left);

	if (___root->right)
		__dump_tree(___root->right);

	fprintf(stdout, "url == %s\n", ___root->url);

	return;
}
#endif

static int
__insert_link(wr_cache_t *cachep, http_link_t **root, buf_t *url)
{
	assert(cachep);
	assert(url);

	//int loops = 0;

	if (!(*root))
	{
		*root = (http_link_t *)wr_cache_alloc(cachep, root);
		assert(*root);
		assert(wr_cache_obj_used(cachep, (void *)*root));

		strncpy((*root)->url, url->buf_head, url->data_len);
		(*root)->url[url->data_len] = 0;

		(*root)->left = NULL;
		(*root)->right = NULL;
		(*root)->parent = NULL;

		//fprintf(stderr, "%d\n", wr_cache_nr_used(cachep));

		return 0;
	}

/*
 * Cannot use recursion to insert nodes because when the cache
 * is extended, all the addresses that active pointers hold are
 * patched, and any active pointers that reside in the cache
 * itself are also rightly patched. However, the numerous
 * stack frames due to recursion still hold old addresses from
 * the old cache location. We cannot patch them. So we need
 * to iteratively insert nodes into the tree.
 */

	http_link_t *nptr = *root;
	int cmp;
	off_t nptr_offset;
	void *nptr_stack = &nptr;
	http_link_t *new_addr;

	while (1)
	{
#if 0
		++loops;

		if (loops > 100)
		{
			fprintf(stderr, "loops > 100\n");
			__dump_tree(*root);
			assert(0);
		}
#endif

		cmp = strcmp(url->buf_head, nptr->url);
		//fprintf(stderr, "comparing %s with %s\n", url->buf_head, nptr->url);

		if (nptr->url[0] && !cmp)
		{
			++nr_dups;
			--nr_urls_call;
			break;
		}
		else
		if (cmp < 0)
		{
			if (!nptr->left)
			{
				nptr_offset = (off_t)((char *)nptr - (char *)cachep->cache);
				new_addr = (http_link_t *)wr_cache_alloc(cachep, &nptr->left);
				*((unsigned long *)nptr_stack) = (unsigned long)((char *)cachep->cache + nptr_offset);

				nptr->left = new_addr;

				assert(((char *)nptr - (char *)cachep->cache) < cachep->cache_size);
				assert(nptr->left);
				strncpy(nptr->left->url, url->buf_head, url->data_len);
				nptr->left->url[url->data_len] = 0;
				nptr->left->parent = nptr;

				//fprintf(stderr, "copied %s to node @ %p (%d)\n", url->buf_head, nptr->left, wr_cache_nr_used(cachep));
				break;
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
				nptr_offset = (off_t)((char *)nptr - (char *)cachep->cache);
				new_addr = wr_cache_alloc(cachep, &nptr->right);
				*((unsigned long *)nptr_stack) = (unsigned long)((char *)cachep->cache + nptr_offset);
				assert(((char *)nptr - (char *)cachep->cache) < cachep->cache_size);

				nptr->right = new_addr;

				assert(nptr->right);
				strncpy(nptr->right->url, url->buf_head, url->data_len);
				nptr->right->url[url->data_len] = 0;
				nptr->right->parent = nptr;

				//fprintf(stderr, "copied %s to node @ %p (%d)\n", url->buf_head, nptr->right, wr_cache_nr_used(cachep));
				break;
			}
			else
			{
				nptr = nptr->right;
				continue;
			}
		}
	}

	return 0;
}

int
parse_links(wr_cache_t *e_cache, wr_cache_t *f_cache, http_link_t **tree_root, connection_t *conn)
{
	assert(e_cache);
	assert(f_cache);
	assert(conn);

	char					*p = NULL;
	char					*savep = NULL;
	char					*tail;
	char delim;
	int url_type_idx = 0;
	size_t url_len = 0;
	buf_t *buf = &conn->read_buf;
	buf_t url;
	buf_t full_url;
	buf_t path;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&full_url, HTTP_URL_MAX);
	buf_init(&path, path_max);

	tail = buf->buf_tail;
	savep = buf->buf_head;

	nr_already = 0;
	nr_sibling = 0;
	nr_dups = 0;
	nr_urls_call = 0;
	nr_urls_total = wr_cache_nr_used(e_cache);

	while (1)
	{
		buf_clear(&url);
		buf_clear(&full_url);
		buf_clear(&path);

		p = strstr(savep, url_types[url_type_idx].string);
		delim = url_types[url_type_idx].delim;

		if (!p || p >= tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		savep = (p += url_types[url_type_idx].len);
		p = memchr(savep, delim, (tail - savep));

		if (!p)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_len = (p - savep);

		if (!url_len || url_len >= HTTP_URL_MAX)
		{
			savep = ++p;
			continue;
		}

		assert(url_len > 0);
		assert(url_len < HTTP_URL_MAX);

		buf_append_ex(&url, savep, url_len);
		make_full_url(conn, &url, &full_url);

		if (!__url_acceptable(conn, e_cache, f_cache, &full_url))
		{
			savep = ++p;
			continue;
		}

		//fprintf(stderr, "inserting URL %s to tree\n", full_url.buf_head);

		if (__insert_link(e_cache, tree_root, &full_url) < 0)
			goto fail_destroy_bufs;

		savep = ++p;
		++nr_urls_call;
	}

	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);

	fprintf(stdout, "%s%sParsed %d more URLs (removed: %d dups, %d already archived, %d twins; total in cache = %d)%s\n",
		COL_DARKRED, ACTION_DONE_STR, nr_urls_call, nr_dups, nr_already, nr_sibling, wr_cache_nr_used(e_cache), COL_END);

	return 0;

	fail_destroy_bufs:
	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);
	return -1;
}
