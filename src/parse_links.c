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

#if 0
static int
__remove_dups(char **links, const int nr)
{
	int i;
	int j;
	int k;
	int nr_removed = 0;
	size_t len;
	size_t copy_len;

	for (i = 0; i < (nr-1); ++i)
	{
		len = strlen(links[i]);

		for (j = (nr - 1); j > i; --j)
		{
			if (len && !strcmp(links[i], links[j]))
			{
				++nr_removed;

				for (k = j; k < (nr - 1); ++k)
				{
					copy_len = strlen(links[k+1]);
					memcpy(links[k], links[k+1], copy_len);
					//strncpy(links[k], links[k+1], copy_len);
					links[k][copy_len] = 0;
				}

				memset(links[k], 0, HTTP_URL_MAX);
			}
		}
	}

	return nr_removed;
}
#endif

static int nr_already = 0;
static int nr_sibling = 0;
static int nr_dups = 0;

static int
__url_acceptable(connection_t *conn, wr_cache_t *e_cache, wr_cache_t *f_cache, buf_t *url)
{
	assert(conn);
	assert(url);

	char *tail = url->buf_tail;

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

#if 0
	link = (http_link_t *)e_cache->cache;
	nr_urls = wr_cache_nr_used(e_cache);
	for (i = 0; i < nr_urls; ++i)
	{
		while (!wr_cache_obj_used(e_cache, (void *)link))
			++link;

		if (!strcmp(link->url, url->buf_head))
			return 0;
	}
#endif

	return 1;
}

//static char **url_links = NULL;

#if 0
static int
__do_insert(wr_cache_t *cachep, http_link_t **root, buf_t *url)
{
	int cmp = strcmp(url->buf_head, (*root)->url);

	assert(*root);

	if (!url->buf_head[0])
	{
		fprintf(stderr, "__do_insert: empty url (%s)\n", url->buf_head);
		return 0;
	}

	if ((*root)->url[0] && url->buf_head[0] && !cmp)
	{
		fprintf(stderr, "did not insert duplicate node\n");
		++nr_dups;
		return 0;
	}
	else
	if (cmp < 0)
	{
		if (!(*root)->left)
		{
			(*root)->left = (http_link_t *)wr_cache_alloc(cachep, &(*root)->left);
			if (!(*root)->left)
				return -1;

			strncpy((*root)->left->url, url->buf_head, url->data_len);
			(*root)->left->url[url->data_len] = 0;

			fprintf(stderr, "inserted new URL node to the left @ %p\n", (*root)->left);

			return 0;
		}

		return (__do_insert(cachep, &(*root)->left, url));
	}
	else
	{
		if (!(*root)->right)
		{
			(*root)->right = (http_link_t *)wr_cache_alloc(cachep, &(*root)->right);
			if (!(*root)->right)
				return -1;

			strncpy((*root)->right->url, url->buf_head, url->data_len);
			(*root)->right->url[url->data_len] = 0;

			fprintf(stderr, "inserted new URL node to the right @ %p\n", (*root)->right);

			return 0;
		}

		return __do_insert(cachep, &(*root)->right, url);
	}

	return 0;
}
#endif

static int
__insert_link(wr_cache_t *cachep, http_link_t **root, buf_t *url)
{
	assert(cachep);
	assert(url);

	if (!(*root))
	{
		*root = (http_link_t *)wr_cache_alloc(cachep, root);
		assert(*root);
		assert(wr_cache_obj_used(cachep, (void *)*root));

		strncpy((*root)->url, url->buf_head, url->data_len);
		(*root)->url[url->data_len] = 0;

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
		cmp = strcmp(nptr->url, url->buf_head);

		if (nptr->url[0] && !cmp)
		{
			++nr_dups;
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
				strncpy(nptr->url, url->buf_head, url->data_len);
				nptr->url[url->data_len] = 0;
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
				assert(nptr->url);
				strncpy(nptr->url, url->buf_head, url->data_len);
				nptr->url[url->data_len] = 0;
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
parse_links(wr_cache_t *e_cache, wr_cache_t *f_cache, http_link_t *tree_root, connection_t *conn)
{
	assert(e_cache);
	assert(f_cache);
	assert(conn);

	char					*p = NULL;
	char					*savep = NULL;
	char					*tail;
	char delim;
	int url_type_idx = 0;
	int nr_urls = 0;
	size_t url_len = 0;
	//size_t cur_size = DEFAULT_MATRIX_SIZE;
	//int aidx = 0;
	//int i;
	buf_t *buf = &conn->read_buf;
	buf_t url;
	buf_t full_url;
	buf_t path;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&full_url, HTTP_URL_MAX);
	buf_init(&path, path_max);

	//MATRIX_INIT(url_links, cur_size, HTTP_URL_MAX, char);

	tail = buf->buf_tail;
	savep = buf->buf_head;

	nr_already = 0;
	nr_sibling = 0;
	nr_dups = 0;

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

		if (url_len >= HTTP_URL_MAX)
		{
			savep = ++p;
			continue;
		}

		assert(url_len < HTTP_URL_MAX);
		//assert(aidx <= cur_size);

		buf_append_ex(&url, savep, url_len);
		make_full_url(conn, &url, &full_url);

		if (!__url_acceptable(conn, e_cache, f_cache, &full_url))
		{
			savep = ++p;
			continue;
		}

		if (__insert_link(e_cache, &tree_root, &full_url) < 0)
			goto fail_destroy_bufs;

#if 0
		MATRIX_CHECK_CAPACITY(url_links, aidx, cur_size, HTTP_URL_MAX, char);
		strncpy(url_links[aidx], full_url.buf_head, full_url.data_len);
		url_links[aidx][full_url.data_len] = 0;
#endif

		savep = ++p;
		//++aidx;
		++nr_urls;
	}

	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);

#if 0
	int removed;
	removed = __remove_dups(url_links, (const int)nr_urls);
	nr_urls -= removed;

	assert(nr_urls <= cur_size);
#endif

	fprintf(stdout, "%s%sParsed %d more URLs (removed: %d dups, %d already archived, %d twins)%s\n",
		COL_LIGHTRED, ACTION_DONE_STR, nr_urls, nr_dups, nr_already, nr_sibling, COL_END);

#if 0
	for (i = 0; i < nr_urls; ++i)
	{
#ifdef DEBUG
		fprintf(stderr, "allocating link obj in HL_LOOP @ %p\n", hl_loop);
#endif

		url_len = strlen(url_links[i]);
		if (url_len >= HTTP_URL_MAX)
			fprintf(stderr, "%s\n", url_links[i]);
		assert(url_len < HTTP_URL_MAX);
		strncpy((*hl_loop)->url, url_links[i], url_len);
		(*hl_loop)->url[url_len] = 0;
		(*hl_loop)->nr_requests = 0;
	}
#endif

	//MATRIX_DESTROY(url_links, cur_size);

	return 0;


	//fail_free_links:

	fail_destroy_bufs:
	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);
	//MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
