#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "fast_mode.h"
#include "http.h"
#include "robots.h"
#include "utils_url.h"
#include "webreaper.h"

static int nr_already = 0;
static int nr_twins = 0;
static int nr_dups = 0;
static int nr_urls_call = 0;
static int nr_urls_total = 0;

static const char *const __disallowed_tokens[] =
{
	"javascript:",
	"data:image",
	".exe",
	".dll",
	"cgi-",
	(char *)NULL
};

static int
__url_acceptable(connection_t *conn, struct cache_ctx *fctx, struct cache_ctx *dctx, buf_t *url)
{
	assert(conn);
	assert(fctx);
	assert(dctx);
	assert(url);

	char *tail = url->buf_tail;
	static char tmp_page[HTTP_URL_MAX];
	int i;

	if (url->data_len >= 256)
		return 0;

	if (!strncmp("http:", url->buf_head, 5)
	|| !strncmp("https:", url->buf_head, 6))
	{
		if (url->data_len < httplen || url->data_len < httpslen)
			return 0;

#if 0
		if (got_token_graph(wrctx))
		{
			http_parse_page(url->buf_head, tmp_page);
			if (!robots_eval_url(allowed, forbidden, tmp_page))
			{
				return 0;
			}
		}
#endif
	}

	if (local_archive_exists(url->buf_head))
	{
		++nr_already;
		return 0;
	}

	if (memchr(url->buf_head, '#', tail - url->buf_head))
		return 0;

	for (i = 0; __disallowed_tokens[i] != NULL; ++i)
	{
		if (strstr(url->buf_head, __disallowed_tokens[i]))
			return 0;
	}
	
	if (is_xdomain(conn, url))
	{
		if (!option_set(OPT_ALLOW_XDOMAIN))
			return 0;
	}


/*
 * Check the current "draining" cache for duplicate URLs
 */
	if (dctx->cache)
	{
		wr_cache_lock(dctx->cache);

		int cmp = 0;
		http_link_t *nptr = dctx->root;

		while (nptr)
		{
			cmp = strcmp(url->buf_head, nptr->url);

			if (url->buf_head[0] && nptr->url[0] && !cmp)
			{
				++nr_twins;
				wr_cache_unlock(dctx->cache);
				return 0;
			}
			else
			if (cmp < 0)
			{
				nptr = nptr->left;
			}
			else
			{
				nptr = nptr->right;
			}

			if (!nptr)
				break;
		}

		wr_cache_unlock(dctx->cache);
	}

	return 1;
}

static int
__insert_link(struct cache_ctx *fctx, buf_t *url)
{
	assert(cachep);
	assert(url);

	//int loops = 0;

	if (!(fctx->root))
	{
		fctx->root = (http_link_t *)wr_cache_alloc(cachep, &fctx->root);

		strncpy(fctx->root->url, url->buf_head, url->data_len);
		fctx->root->url[url->data_len] = 0;

		fctx->root->left = NULL;
		fctx->root->right = NULL;
		fctx->root->parent = NULL;

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

	http_link_t *nptr = fctx->root;
	int cmp;
	off_t nptr_offset;
	void *nptr_stack = &nptr;
	http_link_t *new_addr;

	while (1)
	{
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
	nr_twins = 0;
	nr_dups = 0;
	nr_urls_call = 0;
	nr_urls_total = wr_cache_nr_used(e_cache);

	//update_operation_status("Parsing URLs...");

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

#if 0
	update_operation_status("Added %d URL%s (ignored %d dup%s, %d archived, %d twin%s)",
		nr_urls_call,
		nr_urls_call == 1 ? "" : "s",
		nr_dups,
		nr_dups == 1 ? "" : "s",
		nr_dups,
		nr_dups == 1 ? "" : "s");
#endif

	return 0;

	fail_destroy_bufs:
	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);
	return -1;
}

/**
 * parse_links_ex - parse links from page and store in URL cache within fctx
 *			checking for duplicate URLs in URL cache within dctx.
 * @fctx: context of cache we are filling
 * @dctx: context of cache within which we are checking for duplicates
 * @conn: the context of the connection to remote webserver
 */
int
parse_links_ex(struct cache_ctx *fctx, struct cache_ctx *dctx, connection_t *conn)
{
	assert(fctx);
	assert(dctx);
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
	nr_twins = 0;
	nr_dups = 0;
	nr_urls_call = 0;
	nr_urls_total = wr_cache_nr_used(fctx->cache);

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

		if (!__url_acceptable(conn, fctx->cache, dctx->cache, &full_url))
		{
			savep = ++p;
			continue;
		}

		//fprintf(stderr, "inserting URL %s to tree\n", full_url.buf_head);

		if (__insert_link(fctx->cache, &fctx->root, &full_url) < 0)
			goto fail_destroy_bufs;

		savep = ++p;
		++nr_urls_call;
	}

	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);

	return 0;

	fail_destroy_bufs:
	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);
	return -1;
}
