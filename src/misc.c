#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "misc.h"
#include "robots.h"
#include "utils_url.h"
#include "webreaper.h"

int
check_local_dirs(struct http_t *http, buf_t *filename)
{
	assert(http);
	assert(filename);

	char *p;
	char *e;
	char *end;
	char *name = filename->buf_head;
	buf_t _tmp;

	buf_init(&_tmp, pathconf("/", _PC_PATH_MAX));

	if (*(filename->buf_tail - 1) == '/')
		buf_snip(filename, 1);

	end = filename->buf_tail;
	p = strstr(name, WEBREAPER_DIR);

	if (!p)
	{
		put_error_msg("check_local_dirs: failed to find webreaper directory in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	e = ++p;

	e = memchr(p, '/', (end - p));

	if (!e)
	{
		put_error_msg("check_local_dirs: failed to find necessary '/' character in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	p = ++e;

/*
 * e.g. /home/johndoe/WR_Reaped/favourite-site.com/categories/best-rated
 *                              ^start here, work along to end, checking
 * creating a directory for each part if necessary.
 */

	while (e < end)
	{
		e = memchr(p, '/', (end - p));

		if (!e) /* The rest of the filename is the file itself */
		{
			break;
		}

		buf_append_ex(&_tmp, name, (e - name));
		BUF_NULL_TERMINATE(&_tmp);

		if(access(_tmp.buf_head, F_OK) != 0)
		{
			if (mkdir(_tmp.buf_head, S_IRWXU) < 0)
				put_error_msg("Failed to create directory: %s", strerror(errno));
		}

		p = ++e;
		buf_clear(&_tmp);
	}

	buf_destroy(&_tmp);
	return 0;
}

void
replace_with_local_urls(struct http_t *http, buf_t *buf)
{
	assert(http);
	assert(buf);

	char *tail = buf->buf_tail;
	char *p;
	char *savep;
	char *url_start;
	char *url_end;
	off_t url_start_off;
	off_t url_end_off;
	off_t savep_off;
	off_t poff;
	size_t range;
	buf_t url;
	buf_t path;
	buf_t full;
	int url_type_idx;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&path, HTTP_URL_MAX);
	buf_init(&full, HTTP_URL_MAX);

#define save_pointers()\
do {\
	savep_off = (savep - buf->buf_head);\
	poff = (savep - buf->buf_head);\
	url_start_off = (url_start - buf->buf_head);\
	url_end_off = (url_end - buf->buf_head);\
} while (0)

#define restore_pointers()\
do {\
	savep = (buf->buf_head + savep_off);\
	p = (buf->buf_head + poff);\
	url_start = (buf->buf_head + url_start_off);\
	url_end = (buf->buf_head + url_end_off);\
} while (0)

	savep = buf->buf_head;
	url_type_idx = 0;

	while (1)
	{
		buf_clear(&url);

		assert(buf->buf_tail <= buf->buf_end);
		assert(buf->buf_head >= buf->data);

		p = strstr(savep, url_types[url_type_idx].string);

		if (!p || p >= tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_start = (p += url_types[url_type_idx].len);
		url_end = memchr(url_start, url_types[url_type_idx].delim, (tail - url_start));

		if (!url_end)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		assert(buf->buf_tail <= buf->buf_end);
		assert(url_start < buf->buf_tail);
		assert(url_end < buf->buf_tail);
		assert(p < buf->buf_tail);
		assert(savep < buf->buf_tail);
		assert((tail - buf->buf_head) == (buf->buf_tail - buf->buf_head));

		range = (url_end - url_start);

		if (!range)
		{
			++savep;
			continue;
		}

		if (!strncmp("http://", url_start, range) || !strncmp("https://", url_start, range))
		{
			savep = ++url_end;
			continue;
		}

		if (range >= HTTP_URL_MAX)
		{
			savep = ++url_end;
			continue;
		}

		assert(range < HTTP_URL_MAX);

		buf_append_ex(&url, url_start, range);
		BUF_NULL_TERMINATE(&url);

		if (range)
		{
			//fprintf(stderr, "turning %s into full url\n", url.buf_head);
			make_full_url(http, &url, &full);
			//fprintf(stderr, "made %s\n", full.buf_head);

			if (make_local_url(http, &full, &path) == 0)
			{
				//fprintf(stderr, "made local url %s\n", path.buf_head);
				buf_collapse(buf, (off_t)(url_start - buf->buf_head), range);
				tail = buf->buf_tail;

				save_pointers();

				assert(path.data_len < path_max);
				buf_shift(buf, (off_t)(url_start - buf->buf_head), path.data_len);
				tail = buf->buf_tail;

				restore_pointers();

				assert((url_start - buf->buf_head) == url_start_off);
				assert((url_end - buf->buf_head) == url_end_off);
				assert((p - buf->buf_head) == poff);
				assert((savep - buf->buf_head) == savep_off);

				strncpy(url_start, path.buf_head, path.data_len);
			}
		}

		assert(buf_integrity(&url));
		assert(buf_integrity(&full));
		assert(buf_integrity(&path));

		//++savep;
		savep = ++url_end;

		if (savep >= tail)
			break;
	}
}

int
archive_page(struct http_t *http)
{
	int fd = -1;
	buf_t *buf = &http_rbuf(http);
	buf_t tmp;
	buf_t local_url;
	char *p;
	int rv;

	update_operation_status("Archiving %s", http->full_url);
	p = HTTP_EOH(buf);

	if (p)
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));

	if (__url_parseable(http->full_url))
		replace_with_local_urls(http, buf);

	buf_init(&tmp, HTTP_URL_MAX);
	buf_init(&local_url, 1024);

	buf_append(&tmp, http->full_url);
	make_local_url(http, &tmp, &local_url);

/* Now we have "file:///path/to/file.extension" */
	buf_collapse(&local_url, (off_t)0, strlen("file://"));

	rv = check_local_dirs(http, &local_url);

	if (rv < 0)
		goto fail_free_bufs;

	if (access(local_url.buf_head, F_OK) == 0)
	{
		//update_operation_status("Already archived local copy", 1);
		goto out_free_bufs;
	}

	fd = open(local_url.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd == -1)
	{
		put_error_msg("Failed to create local copy (%s)", strerror(errno));
		goto fail_free_bufs;
	}

	update_operation_status("Created %s", local_url.buf_head);
	++nr_reaped;

	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

	out_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return 0;

	fail_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return -1;
}

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

/**
 * __url_acceptable - determine if parsed URL is acceptable by searching for certain tokens
 *				and checking if the URL is already present in the DRAINING cache.
 *
 * @http: our HTTP object with remote host info
 * @fctx: the FILLING cache context with binary tree root
 * @dctx: the DRAINING cache contetx with binary tree root
 * @url: the parsed URL to check
 */
static int
__url_acceptable(struct http_t *http, struct cache_ctx *fctx, struct cache_ctx *dctx, buf_t *url)
{
	assert(http);
	assert(fctx);
	assert(dctx);
	assert(url);

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

	if (memchr(url->buf_head, '#', buf->buf_tail - url->buf_head))
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
	}

	wr_cache_unlock(dctx->cache);
	return 1;
}

/**
 * __insert_link - insert a URL into the current "filling" cache
 * @fctx: context holding cache pointer and binary tree root
 * @url: url to add to cache
 */
static int
__insert_link(struct cache_ctx *fctx, buf_t *url)
{
	assert(fctx);
	assert(url);

	if (!(fctx->root))
	{
		wr_cache_lock(fctx->cache);

		http_link_t *r = fctx->root;
		r = (http_link_t *)wr_cache_alloc(fctx->cache, &fctx->root);

		strncpy(r->url, url->buf_head, url->data_len);
		r->url[url->data_len] = 0;

		r->left = NULL;
		r->right = NULL;
		r->parent = NULL;

		wr_cache_unlock(fctx->cache);

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

	wr_cache_lock(fctx->cache);

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

	wr_cache_unlock(fctx->cache);

	return 0;
}

/**
 * parse_links - parse links from page and store in URL cache within fctx
 *			checking for duplicate URLs in URL cache within dctx.
 * @http: our HTTP object with remote host info
 * @fctx: context of cache we are filling
 * @dctx: context of cache within which we are checking for duplicates
 */
int
parse_links(struct http_t *http, struct cache_ctx *fctx, struct cache_ctx *dctx)
{
	assert(http);
	assert(fctx);
	assert(dctx);

	char *p = NULL;
	char *savep = NULL;
	char delim;
	int url_type_idx = 0;
	size_t url_len = 0;
	buf_t *buf = &http_rbuf(http);
	buf_t url;
	buf_t full_url;
	buf_t path;

	if (buf_init(&url, HTTP_URL_MAX) < 0)
		goto fail;

	if (buf_init(&full_url, HTTP_URL_MAX) < 0)
		goto fail_destroy_bufs;

	if (buf_init(&path, path_max) < 0)
		goto fail_destroy_bufs;

	savep = buf->buf_head;

	nr_already = 0;
	nr_twins = 0;
	nr_dups = 0;
	nr_urls_call = 0;

	while (1)
	{
		buf_clear(&url);
		buf_clear(&full_url);
		buf_clear(&path);

		p = strstr(savep, url_types[url_type_idx].string);
		delim = url_types[url_type_idx].delim;

		if (!p || p >= buf->buf_tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		savep = (p += url_types[url_type_idx].len);
		p = memchr(savep, delim, (buf->buf_tail - savep));

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
		make_full_url(http, &url, &full_url);

		if (!__url_acceptable(http, fctx->cache, dctx->cache, &full_url))
		{
			savep = ++p;
			continue;
		}

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
