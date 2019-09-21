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

static int nr_already = 0;

static int
__url_acceptable(connection_t *conn, buf_t *url)
{
	assert(conn);
	assert(url);

	char *tail = url->buf_tail;

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

	if (strstr(url->buf_head, "cgi-"))
		return 0;
	
	if (is_xdomain(conn, url))
	{
		if (!option_set(OPT_ALLOW_XDOMAIN))
			return 0;
	}

	return 1;
}

static char **url_links = NULL;

struct url_types
{
	char *string;
	char delim;
	size_t len;
};

struct url_types url_types[] =
{
	{ "href=\"", '"', 6 },
	{ "HREF=\"", '"', 6 },
	{ "src=\"", '"', 5 },
	{ "SRC=\"", '"', 5 },
	{ "href=\'", '\'', 6 },
	{ "HREF=\'", '\'', 6 },
	{ "src=\'", '\'', 5 },
	{ "SRC=\'", '\'', 5 },
	{ "", 0, 0 }
};

int
parse_links(wr_cache_t *cachep, connection_t *conn)
{
	assert(cachep);
	assert(conn);

	char					*p = NULL;
	char					*savep = NULL;
	char					*tail;
	char delim;
	int url_type_idx = 0;
	int nr_urls = 0;
	size_t url_len = 0;
	size_t cur_size = DEFAULT_MATRIX_SIZE;
	int aidx = 0;
	int i;
	buf_t *buf = &conn->read_buf;
	buf_t url;
	buf_t full_url;
	buf_t path;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&full_url, HTTP_URL_MAX);
	buf_init(&path, path_max);

	tail = buf->buf_tail;

	MATRIX_INIT(url_links, cur_size, HTTP_URL_MAX, char);

	savep = buf->buf_head;

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
		assert(aidx < cur_size);

		buf_append_ex(&url, savep, url_len);
		make_full_url(conn, &url, &full_url);

		if (!__url_acceptable(conn, &full_url))
		{
			savep = ++p;
			continue;
		}

		MATRIX_CHECK_CAPACITY(url_links, aidx, cur_size, HTTP_URL_MAX, char);
		strncpy(url_links[aidx], full_url.buf_head, full_url.data_len);
		url_links[aidx][full_url.data_len] = 0;

		savep = ++p;
		++aidx;
		++nr_urls;
	}

	buf_destroy(&url);
	buf_destroy(&full_url);
	buf_destroy(&path);

	int removed;

	removed = __remove_dups(url_links, (const int)nr_urls);
	nr_urls -= removed;

	assert(nr_urls < cur_size);

	fprintf(stdout, "%sParsed %d URLs (removed %d dups, %d already archived)\n",
		ACTION_DONE_STR, nr_urls, removed, nr_already);

	for (i = 0; i < nr_urls; ++i)
	{
#ifdef DEBUG
		fprintf(stderr, "allocating link obj in HL_LOOP @ %p\n", hl_loop);
#endif
		*hl_loop = (http_link_t *)wr_cache_alloc(cachep, hl_loop);

		assert(*hl_loop);

		if (!(*hl_loop))
			goto fail_free_links;

		url_len = strlen(url_links[i]);
		assert(url_len < HTTP_URL_MAX);
		strncpy((*hl_loop)->url, url_links[i], url_len);
		(*hl_loop)->url[url_len] = 0;
		(*hl_loop)->nr_requests = 0;
	}

	MATRIX_DESTROY(url_links, cur_size);

	return 0;


	fail_free_links:

	MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
