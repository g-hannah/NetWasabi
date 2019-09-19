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

static char **url_links = NULL;

#if 0
static char *__ignore_tokens__[] =
{
	"favicon.ico",
	".png",
	".jpg",
	".jpeg",
	".gif",
	".pdf",
	//".php",
	NULL
};
#endif

int
parse_links(wr_cache_t *cachep, connection_t *conn, char *host)
{
	assert(cachep);
	assert(conn);

	http_link_t		*hl = NULL;
	char					*p = NULL;
	char					*savep = NULL;
	char					*tail;
	int nr_urls = 0;
	int nr_already = 0;
	size_t url_len = 0;
	size_t cur_size = DEFAULT_MATRIX_SIZE;
	size_t href_len = strlen("href=\"");
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

		p = strstr(savep, "href=\"");

		if (!p || p >= tail)
			break;

		savep = (p += href_len);
		p = memchr(savep, '"', (tail - savep));

		if (!p)
			break;

		url_len = (p - savep);

		if (url_len >= HTTP_URL_MAX || url_len < 5)
		{
			savep = ++p;
			continue;
		}

		MATRIX_CHECK_CAPACITY(url_links, aidx, cur_size, HTTP_URL_MAX, char);

		assert(url_len < HTTP_URL_MAX);
		assert(aidx < cur_size);

	/*
	 * Ignore URLs that refer to part of their own page
	 * and URLs that have parameters (page.php?id=1234).
	 */
		if (memchr(savep, '#', url_len) || memchr(savep, '?', url_len))
		{
			savep = ++p;
			continue;
		}

		buf_append_ex(&url, savep, url_len);
		make_full_url(conn, &url, &full_url);

		if (is_xdomain(conn, &full_url))
		{
			if (!option_set(OPT_ALLOW_XDOMAIN))
			{
				savep = ++p;
				continue;
			}
		}

		BUF_NULL_TERMINATE(&url);

		strncpy(url_links[aidx], full_url.buf_head, full_url.data_len);
		url_links[aidx][full_url.data_len] = 0;

		if (local_archive_exists(url_links[aidx]))
		{
			savep = ++p;
			++nr_already;
			continue;
		}

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

#ifdef DEBUG
	fprintf(stderr,
		"Parsed %d urls\n"
		"(Removed %d duplicates)\n"
		"(Ignored %d already archived)\n",
		nr_urls,
		removed,
		nr_already);
#endif

	for (i = 0; i < nr_urls; ++i)
	{
		hl = (http_link_t *)wr_cache_alloc(cachep);

		assert(hl);
		assert(hl->url);
		assert(wr_cache_obj_used(cachep, (void *)hl));

		if (!hl)
			goto fail_free_links;

		url_len = strlen(url_links[i]);
		assert(url_len < HTTP_URL_MAX);
		strncpy(hl->url, url_links[i], url_len);
		hl->url[url_len] = 0;
		hl->nr_requests = 0;
	}

	assert(nr_urls == wr_cache_nr_used(cachep));

	MATRIX_DESTROY(url_links, cur_size);

	return 0;


	fail_free_links:

	MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
