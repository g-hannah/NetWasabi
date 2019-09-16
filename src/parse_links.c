#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "webreaper.h"

#define MATRIX_INIT(PTR, NUM, ALEN, TYPE) \
do {\
	int i;\
	(PTR) = calloc((NUM), sizeof(TYPE *));\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = (TYPE *)NULL;\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = calloc(ALEN+1, sizeof(TYPE));\
} while (0)

#define MATRIX_DESTROY(PTR, NUM) \
do { \
	int i;\
	if ((PTR))\
	{\
		for (i = 0; i < (NUM); ++i)\
		{\
			if ((PTR)[i])\
				free((PTR)[i]);\
		}\
		free((PTR));\
	}\
} while (0)
		

static int
__remove_dups(char **links, int nr)
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
					strncpy(links[k], links[k+1], copy_len);
					links[k][copy_len] = 0;
				}

				memset(links[k], 0, HTTP_URL_MAX);
			}
		}
	}

	return nr_removed;
}

static char **url_links = NULL;

int
parse_links(wr_cache_t *cachep, buf_t *buf, char *host)
{
	assert(cachep);
	assert(buf);

	http_link_t		*hl = NULL;
	char					*p = NULL;
	char					*savep = NULL;
	char					*tail = buf->buf_tail;
	int						nr = 0;
	size_t url_len = 0;
	size_t max_len = (HTTP_URL_MAX - strlen("https://"));
	size_t old_size = 0;
	size_t cur_size = 256;
	size_t aidx = 0;
	int i;

	MATRIX_INIT(url_links, cur_size, HTTP_URL_MAX, char);

	savep = buf->buf_head;

	while (1)
	{
		p = strstr(savep, "href=\"");

		if (!p || p >= tail)
			break;

		savep = p;

		p += strlen("href=\"");

		if (*p != '/')
		{
			savep = p;
			continue;
		}

		savep = p;

		p = memchr(savep, 0x22, (tail - savep));

		if (!p)
			break;

		if (memchr(savep, '?', (p - savep)))
		{
			savep = ++p;
			continue;
		}

		url_len = (p - savep);

		if (url_len >= max_len || url_len < 5)
		{
			savep = ++p;
			continue;
		}

		assert(url_len < HTTP_URL_MAX);
		strncpy(url_links[aidx], savep, url_len);
		url_links[aidx][url_len] = 0;

		printf("parsed url %s\n", url_links[aidx]);

		++aidx;

		if (aidx >= cur_size)
		{
			printf("extending url_links matrix\n");
			old_size = cur_size;
			cur_size *= 2;

			url_links = realloc(url_links, (cur_size * sizeof(char *)));

			if (!url_links)
				goto out_free_links;

			for (i = old_size; i < cur_size; ++i)
				url_links[i] = NULL;

			for (i = old_size; i < cur_size; ++i)
				url_links[i] = calloc(HTTP_URL_MAX, 1);
		}

		savep = ++p;

		++nr;
	}

	int removed;

	removed = __remove_dups(url_links, nr);

	nr -= removed;

	for (i = 0; i < nr; ++i)
	{
		printf("allocating link #%d\n", i);
		hl = (http_link_t *)wr_cache_alloc(cachep);

		if (!hl)
			goto out_free_links;

		url_len = strlen(url_links[i]);
		assert(url_len < HTTP_URL_MAX);
		strncpy(hl->url, url_links[i], url_len);
		hl->url[url_len] = 0;
	}

	MATRIX_DESTROY(url_links, cur_size);

	printf("Done parsing %d links\n", nr);
	return 0;

	out_free_links:

	MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
