#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"

#define MATRIX_INIT(PTR, NUM, ALEN, TYPE) \
do {\
	int i;\
	(PTR) = calloc((NUM), sizeof(TYPE *));\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = (TYPE *)NULL;\
	for (i = 0; i < (NUM); ++i)\
		(PTR)[i] = calloc(ALEN, sizeof(TYPE));\
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
		

static void
__remove_dups(char **links, size_t *cur_size)
{
	int i;
	int j;
	size_t size = *cur_size;
	size_t len;

	for (i = 0; i < size; ++i)
	{
		for (j = (size - 1); j > i; --j)
		{
			len = strlen(links[i]);

			if (len && !strcmp(links[i], links[j]))
			{
				printf("removing dup %s\n", links[j]);
				memset(links[j], 0, HTTP_URL_MAX);
				--size;
			}
		}
	}

	*cur_size = size;

	return;
}

static char **url_links = NULL;

int
http_parse_links(wr_cache_t *cachep, buf_t *buf, char *host)
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
	size_t host_len = strlen(host);
	size_t old_size = 0;
	size_t cur_size = 256;
	size_t aidx = 0;
	buf_t url;
	int i;

	buf_init(&url, HTTP_URL_MAX);

	MATRIX_INIT(url_links, cur_size, HTTP_URL_MAX, char);

	savep = buf->buf_head;

	while (1)
	{
		buf_clear(&url);

		p = strstr(savep, "href=\"");

		if (!p || p >= tail)
			break;

		savep = p;

		p += strlen("href=\"");

		savep = p;

		p = memchr(savep, 0x22, (tail - savep));

		if (!p)
			break;

		url_len = (p - savep);

		if (url_len >= max_len || url_len < 5)
		{
			savep = ++p;
			continue;
		}

		buf_append_ex(&url, savep, url_len);
		printf("parsed url %s\n", url.buf_head);

		if (*(url.buf_head) == '/')
		{
			buf_shift(&url, (off_t)0, (strlen("http://") + host_len + 1));
			strncpy(url.buf_head, "http://", strlen("http://"));
			strncpy(url.buf_head + strlen("http://"), host, host_len);
			strncpy(url.buf_head + strlen("http://") + host_len, "/", 1);
		}

		BUF_NULL_TERMINATE(&url);

		strncpy(url_links[aidx], url.buf_head, url.data_len);
		url_links[aidx][url.data_len] = 0;

		++aidx;

		if (aidx >= cur_size)
		{
			old_size = cur_size;
			cur_size *= 2;

			url_links = realloc(url_links, cur_size);
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

	buf_destroy(&url);

	__remove_dups(url_links, &cur_size);

	for (i = 0; i < cur_size; ++i)
	{
		hl = (http_link_t *)wr_cache_alloc(cachep);
		if (!hl)
			goto out_free_links;

		url_len = strlen(url_links[i]);
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
