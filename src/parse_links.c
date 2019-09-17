#include <assert.h>
#include <errno.h>
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

#define MATRIX_CHECK_CAPACITY(PTR, CUR_IDX, NUM, SIZE, TYPE)\
do {\
	size_t ____i;\
	size_t ____old_size;\
	if ((PTR))\
	{\
		if ((CUR_IDX) >= (NUM))\
		{\
			____old_size = (NUM);\
			(NUM) *= 2;\
			(PTR) = realloc((PTR), ((NUM) * sizeof(TYPE *)));\
			fprintf(stderr,\
				"num=%lu\n"\
				"old_size=%lu\n",\
				(NUM),\
				____old_size);\
			for (____i = ____old_size; ____i < (NUM); ++____i)\
			{\
				(PTR)[____i] = NULL;\
				(PTR)[____i] = calloc((SIZE), sizeof(TYPE));\
			}\
		}\
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

static char *__ignore_tokens__[] =
{
	"favicon.ico",
	".png",
	".jpg",
	".jpeg",
	".gif",
	".pdf",
	".php",
	NULL
};

static int
__local_archive_exists(char *link, char *host)
{
	buf_t tmp;
	int path_max = 0;
	int exists = 0;
	char *home;

	path_max = pathconf("/", _PC_PATH_MAX);
	if (path_max == 0)
		path_max = 1024;

	buf_init(&tmp, path_max);

	home = getenv("HOME");

	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR "/");
	buf_append(&tmp, host);
	buf_append(&tmp, link);
	buf_append(&tmp, ".html");

#ifdef DEBUG
	printf("CHECKING LOCAL PATH %s\n", tmp.buf_head);
#endif

	exists = access(tmp.buf_head, F_OK);

	buf_destroy(&tmp);

	if (exists == 0)
		return 1;
	else
		return 0;
}

#define DEFAULT_MATRIX_SIZE 256

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
	size_t cur_size = DEFAULT_MATRIX_SIZE;
	int aidx = 0;
	int i;
	int ignore = 0;

	MATRIX_INIT(url_links, cur_size, max_len, char);

	savep = buf->buf_head;

	while (1)
	{
		ignore = 0;

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

		MATRIX_CHECK_CAPACITY(url_links, aidx, cur_size, HTTP_URL_MAX, char);

		assert(url_len < max_len);
		assert(aidx < cur_size);
		strncpy(url_links[aidx], savep, url_len);
		url_links[aidx][url_len] = 0;

		for (i = 0; __ignore_tokens__[i] != NULL; ++i)
		{
			if (strstr(url_links[aidx], __ignore_tokens__[i]))
			{
				savep = ++p;
				ignore = 1;
				break;
			}
		}

		if (ignore)
			continue;

		if (strstr(url_links[aidx], host))
		{
			savep = ++p;
			continue;
		}

		if (__local_archive_exists(url_links[aidx], host))
		{
			savep = ++p;
			continue;
		}

		savep = ++p;
		++aidx;
		++nr;
	}

	int removed;

	removed = __remove_dups(url_links, nr);

	nr -= removed;

	assert(nr < cur_size);
	fprintf(stderr, "parsed %d links\n", nr);

	for (i = 0; i < nr; ++i)
	{
		hl = (http_link_t *)wr_cache_alloc(cachep);

		assert(hl);
		assert(hl->url);
		assert(wr_cache_obj_used(cachep, (void *)hl));

		fprintf(stderr, "allocated obj #%d\n", (i+1));

		if (!hl)
			goto out_free_links;

		url_len = strlen(url_links[i]);
		assert(url_len < max_len);
		strncpy(hl->url, url_links[i], url_len);
		hl->url[url_len] = 0;
		hl->nr_requests = 0;
	}

	MATRIX_DESTROY(url_links, cur_size);

	return 0;


	out_free_links:

	MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
