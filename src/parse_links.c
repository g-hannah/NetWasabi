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
	//".php",
	NULL
};

static int
__local_archive_exists(char *link, char *host)
{
	buf_t tmp;
	int path_max = 0;
	int exists = 0;
	char *home;
	static char ptmp[1024];

	path_max = pathconf("/", _PC_PATH_MAX);
	if (path_max == 0)
		path_max = 1024;

	buf_init(&tmp, path_max);

	home = getenv("HOME");

	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR "/");
	buf_append(&tmp, host);
	http_parse_page(link, ptmp);
	buf_append(&tmp, ptmp);

	//buf_append(&tmp, ".html");

	exists = access(tmp.buf_head, F_OK);

	buf_destroy(&tmp);

	if (exists == 0)
		return 1;
	else
		return 0;
}

#define DEFAULT_MATRIX_SIZE 256

int
parse_links(wr_cache_t *cachep, connection_t *conn, char *host)
{
	assert(cachep);
	assert(conn);

	http_link_t		*hl = NULL;
	char					*p = NULL;
	char					*savep = NULL;
	char					*tail;
	int						nr = 0;
	size_t url_len = 0;
	size_t max_len = (HTTP_URL_MAX - strlen("https://"));
	size_t cur_size = DEFAULT_MATRIX_SIZE;
	int aidx = 0;
	int i;
	int ignore = 0;
	buf_t *buf = &conn->read_buf;
	buf_t url;
	buf_t tmp;
	static char page_tmp[1024];
	static char host_tmp[1024];

	tail = buf->buf_tail;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&tmp, HTTP_URL_MAX);

	MATRIX_INIT(url_links, cur_size, max_len, char);

	savep = buf->buf_head;

	while (1)
	{
		ignore = 0;
		buf_clear(&url);
		buf_clear(&tmp);

		p = strstr(savep, "href=\"");

		if (!p || p >= tail)
			break;

		savep = (p += strlen("href=\""));

		p = memchr(savep, '?', (p - savep));

		if (!p)
			p = memchr(savep, '"', (tail - savep));

		if (!p)
			break;

		url_len = (p - savep);

		if (url_len >= max_len || url_len < 5)
		{
			savep = ++p;
			continue;
		}

		MATRIX_CHECK_CAPACITY(url_links, aidx, cur_size, HTTP_URL_MAX, char);

		assert(url_len < max_len);
		assert(aidx < cur_size);

	/*
	 * Different servers of same site (e.g., community.something... / blog.something)
	 * are coded in the page starting with 2 slashes. Handle this.
	 */
		if (!strncmp("//", savep, 2))
		{
			if (!option_set(OPT_ALLOW_XDOMAIN))
			{
				savep = ++p;
				continue;
			}

			savep += 2;
			url_len -= 2;
			p = memchr(savep, '/', url_len);
			if (!p)
				continue;

			url_len = (p - savep);

			if (option_set(OPT_USE_TLS))
				buf_append(&tmp, "https://");
			else
				buf_append(&tmp, "http://");

			buf_append_ex(&tmp, savep, url_len);
		}
		else
		{
			buf_append_ex(&tmp, savep, url_len);
		}

	/*
	 * Ignore URLs that refer
	 * to part of their own page.
	 */
		if (memchr(tmp.buf_head, '#', url_len))
		{
			savep = ++p;
			continue;
		}

		if (!strncmp(tmp.buf_head, "//", 2))
		{
			if (!option_set(OPT_ALLOW_XDOMAIN))
			{
				savep = ++p;
				continue;
			}
		}

		if (!strncmp("http", tmp.buf_head, 4))
		{
			if (!strncmp("https", tmp.buf_head, 5))
				buf_append(&url, "https://");
			else
				buf_append(&url, "http://");

			http_parse_host(tmp.buf_head, host_tmp);

			if (strcmp(host_tmp, conn->primary_host))
			{
				if (!option_set(OPT_ALLOW_XDOMAIN))
				{
					savep = ++p;
					continue;
				}
			}

			buf_append(&url, host_tmp);

			http_parse_page(tmp.buf_head, page_tmp);

			buf_append(&url, page_tmp);
		}
		else
		{
			if (option_set(OPT_USE_TLS))
				buf_append(&url, "https://");
			else
				buf_append(&url, "http://");

			buf_append(&url, conn->host);

		/*
		 * It's a link relative to the current page.
		 */
			if (*savep == '.' || *savep != '/')
			{
				if (*savep == '.')
				{
					savep += 2;
					url_len = (p - savep);
				}

				buf_append(&url, conn->page);

				if (*(url.buf_tail - 1) != '/')
					buf_append(&url, "/");

				buf_append_ex(&url, savep, url_len);
			}
			else
			{
				/* If we get here, *savep == '/' */
				buf_append_ex(&url, savep, url_len);
			}
		}

		BUF_NULL_TERMINATE(&url);

		fprintf(stderr,
			"in parse_links: parsed URL=%s\n",
			url.buf_head);

		strncpy(url_links[aidx], url.buf_head, url.data_len);
		url_links[aidx][url.data_len] = 0;

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

		if (__local_archive_exists(url_links[aidx], host))
		{
			savep = ++p;
			continue;
		}

		savep = ++p;
		++aidx;
		++nr;
	}

	buf_destroy(&url);

	int removed;

	removed = __remove_dups(url_links, nr);

	nr -= removed;

	assert(nr < cur_size);

	for (i = 0; i < nr; ++i)
	{
		hl = (http_link_t *)wr_cache_alloc(cachep);

		assert(hl);
		assert(hl->url);
		assert(wr_cache_obj_used(cachep, (void *)hl));

		if (!hl)
			goto out_free_links;

		url_len = strlen(url_links[i]);
		assert(url_len < max_len);
		strncpy(hl->url, url_links[i], url_len);
		hl->url[url_len] = 0;
		hl->nr_requests = 0;
	}

	assert(nr == wr_cache_nr_used(cachep));

	MATRIX_DESTROY(url_links, cur_size);

	return 0;


	out_free_links:

	MATRIX_DESTROY(url_links, cur_size);
	return -1;
}
