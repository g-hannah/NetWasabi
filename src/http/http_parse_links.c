#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"

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

	savep = buf->buf_head;

	while (1)
	{
		p = strstr(savep, "href");

		if (!p || p >= tail)
			break;

		savep = p;

		p = memchr(savep, '"', (tail - savep));

		if (!p)
			break;

		++p;

		savep = p;

		p = memchr(savep, '"', (tail - savep));

		if (!p)
			break;

		url_len = (p - savep);

		if (url_len >= (HTTP_URL_MAX + strlen("https://")) || url_len < 5)
		{
			savep = p;
			continue;
		}

		if (!(hl = (http_link_t *)wr_cache_alloc(cachep)))
			return -1;

		if (strncmp("http", savep, 4))
		{
			buf_t full_url;

			buf_init(&full_url, HTTP_URL_MAX);

			if (strncmp("http", host, 4))
				buf_append(&full_url, option_set(OPT_USE_TLS) ? "https://" : "http://");

			buf_append(&full_url, host);

			buf_append_ex(&full_url, savep, (p - savep));

			strncpy(hl->url, full_url.buf_head, full_url.data_len);
			hl->url[full_url.data_len] = 0;
			hl->time_reaped = time(NULL);

			buf_destroy(&full_url);
		}
		else
		{
			strncpy(hl->url, savep, url_len);
			hl->url[url_len] = 0;
			hl->time_reaped = time(NULL);
		}

		savep = p;

		++nr;
	}

	printf("Done parsing links\n");
	return 0;
}
