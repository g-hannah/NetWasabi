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

	p = savep = buf->buf_head;

	while (p < tail && (p = strstr(savep, " href")))
	{
		if (!p)
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

		if ((p - savep) >= HTTP_URL_MAX || (p - savep) < 5)
			continue;
		else
		if (!memchr(savep, '/', (p - savep)))
			continue;

		if (!(hl = (http_link_t *)wr_cache_alloc(cachep)))
			return -1;

		if (*savep == '/')
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
			strncpy(hl->url, savep, (p - savep));
			hl->url[p - savep] = 0;
			hl->time_reaped = time(NULL);
		}

		savep = p;
	}

	return 0;
}
