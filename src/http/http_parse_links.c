#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"

int
http_parse_links(wr_cache_t *cachep, buf_t *buf)
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

		if (!(hl = (http_link_t *)wr_cache_alloc(cachep)))
			return -1;

		strncpy(hl->url, savep, (p - savep));
		hl->url[p - savep] = 0;
		hl->time_reaped = time(NULL);

		char *url = hl->url;

		if (!strcmp("#", url)
			|| !strcmp("/", url))
		{
			wr_cache_dealloc(cachep, hl);
			savep = p;
			continue;
		}

		savep = p;
	}

	return 0;
}
