#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "cache.h"
#include "http.h"

int
http_parse_links(wr_cache_t *cachep, buf_t *buf)
{
	assert(cachep);
	assert(buf);

	http_link_t		*hl = NULL;
	char					*p = buf->head;
	char					*savep = NULL;
	char					*tail = buf->buf_tail;

	savep = p;

	while (p < tail && (p = strstr(savep, "href")))
	{
		savep = p;

		p = strstr(savep, "http");

		if (!p)
		{
			p = savep;
			continue;
		}

		savep = p;

		p = memchr(savep, '"', (tail - savep));

		if (!p)
		{
			p = savep;
			continue;
		}

		if ((p - savep) >= HTTP_MAX_URL)
			continue;

		if (!(hl = wr_cache_alloc(cachep)))
			return -1;

		strncpy(hl->url, savep, (p - savep));

		hl->url[p - savep] = 0;
		hl->time_reaped = time(NULL);
	}

	return 0;
}
