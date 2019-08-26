#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

	p = savep = buf->data;

	while (p < tail && (p = strstr(savep, "href")))
	{
		if (!p)
			break;

		savep = p;

		p = strstr(savep, "http");

		if (!p)
			break;

		savep = p;

		p = memchr(savep, '"', (tail - savep));

		if (!p)
			break;

		if ((p - savep) >= HTTP_URL_MAX)
			continue;

		if (!(hl = wr_cache_alloc(cachep)))
			return -1;

		hl->used = 1;

		strncpy(hl->url, savep, (p - savep));
		hl->url[p - savep] = 0;
		hl->time_reaped = time(NULL);

		savep = p;
	}

	return 0;
}
