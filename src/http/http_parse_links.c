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

	while (p < tail && (p = strstr(savep, "http")))
	{
		hl = wr_cache_alloc(cachep);
	}
}
