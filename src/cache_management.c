#include <assert.h>
#include "netwasabi.h"

/*
 * TODO	Change name of this file to general
 *	cache-related management functions.
 */

int
Redirected_URL_cache_ctor(void *rlObj)
{
	assert(rlObj);

	Redirected_URL_t *rl = (Redirected_URL_t *)rlObj;

	rl->fromURL = calloc(HTTP_URL_MAX, 1);
	rl->toURL = calloc(HTTP_URL_MAX, 1);

	if (!rl->fromURL || !rl->toURL)
		goto fail_dealloc;

	rl->when = 0;

	return 0;

fail_dealloc:

	if (NULL != rl->fromURL)
		free(rl->fromURL);
	if (NULL != rl->toURL)
		free(rl->toURL);

	return -1;
}

void
Redirected_URL_cache_dtor(void *rlObj)
{
	assert(rlObj);

	Redirected_URL_t *rl = (Redirected_URL_t *)rlObj;

	if (NULL != rl->fromURL)
		free(rl->fromURL);
	if (NULL != rl->toURL)
		free(rl->toURL);

	rl->when = 0;

	return;
}

int
Dead_URL_cache_ctor(void *dlObj)
{
	assert(dlObj);

	Dead_URL_t *dl = (Dead_URL_t *)dlObj;

	dl->URL = nw_calloc(HTTP_URL_MAX, 1);
	dl->code = 0;
	dl->timestamp = 0;
	dl->times_seen = 0;

	if (NULL == dl->URL)
		return -1;

	return 0;
}

/**
 * Destructor for dead linke cache objects.
 */
void
Dead_URL_cache_dtor(void *dlObj)
{
	assert(dlObj);

	Dead_URL_t *dl = (Dead_URL_t *)dlObj;

	if (NULL != dl->URL)
	{
		free(dl->URL);
		dl->URL = NULL;
	}

	dl->code = 0;
	dl->timestamp = 0;
	dl->times_seen = 0;

	return;
}

Dead_URL_t *
HTTP_search_dead_link(cache_t *cache, const char *URL)
{
	assert(private);

	Dead_URL_t *dead = NULL;
	int objUsed = 0;
	size_t URL_len = strlen(URL);

	dead = (Dead_URL_t *)cache->cache;

	while (1)
	{
		while ((objUsed = cache_obj_used(cache, (void *)dead)) != 0)
			++dead;

		if (objUsed < 0)
			break;

		if (!memcmp((void *)dead->URL, (void *)URL, URL_len))
			return dead; 
	}

	return NULL;
}

int
URL_cache_ctor(void *http_link)
{
	URL_t *hl = (URL_t *)http_link;
	clear_struct(hl);

	hl->URL = nw_calloc(HTTP_URL_MAX+1, 1);

	if (!hl->URL)
		return -1;

	memset(hl->URL, 0, HTTP_URL_MAX+1);

	hl->left = NULL;
	hl->right = NULL;

	return 0;
}

void
URL_cache_dtor(void *http_link)
{
	assert(http_link);

	URL_t *hl = (URL_t *)http_link;

	if (hl->URL)
	{
		free(hl->URL);
		hl->URL = NULL;
	}

	clear_struct(hl);
	return;
}
