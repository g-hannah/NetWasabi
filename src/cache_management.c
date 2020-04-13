#include <assert.h>
#include "cache_management.h"
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

	dl->URL = calloc(HTTP_URL_MAX, 1);

	assert(dl->URL);

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
search_dead_URL(cache_t *cache, const char *URL)
{
	assert(cache);
	assert(URL);

	Dead_URL_t *dead = NULL;
	int i;
	int capacity = cache->capacity;
	size_t URL_len = strlen(URL);

	dead = (Dead_URL_t *)cache->cache;

	for (dead = (Dead_URL_t *)cache->cache, i = 0;
		i < capacity;
		++i, ++dead)
	{
		if (!cache_obj_used(cache, (void *)dead))
			continue;

		if (!memcmp((void *)dead->URL, (void *)URL, URL_len))
			return dead; 
	}

	return NULL;
}

static Dead_URL_t dummy_dead_URL;

void
cache_dead_URL(cache_t *cache, const char *URL, int code)
{
	assert(cache);
	assert(URL);

	Dead_URL_t *dead = cache_alloc(cache, &dummy_dead_URL);
	if (!dead)
		return;

	memcpy((void *)dead->URL, (void *)URL, strlen(URL));
	dead->code = code;
	dead->timestamp = time(NULL);
	dead->times_seen = 1;

	dead = NULL;
	return;
}

int
URL_cache_ctor(void *urlObj)
{
	assert(urlObj);

	URL_t *url = (URL_t *)urlObj;
	clear_struct(url);

	url->URL = calloc(HTTP_URL_MAX+1, 1);

	if (!url->URL)
		return -1;

	memset(url->URL, 0, HTTP_URL_MAX+1);

	url->left = NULL;
	url->right = NULL;

	return 0;
}

void
URL_cache_dtor(void *urlObj)
{
	assert(urlObj);

	URL_t *url = (URL_t *)urlObj;

	if (url->URL)
	{
		free(url->URL);
		url->URL = NULL;
	}

	clear_struct(url);
	return;
}
