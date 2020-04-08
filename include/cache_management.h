#ifndef __CACHE_MANAGEMENT_H__
#define __CACHE_MANAGEMENT_H__ 1

#include "cache.h"
#include "netwasabi.h"

int Dead_URL_cache_ctor(void *);
void Dead_URL_cache_dtor(void *);

int Redirected_URL_cache_ctor(void *);
void Redirected_URL_cache_dtor(void *);

int URL_cache_ctor(void *);
void URL_cache_dtor(void *);

Dead_URL_t *search_dead_URL(cache_t *, const char *);
void cache_dead_URL(cache_t *, const char *, int);

#endif /* !defined __CACHE_MANAGEMENT_H__ */
