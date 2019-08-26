#ifndef HTTP_H
#define HTTP_H 1

#include <stdint.h>
#include <time.h>
#include "cache.h"

#define HTTP_OK 200u
#define HTTP_MOVED_PERMANENTLY 301u
#define HTTP_FOUND 302u
#define HTTP_BAD_REQUEST 400u
#define HTTP_UNAUTHORISED 401u
#define HTTP_FORBIDDEN 403u
#define HTTP_NOT_FOUND 404u
#define HTTP_INTERNAL_ERROR 500u
#define HTTP_BAD_GATEWAY 502u
#define HTTP_SERVICE_UNAV 503u
#define HTTP_GATEWAY_TIMEOUT 504u

#define HTTP_URL_MAX	256

typedef struct http_link_t
{
	int http_status;
	char *url;
	time_t time_reaped;
	int used;
} http_link_t;

#define http_inc_cookies(h) (++(h)->nr_cookies)
#define http_dec_cookies(h) (--(h)->nr_cookies)
#define http_nr_cookies(h) ((h)->nr_cookies)
#define http_nr_links(h) ((h)->nr_links)
#define http_nr_requests(h) ((h)->nr_requests)

typedef struct http_state_t
{
	int nr_requests; /* total number page requests we've sent */
	int nr_links; /* total number links we've reaped */
	http_link_t *head;
	http_link_t *tail;
	char **http_cookies; /* cookies we must set in outgoing http headers */
	int nr_cookies; /* number cookies we have set */
	char *base_page; /* website specified by user */
} http_state_t;

int wr_cache_http_link_ctor(void *) __nonnull((1)) __wur;
void wr_cache_http_link_dtor(void *) __nonnull((1));

#endif /* !defined HTTP_H */
