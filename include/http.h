#ifndef HTTP_H
#define HTTP_H 1

#include <stdint.h>
#include <time.h>
#include "buffer.h"
#include "cache.h"
#include "connection.h"

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

/* Hypertext Transmission Protocol Verbs */
#define HTTP_GET		"GET"
#define HTTP_HEAD		"HEAD"

#define HTTP_EOH_SENTINEL "\r\n\r\n"

#define HTTP_DEFAULT_READ_BUF_SIZE	32768
#define HTTP_DEFAULT_WRITE_BUF_SIZE	4096

#define HTTP_PORT_NR	80
#define HTTPS_PORT_NR 443

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

int http_build_request_header(connection_t *, const char *, const char *) __nonnull((1,2,3)) __wur;
int http_send_request(connection_t *) __nonnull((1)) __wur;
int http_recv_response(connection_t *) __nonnull((1)) __wur;
int http_append_header(buf_t *, const char *) __nonnull((1,2)) __wur;
int http_status_code_int(buf_t *) __nonnull((1)) __wur;
const char *http_status_code_string(int) __wur;
char *http_get_header(buf_t *, const char *) __nonnull((1,2)) __wur;
char *http_parse_host(char *, char *) __nonnull((1,2)) __wur;
char *http_parse_page(char *, char *) __nonnull((1,2)) __wur;
int http_parse_links(wr_cache_t *, buf_t *) __nonnull((1,2)) __wur;
int wr_cache_http_link_ctor(void *) __nonnull((1)) __wur;
void wr_cache_http_link_dtor(void *) __nonnull((1));

#endif /* !defined HTTP_H */
