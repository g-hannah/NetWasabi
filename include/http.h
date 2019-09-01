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
#define HTTP_REQUEST_TIMEOUT 408u
#define HTTP_INTERNAL_ERROR 500u
#define HTTP_BAD_GATEWAY 502u
#define HTTP_SERVICE_UNAV 503u
#define HTTP_GATEWAY_TIMEOUT 504u

#define HTTP_URL_MAX	256
#define HTTP_COOKIE_MAX 256 /* Surely this is more than enough */
#define HTTP_HNAME_MAX 64 /* Header name */

#define HTTP_GET		"GET"
#define HTTP_HEAD		"HEAD"

#define HTTP_VERSION				"1.1"
#define HTTP_USER_AGENT			"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
#define HTTP_ACCEPT					"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
#define HTTP_EOH_SENTINEL		"\r\n\r\n"

#define HTTP_DEFAULT_READ_BUF_SIZE	32768
#define HTTP_DEFAULT_WRITE_BUF_SIZE	4096

#define HTTP_PORT_NR	80
#define HTTPS_PORT_NR 443



typedef struct http_link_t
{
	int status_code;
	char *url;
	time_t time_reaped;
	int used;
} http_link_t;

#define http_nr_cookies(h) ((h)->nr_cookies)
#define http_nr_links(h) ((h)->nr_links)
#define http_nr_requests(h) ((h)->nr_requests)

/*
 * TODO:
 * Implement RING linked list (like in Apache)
 */
typedef struct http_state_t
{
	int nr_requests; /* total number page requests we've sent */
	int nr_links; /* total number links we've reaped */
	http_link_t *head;
	char *base_page; /* website specified by user */
} http_state_t;

typedef struct http_header_t
{
	char *name;
	char *value;
	size_t nlen; /* Length of data for name */
	size_t vlen; /* Length of data for value */
	size_t nsize; /* Amount of memory allocated for name */
	size_t vsize; /* Amount of memory allocated for value */
} http_header_t;

int http_build_request_header(connection_t *, const char *, const char *) __nonnull((1,2,3)) __wur;
int http_send_request(connection_t *) __nonnull((1)) __wur;
int http_recv_response(connection_t *) __nonnull((1)) __wur;
int http_append_header(buf_t *, http_header_t *) __nonnull((1,2)) __wur;
int http_status_code_int(buf_t *) __nonnull((1)) __wur;
const char *http_status_code_string(int) __wur;
int http_check_header(buf_t *, const char *, off_t, off_t *) __nonnull((1,2,4)) __wur;
char *http_fetch_header(buf_t *, const char *, http_header_t *, off_t) __nonnull((1,2,3)) __wur;
char *http_parse_host(char *, char *) __nonnull((1,2)) __wur;
char *http_parse_page(char *, char *) __nonnull((1,2)) __wur;
int http_parse_links(wr_cache_t *, buf_t *) __nonnull((1,2)) __wur;
int wr_cache_http_link_ctor(void *) __nonnull((1)) __wur;
void wr_cache_http_link_dtor(void *) __nonnull((1));
int wr_cache_http_cookie_ctor(void *) __nonnull((1)) __wur;
void wr_cache_http_cookie_dtor(void *) __nonnull((1));

#endif /* !defined HTTP_H */
