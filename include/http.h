#ifndef HTTP_H
#define HTTP_H 1

#include <openssl/ssl.h>
#include <stdint.h>
#include <time.h>
#include "buffer.h"
#include "cache.h"

#define HTTP_OK 200u
#define HTTP_MOVED_PERMANENTLY 301u
#define HTTP_FOUND 302u
#define HTTP_SEE_OTHER 303u
#define HTTP_BAD_REQUEST 400u
#define HTTP_UNAUTHORISED 401u
#define HTTP_FORBIDDEN 403u
#define HTTP_NOT_FOUND 404u
#define HTTP_METHOD_NOT_ALLOWED 405u
#define HTTP_REQUEST_TIMEOUT 408u
#define HTTP_GONE 410u
#define HTTP_INTERNAL_ERROR 500u
#define HTTP_BAD_GATEWAY 502u
#define HTTP_SERVICE_UNAV 503u
#define HTTP_GATEWAY_TIMEOUT 504u

/* Custom status codes */
#define HTTP_ALREADY_EXISTS 702u
#define HTTP_IS_XDOMAIN 703u

#define HTTP_URL_MAX 768
#define HTTP_COOKIE_MAX 2048 /* Surely this is more than enough */
#define HTTP_HNAME_MAX 64 /* Header name */
#define HTTP_HOST_MAX 256

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

#define HTTP_SKIP_HOST_PART(PTR, URL)\
do {\
	char *____s_p = NULL;\
	char *____e_p = NULL;\
	if (!strncmp("http", (URL), 4))\
	{\
		(PTR) = (URL) + strlen("http://");\
		if ((*PTR) == '/')\
			++(PTR);\
			____e_p = ((URL) + strlen((URL)));\
			____s_p = memchr((PTR), '/', (____e_p - (PTR)));\
			if (____s_p)\
				(PTR) = ____s_p;\
	}\
	else\
	{\
		(PTR) = (URL);\
	}\
} while (0)

#define HTTP_EOH(BUF)\
({\
	char *___p_t_r = strstr((BUF)->buf_head, HTTP_EOH_SENTINEL);\
	___p_t_r += strlen(HTTP_EOH_SENTINEL);\
	___p_t_r;\
})

typedef struct http_link_t
{
	char *url;
	int nr_requests;
	struct http_link_t *left;
	struct http_link_t *right;
	struct http_link_t *parent;
} http_link_t;

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

struct http_cookie_t
{
	char *data;
	char *domain;
	char *path;
	char *expires;
	size_t data_len;
	size_t domain_len;
	size_t path_len;
	size_t expires_len;
	time_t expires_ts;
};

#define http_socket(h) ((h)->conn.sock)
#define http_tls(h) ((h)->conn.ssl)
#define http_rbuf(h) ((h)->conn.read_buf)
#define http_wbuf(h) ((h)->conn.write_buf)

struct http_t
{
	char *host;
	char *page;
	char *full_url;
	char *primary_host;

	struct conn
	{
		int sock;
		SSL *ssl;
		buf_t read_buf;
		buf_t write_buf;
		char *host_ipv4;
		SSL_CTX *ssl_ctx;
	};
};

http_header_t **hh_loop;
http_link_t **hl_loop;
struct http_cookie_t **hc_loop;

http_link_t *cache1_url_root;
http_link_t *cache2_url_root;

wr_cache_t *http_hcache;
wr_cache_t *http_lcache;
wr_cache_t *http_lcache2;
size_t httplen;
size_t httpslen;

int http_build_request_header(struct http_t *, const char *http_verb) __nonnull((1,2)) __wur;
int http_send_request(struct http_t *) __nonnull((1)) __wur;
int http_recv_response(struct http_t *) __nonnull((1)) __wur;
int http_append_header(buf_t *, http_header_t *) __nonnull((1,2)) __wur;
int http_status_code_int(buf_t *) __nonnull((1)) __wur;
ssize_t http_response_header_len(buf_t *) __nonnull((1)) __wur;
const char *http_status_code_string(int) __wur;
int http_check_header(buf_t *, const char *, off_t, off_t *) __nonnull((1,2,4)) __wur;
char *http_fetch_header(buf_t *, const char *, http_header_t *, off_t) __nonnull((1,2,3)) __wur;
char *http_parse_host(char *, char *) __nonnull((1,2)) __wur;
char *http_parse_page(char *, char *) __nonnull((1,2)) __wur;
int parse_links(wr_cache_t *, wr_cache_t *, http_link_t **, connection_t *) __nonnull((1,2,3,4)) __wur;
int http_new_cookie_cache(void) __wur;
int http_link_cache_ctor(void *) __nonnull((1)) __wur;
void http_link_cache_dtor(void *) __nonnull((1));
int http_header_cache_ctor(void *) __nonnull((1)) __wur;
void http_header_cache_dtor(void *) __nonnull((1));
int http_cookie_cache_ctor(void *) __nonnull((1)) __wur;
void http_cookie_cache_dtor(void *) __nonnull((1));
int http_cookie_ctor(void *) __nonnull((1)) __wur;
void http_cookie_dtor(void *) __nonnull((1));

/*
 * Connection-related functions
 */
int http_connect(struct http_t *) __nonnull((1)) __wur;
void http_disconnect(struct http_t *) __nonnull((1));
int http_reconnect(struct http_t *) __nonnull((1)) __wur;
int http_switch_tls(struct http_t *) __nonnull((1)) __wur;

#endif /* !defined HTTP_H */
