#ifndef HTTP_H
#define HTTP_H 1

#include <openssl/ssl.h>
#include <stdint.h>
#include <time.h>
#include "buffer.h"
#include "cache.h"
#include "hash_bucket.h"

#define HTTP_SWITCHING_PROTOCOLS 101u // for successful upgrade to HTTP 2.0
#define HTTP_OK 200u
#define HTTP_MOVED_PERMANENTLY 301u
#define HTTP_FOUND 302u // the URI is being temporarily redirected
#define HTTP_SEE_OTHER 303u
#define HTTP_BAD_REQUEST 400u // the user agent sent a malformed request
#define HTTP_UNAUTHORISED 401u
#define HTTP_PAYMENT_REQUIRED 402u
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

#define HTTP_OPERATION_TIMEOUT -2

#define HTTP_URL_MAX 768
#define HTTP_COOKIE_MAX 2048 /* Surely this is more than enough */
#define HTTP_HNAME_MAX 64 /* Header name */
#define HTTP_HOST_MAX 256
#define HTTP_HEADER_FIELD_MAX_LENGTH 2048

#define HTTP_VERSION		"1.1"
#define HTTP_USER_AGENT		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0"
#define HTTP_ACCEPT		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
#define HTTP_EOH_SENTINEL	"\r\n\r\n"
#define HTTP_EOL		"\r\n"

#define HTTP_DEFAULT_READ_BUF_SIZE	32768
#define HTTP_DEFAULT_WRITE_BUF_SIZE	4096

#define HTTP_PORT	80
#define HTTPS_PORT	443

#define HTTP_EOH(BUF) \
({\
	char *___p_t_r = NULL; \
	___p_t_r = strstr((BUF)->buf_head, HTTP_EOH_SENTINEL); \
	if (NULL != ___p_t_r) \
		___p_t_r += strlen(HTTP_EOH_SENTINEL); \
	___p_t_r; \
})

#define HTTP_ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

/*
 * Allow callers to register callbacks, for example
 * to be called on certain HTTP codes and whatnot.
 */
//typedef void *(*HTTP_callback_t)(struct http_t *, void *);

typedef struct HTTP_Header
{
	char *name;
	char *value;
	size_t nlen; /* Length of data for name */
	size_t vlen; /* Length of data for value */
	size_t nsize; /* Amount of memory allocated for name */
	size_t vsize; /* Amount of memory allocated for value */
} http_header_t;

#define http_socket(h) ((h)->conn.sock)
#define http_tls(h) ((h)->conn.ssl)
#define http_rbuf(h) ((h)->conn.read_buf)
#define http_wbuf(h) ((h)->conn.write_buf)

struct conn
{
	int sock;
	SSL *ssl;
	buf_t read_buf;
	buf_t write_buf;
	int sock_nonblocking;
	int ssl_nonblocking;
	char *host_ipv4;
	SSL_CTX *ssl_ctx;
};

enum request
{
	HEAD = 0,
	GET = 1
};

struct http_t
{
	uint32_t version;
	enum request verb;
	struct conn conn;
	int code;
	int followRedirects;
	int usingSecure;

	uint32_t id;

	char *host;
	char *page;
	char *URL;
	char *primary_host;

	size_t URL_len;

	struct HTTP_methods *ops;
};

struct HTTP_methods
{
	int (*send_request)(struct http_t *);
	int (*recv_response)(struct http_t *);
	int (*build_header)(struct http_t *);
	int (*append_header)(struct http_t *, char *, char *);
	char *(*fetch_header)(struct http_t *, char *);
	char *(*URL_parse_host)(char *, char *);
	char *(*URL_parse_page)(char *, char *);
	const char *(*code_as_string)(struct http_t *);
};

size_t httplen;
size_t httpslen;

struct http_t *HTTP_new(uint32_t) __wur;
void HTTP_delete(struct http_t *) __nonnull((1));

void http_check_host(struct http_t *) __nonnull((1));

/*
 * Connection-related functions
 */
int http_connect(struct http_t *) __nonnull((1)) __wur;
void http_disconnect(struct http_t *) __nonnull((1));
int http_reconnect(struct http_t *) __nonnull((1)) __wur;
int HTTP_upgrade_to_TLS(struct http_t *) __nonnull((1)) __wur;

#endif /* !defined HTTP_H */
