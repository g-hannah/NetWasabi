#ifndef CONNECTION_H
#define CONNECTION_H 1

#include <openssl/ssl.h>
#include "buffer.h"

typedef struct connection_t
{
	int sock;
	SSL *ssl;
	buf_t read_buf;
	buf_t write_buf;
	char *host;
	char *page;
	char *full_url;
	char *primary_host;
	char *host_ipv4;
	SSL_CTX *ssl_ctx;
} connection_t;

void conn_init(connection_t *) __nonnull((1));
void conn_destroy(connection_t *) __nonnull((1));
int conn_using_tls(connection_t *) __nonnull((1)) __wur;
int conn_socket(connection_t *) __nonnull((1)) __wur;
SSL *conn_tls(connection_t *) __nonnull((1)) __wur;
int conn_switch_to_tls(connection_t *) __nonnull((1)) __wur;
int open_connection(connection_t *) __nonnull((1)) __wur;
void close_connection(connection_t *) __nonnull((1));
int reconnect(connection_t *) __nonnull((1)) __wur;

#endif /* !defined CONNECTION_H */
