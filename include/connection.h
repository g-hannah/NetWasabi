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
	SSL_CTX *ssl_ctx;
} connection_t;

int connection_using_tls(connection_t *) __nonnull((1)) __wur;
int connection_socket(connection_t *) __nonnull((1)) __wur;
SSL *connection_tls(connection_t *) __nonnull((1)) __wur;

#endif /* !defined CONNECTION_H */
