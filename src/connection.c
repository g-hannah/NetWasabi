#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "connection.h"
#include "http.h"
#include "malloc.h"
#include "webreaper.h"

void
conn_init(connection_t *conn)
{
	assert(conn);

	clear_struct(conn);
	conn->host = wr_calloc(HTTP_URL_MAX+1, 1);

	return;
}

void
conn_destroy(connection_t *conn)
{
	assert(conn);

	free(conn->host);
	clear_struct(conn);

	return;
}

inline int conn_socket(connection_t *conn)
{
	return conn->sock;
}

inline SSL *conn_tls(connection_t *conn)
{
	return conn->ssl;
}

inline int conn_using_tls(connection_t *conn)
{
	return conn->using_tls;
}

/**
 * __init_openssl - initialise the openssl library
 */
static inline void
__init_openssl(void)
{
	SSL_library_init();
	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

/**
 * open_connection - set up a connection with the target site
 * @conn: &connection_t that is initialised in this function
 * @use_tls: 1 to use HTTPS; 0 to use HTTP
 */
int
open_connection(connection_t *conn, int use_tls)
{
	assert(conn);

	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

	buf_init(&conn->read_buf, HTTP_DEFAULT_READ_BUF_SIZE);
	buf_init(&conn->write_buf, HTTP_DEFAULT_WRITE_BUF_SIZE);
	clear_struct(&sock4);

	if (getaddrinfo(conn->host, NULL, NULL, &ainf) < 0)
	{
		fprintf(stderr, "open_connection: getaddrinfo error (%s)\n", gai_strerror(errno));
		goto fail;
	}

	for (aip = ainf; aip; aip = aip->ai_next)
	{
		if (aip->ai_family == AF_INET && aip->ai_socktype == SOCK_STREAM)
		{
			memcpy(&sock4, aip->ai_addr, aip->ai_addrlen);
			break;
		}
	}

	if (!aip)
		goto fail;

	sock4.sin_port = htons(HTTP_PORT_NR);

	if ((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "open_connection: connect error (%s)\n", strerror(errno));
		goto fail_release_ainf;
	}

	assert(conn->sock > 2);

	if (connect(conn->sock, (struct sockaddr *)&sock4, (socklen_t)sizeof(sock4)) != 0)
	{
		fprintf(stderr, "open_connection: connect error (%s)\n", strerror(errno));
		goto fail_release_ainf;
	}

	printf("connected to %s @ %s\n", conn->host, inet_ntoa(sock4.sin_addr));

	if (use_tls)
	{
		__init_openssl();
		conn->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		assert(conn->ssl_ctx);
		conn->ssl = SSL_new(conn->ssl_ctx);
		assert(conn->ssl);
		SSL_set_fd(conn->ssl, conn->sock);
		SSL_set_connect_state(conn->ssl);
		conn->using_tls = 1;
	}

	freeaddrinfo(ainf);
	return 0;

	fail_release_ainf:
	freeaddrinfo(ainf);

	fail:
	return -1;
}

void
close_connection(connection_t *conn)
{
	assert(conn);

	shutdown(conn->sock, SHUT_RDWR);
	close(conn->sock);
	conn->sock = -1;

	if (conn_using_tls(conn))
	{
		SSL_CTX_free(conn->ssl_ctx);
		SSL_free(conn->ssl);
	}

	buf_destroy(&conn->read_buf);
	buf_destroy(&conn->write_buf);

	return;
}
