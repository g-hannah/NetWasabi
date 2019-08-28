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
#include "buffer.h"
#include "cache.h"
#include "connection.h"
#include "http.h"
#include "webreaper.h"

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
 * @hostname: the domain name of the site
 * @use_tls: 1 to use HTTPS; 0 to use HTTP
 */
int
open_connection(connection_t *conn, const char *hostname, int use_tls)
{
	assert(conn);
	assert(hostname);

	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

	clear_struct(conn);
	buf_init(&conn->read_buf, HTTP_DEFAULT_READ_BUF_SIZE);
	buf_init(&conn->write_buf, HTTP_DEFAULT_WRITE_BUF_SIZE);
	clear_struct(&sock4);

	if (getaddrinfo(hostname, NULL, NULL, &ainf) < 0)
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
