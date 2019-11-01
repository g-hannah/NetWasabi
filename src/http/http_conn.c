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
#include "http.h"
#include "malloc.h"
#include "webreaper.h"

/**
 * __init_openssl - initialise the openssl library
 */
static inline void
__init_openssl(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	ERR_load_crypto_strings();
}

/**
 * open_connection - set up a connection with the target site
 * @conn: &connection_t that is initialised in this function
 */
int
open_connection(struct http_t *http)
{
	assert(conn);

	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

	buf_init(&http->conn.read_buf, HTTP_DEFAULT_READ_BUF_SIZE);
	buf_init(&http->conn.write_buf, HTTP_DEFAULT_WRITE_BUF_SIZE);

	clear_struct(&sock4);

	if (getaddrinfo(http->host, NULL, NULL, &ainf) < 0)
	{
		put_error_msg("open_connection: getaddrinfo error (%s)", gai_strerror(errno));
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

	sprintf(http->host_ipv4, "%s", inet_ntoa(sock4.sin_addr));

	update_connection_state(http, FL_CONNECTION_CONNECTING);

	if (option_set(OPT_USE_TLS))
		sock4.sin_port = htons(HTTPS_PORT_NR);
	else
		sock4.sin_port = htons(HTTP_PORT_NR);

	if ((__http_socket(http) = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	assert(conn->sock > 2);

	if (connect(conn->sock, (struct sockaddr *)&sock4, (socklen_t)sizeof(sock4)) != 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	if (option_set(OPT_USE_TLS))
	{
		__init_openssl();
		conn->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		conn->ssl = SSL_new(conn->ssl_ctx);

		SSL_set_fd(conn->ssl, conn->sock); /* Set the socket for reading/writing */
		SSL_set_connect_state(conn->ssl); /* Set as client */
	}

	update_connection_state(conn, FL_CONNECTION_CONNECTED);
	freeaddrinfo(ainf);
	return 0;

	fail_release_ainf:
	update_connection_state(conn, FL_CONNECTION_DISCONNECTED);
	freeaddrinfo(ainf);

	fail:
	return -1;
}

void
close_connection(struct http_t *http)
{
	assert(conn);

	shutdown(conn->sock, SHUT_RDWR);
	close(conn->sock);
	conn->sock = -1;

	update_connection_state(conn, FL_CONNECTION_DISCONNECTED);

	if (option_set(OPT_USE_TLS))
	{
		SSL_CTX_free(conn->ssl_ctx);
		SSL_free(conn->ssl);
		conn->ssl_ctx = NULL;
		conn->ssl = NULL;
	}

	buf_destroy(&conn->read_buf);
	buf_destroy(&conn->write_buf);

	return;
}

int
reconnect(struct http_t *http)
{
	assert(conn);

	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

	shutdown(conn->sock, SHUT_RDWR);
	close(conn->sock);
	conn->sock = -1;

	if (option_set(OPT_USE_TLS))
	{
		SSL_CTX_free(conn->ssl_ctx);
		SSL_free(conn->ssl);
		conn->ssl_ctx = NULL;
		conn->ssl = NULL;
	}

	clear_struct(&sock4);

	if (getaddrinfo(conn->host, NULL, NULL, &ainf) < 0)
	{
		put_error_msg("open_connection: getaddrinfo error (%s)", gai_strerror(errno));
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

	sprintf(conn->host_ipv4, "%s", inet_ntoa(sock4.sin_addr));

	update_connection_state(conn, FL_CONNECTION_CONNECTING);

	if (option_set(OPT_USE_TLS))
		sock4.sin_port = htons(HTTPS_PORT_NR);
	else
		sock4.sin_port = htons(HTTP_PORT_NR);

	if ((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	assert(conn->sock > 2);

	if (connect(conn->sock, (struct sockaddr *)&sock4, (socklen_t)sizeof(sock4)) != 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	if (option_set(OPT_USE_TLS))
	{
		conn->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		conn->ssl = SSL_new(conn->ssl_ctx);

		SSL_set_fd(conn->ssl, conn->sock); /* Set the socket for reading/writing */
		SSL_set_connect_state(conn->ssl); /* Set as client */
	}

	SET_SOCK_FLAG_ONCE = 0;
	SET_SSL_SOCK_FLAG_ONCE = 0;

	update_connection_state(conn, FL_CONNECTION_CONNECTED);
	freeaddrinfo(ainf);
	return 0;

	fail_release_ainf:
	freeaddrinfo(ainf);

	update_connection_state(conn, FL_CONNECTION_DISCONNECTED);

	fail:
	return -1;
}

int
conn_switch_to_tls(struct http_t *http)
{
	close_connection(conn);

#ifdef DEBUG
	update_operation_status("Switching to TLS (%s)", conn->host);
#endif

	set_option(OPT_USE_TLS);

	if (open_connection(conn) < 0)
		goto fail;

	return 0;

	fail:
	return -1;
}
