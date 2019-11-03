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
 * http_connect - set up a connection with the target site
 * @http: HTTP object with remote host information
 */
int
http_connect(struct http_t *http)
{
	assert(http);

	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

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

	assert(http->conn.host_ipv4);
	sprintf(http->conn.host_ipv4, "%s", inet_ntoa(sock4.sin_addr));
	update_connection_state(http, FL_CONNECTION_CONNECTING);

	if (option_set(OPT_USE_TLS))
		sock4.sin_port = htons(HTTPS_PORT_NR);
	else
		sock4.sin_port = htons(HTTP_PORT_NR);

	if ((http_socket(http) = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	assert(http_socket(http) > 2);

	if (connect(http_socket(http), (struct sockaddr *)&sock4, (socklen_t)sizeof(sock4)) != 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	if (option_set(OPT_USE_TLS))
	{
		__init_openssl();
		http->conn.ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		http_tls(http) = SSL_new(http->conn.ssl_ctx);

		SSL_set_fd(http_tls(http), http_socket(http)); /* Set the socket for reading/writing */
		SSL_set_connect_state(http_tls(http)); /* Set as client */
	}

	update_connection_state(http, FL_CONNECTION_CONNECTED);
	freeaddrinfo(ainf);
	return 0;

	fail_release_ainf:
	update_connection_state(http, FL_CONNECTION_DISCONNECTED);
	freeaddrinfo(ainf);

	fail:
	return -1;
}

void
http_disconnect(struct http_t *http)
{
	assert(http);

	shutdown(http_socket(http), SHUT_RDWR);
	close(http_socket(http));
	http_socket(http) = -1;

	update_connection_state(http, FL_CONNECTION_DISCONNECTED);

	if (option_set(OPT_USE_TLS))
	{
		SSL_CTX_free(http->conn.ssl_ctx);
		SSL_free(http_tls(http));
		http->conn.ssl_ctx = NULL;
		http_tls(http) = NULL;
	}

	return;
}

int
http_reconnect(struct http_t *http)
{
	struct sockaddr_in sock4;
	struct addrinfo *ainf = NULL;
	struct addrinfo *aip = NULL;

	shutdown(http_socket(http), SHUT_RDWR);
	close(http_socket(http));
	http_socket(http) = -1;

	if (option_set(OPT_USE_TLS))
	{
		SSL_CTX_free(http->conn.ssl_ctx);
		SSL_free(http_tls(http));
		http->conn.ssl_ctx = NULL;
		http_tls(http) = NULL;
	}

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

	sprintf(http->conn.host_ipv4, "%s", inet_ntoa(sock4.sin_addr));

	update_connection_state(http, FL_CONNECTION_CONNECTING);

	if (option_set(OPT_USE_TLS))
		sock4.sin_port = htons(HTTPS_PORT_NR);
	else
		sock4.sin_port = htons(HTTP_PORT_NR);

	if ((http_socket(http) = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	if (connect(http_socket(http), (struct sockaddr *)&sock4, (socklen_t)sizeof(sock4)) != 0)
	{
		put_error_msg("open_connection: connect error (%s)", strerror(errno));
		goto fail_release_ainf;
	}

	if (option_set(OPT_USE_TLS))
	{
		http->conn.ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
		http_tls(http) = SSL_new(http->conn.ssl_ctx);

		SSL_set_fd(http_tls(http), http_socket(http)); /* Set the socket for reading/writing */
		SSL_set_connect_state(http_tls(http)); /* Set as client */
	}

	SET_SOCK_FLAG_ONCE = 0;
	SET_SSL_SOCK_FLAG_ONCE = 0;

	update_connection_state(http, FL_CONNECTION_CONNECTED);
	freeaddrinfo(ainf);
	return 0;

	fail_release_ainf:
	freeaddrinfo(ainf);

	update_connection_state(http, FL_CONNECTION_DISCONNECTED);

	fail:
	return -1;
}

int
http_switch_tls(struct http_t *http)
{
	assert(http);

	http_disconnect(http);

#ifdef DEBUG
	update_operation_status("Switching to TLS (%s)", http->host);
#endif

	set_option(OPT_USE_TLS);

	if (http_connect(http) < 0)
		goto fail;

	return 0;

	fail:
	return -1;
}
