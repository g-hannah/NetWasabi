#include <openssl/ssl.h>
#include "connection.h"

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
