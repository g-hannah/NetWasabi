#include <openssl/ssl.h>
#include "connection.h"

inline int connection_socket(connection_t *conn)
{
	return conn->sock;
}

inline SSL *connection_tls(connection_t *conn)
{
	return conn->ssl;
}

inline int connection_using_tls(connection_t *conn)
{
	return conn->using_tls;
}
