#ifndef CONNECTION_H
#define CONNECTION_H 1

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
