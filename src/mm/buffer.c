#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "malloc.h"

static inline void
__buf_reset_head(buf_t *buf)
{
	buf->data_len += (buf->buf_head - buf->data);
	buf->buf_head = buf->data;
}

static inline void
__buf_push_tail(buf_t *buf, size_t by)
{
	buf->buf_tail -= by;
	buf->data_len -= by;
}

static inline void
__buf_push_head(buf_t *buf, size_t by)
{
	buf->buf_head -= by;
	buf->data_len += by;
	if (buf->buf_head < buf->data)
		buf->buf_head = buf->data;
}

static inline void
__buf_pull_tail(buf_t *buf, size_t by)
{
	buf->buf_tail += by;
	buf->data_len += by;
}

static inline void
__buf_pull_head(buf_t *buf, size_t by)
{
	buf->buf_head += by;
	buf->data_len -= by;
}

int
buf_integrity(buf_t *buf)
{
	assert(buf);

	if (buf->magic != BUFFER_MAGIC)
		return 0;
	else
		return 1;
}

void
buf_collapse(buf_t *buf, off_t offset, size_t range)
{
	if (range > buf->buf_size || offset >= buf->buf_size)
		return;

	char *to = (buf->data + offset);
	char *from = (to + range);
	char *end = buf->buf_end;
	size_t bytes;

	if (range == buf->buf_size)
	{
		buf_clear(buf);
		return;
	}

	bytes = (end - from);

	memmove(to, from, bytes);
	to = (end - range);
	memset(to, 0, range);

	__buf_push_tail(buf, range);

	if (buf->buf_tail < buf->buf_head)
		buf->buf_tail = buf->buf_head;

	return;
}

void
buf_shift(buf_t *buf, off_t offset, size_t range)
{
	assert(buf);

	char *from = buf->buf_head + offset;
	char *to = from + range;

	if (range > buf_slack(buf))
		buf_extend(buf, range);

	memmove(to, from, buf->buf_tail - from);
	memset(from, 0, range);

	__buf_pull_tail(buf, range);

	return;
}

int
buf_extend(buf_t *buf, size_t by)
{
	assert(buf);
	assert(buf->data);

	size_t	new_size = (by + buf->buf_size);
	size_t	tail_off;
	size_t	head_off;

	tail_off = buf->buf_tail - buf->data;
	head_off = buf->buf_head - buf->data;

	if (!(buf->data = realloc(buf->data, new_size)))
	{
		fprintf(stderr, "buf_extend: realloc error (%s)\n", strerror(errno));
		return -1;
	}

	buf->buf_end = (buf->data + new_size);
	buf->buf_head = (buf->data + head_off);
	buf->buf_tail = (buf->data + tail_off);
	buf->buf_size = new_size;

	return 0;
}

void
buf_clear(buf_t *buf)
{
	memset(buf->data, 0, buf->buf_size);
	buf->buf_head = buf->buf_tail = buf->data;
}

int
buf_append(buf_t *buf, char *str)
{
	size_t len = strlen(str);
	size_t new_size;

	new_size = (buf->buf_size + len);

	if (new_size > buf_slack(buf))
	{
		buf_extend(buf, len);
	}

	strcat(buf->buf_tail, str);
	
	__buf_pull_tail(buf, len);

	return 0;
}

int
buf_append_ex(buf_t *buf, char *str, size_t bytes)
{
	if (strlen(str) < bytes)
		return -1;

	size_t new_size = (buf->buf_size + bytes);

	if (new_size > buf_slack(buf))
		buf_extend(buf, bytes);

	strncpy(buf->buf_tail, str, bytes);

	__buf_pull_tail(buf, bytes);

	return 0;
}

void
buf_snip(buf_t *buf, size_t how_much)
{
	__buf_push_tail(buf, how_much);
	memset(buf->buf_tail, 0, how_much);

	return;
}

int
buf_init(buf_t *buf, size_t bufsize)
{
	memset(buf, 0, sizeof(*buf));

	if (!(buf->data = calloc(bufsize, 1)))
	{
		perror("buf_init: calloc error");
		return -1;
	}

	memset(buf->data, 0, bufsize);
	buf->buf_size = bufsize;
	buf->buf_end = (buf->data + bufsize);
	buf->buf_head = buf->buf_tail = buf->data;
	buf->magic = BUFFER_MAGIC;

	return 0;
}

void
buf_destroy(buf_t *buf)
{
	assert(buf);

	if (buf->data)
	{
		memset(buf->data, 0, buf->buf_size);
		free(buf->data);
		buf->data = NULL;
	}

	memset(buf, 0, sizeof(*buf));

	return;
}


ssize_t
buf_read_fd(int fd, buf_t *buf, size_t bytes)
{
	assert(buf);

	size_t toread = bytes;
	ssize_t n = 0;
	ssize_t total_read = 0;
	size_t buf_size = buf->buf_size;
	char *p = buf->data;

	if (bytes <= 0)
		return 0;

	if (bytes > buf_size)
		buf_extend(buf, (bytes - buf_size));

	while (toread > 0)
	{
		n = read(fd, p, toread);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
				goto fail;
		}

		p += n;
		toread -= n;
		total_read += n;

		__buf_pull_tail(buf, (size_t)n);
	}

	return total_read;

	fail:
	return (ssize_t)-1;
}

ssize_t
buf_read_socket(int sock, buf_t *buf)
{
	assert(buf);

	size_t remaining = buf->buf_size;
	ssize_t n = 0;
	ssize_t total = 0;

	buf_clear(buf);

	while ((n = recv(sock, buf->buf_tail, remaining, 0)))
	{
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
				goto fail;
		}

		__buf_pull_tail(buf, (size_t)n);
		remaining -= n;
		total += n;

		if (remaining <= 1024)
		{
			remaining += buf->buf_size;
			buf_extend(buf, buf->buf_size);
		}
	}

	return total;

	fail:
	return -1;
}

ssize_t
buf_read_tls(SSL *ssl, buf_t *buf)
{
	assert(ssl);
	assert(buf);

	size_t slack = buf_slack(buf);
	ssize_t n;
	ssize_t total = 0;
	int ssl_error = 0;
	int read_socket = 0;
	int slept_for = 0;
	struct timeval timeout = {0};
	fd_set rdfds;

	read_socket = SSL_get_rfd(ssl);
	fcntl(read_socket, F_SETFL, O_NONBLOCK);

	while (1)
	{
		n = SSL_read(ssl, buf->buf_tail, slack);

		if (!n)
		{
			break;
		}
		else
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				ssl_error = SSL_get_error(ssl, n);

				switch(ssl_error)
				{
					case SSL_ERROR_NONE:
						continue;
					case SSL_ERROR_WANT_READ:
						FD_ZERO(&rdfds);
						FD_SET(read_socket, &rdfds);
						timeout.tv_sec = 1;
						slept_for = select(read_socket+1, &rdfds, NULL, NULL, &timeout);

						if (slept_for < 0)
						{
							fprintf(stderr, "buf_read_tls: select error (%s)\n", strerror(errno));
							goto fail;
						}
						else
						if (!slept_for)
							goto out;
						else
							continue;
				}
			}
		}
		else
		{
			total += n;
			slack -= n;
			__buf_pull_tail(buf, (size_t)n);

			if (!slack)
			{
				buf_extend(buf, buf->buf_size);
				slack = buf_slack(buf);
			}
		}
	} /* while (1) */

	out:
	return total;

	fail:
	return -1;
	
}

ssize_t
buf_write_fd(int fd, buf_t *buf)
{
	assert(buf);

	size_t towrite = buf->data_len;
	ssize_t n;
	ssize_t total = 0;

	while (towrite > 0)
	{
		n = write(fd, buf->buf_head, towrite);

		if (n < 0)
			goto fail;

		total += n;

		__buf_pull_head(buf, (size_t)n);
	}

	__buf_reset_head(buf);

	return total;

	fail:
	return -1;
}

ssize_t
buf_write_socket(int sock, buf_t *buf)
{
	assert(buf);

	size_t towrite = buf->data_len;
	ssize_t n = 0;
	ssize_t total = 0;

	while (towrite > 0)
	{
		n = send(sock, buf->buf_head, towrite, 0);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
				goto fail;
		}

		__buf_pull_head(buf, (size_t)n);
		towrite -= n;
		total += n;
	}

	__buf_reset_head(buf);
	return total;

	fail:
	fprintf(stderr, "buf_write_socket: %s\n", strerror(errno));
	return -1;
}

ssize_t
buf_write_tls(SSL *ssl, buf_t *buf)
{
	assert(buf);
	assert(ssl);

	size_t towrite = buf->data_len;
	ssize_t n = 0;
	ssize_t total = 0;

	while (towrite > 0)
	{
		n = SSL_write(ssl, buf->buf_head, towrite);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				ERR_print_errors_fp(stderr);
				int ssl_error = SSL_get_error(ssl, n);
				static char ssl_error_buf[512];

				switch(ssl_error)
				{
					case SSL_ERROR_NONE:
						printf("SSL_ERROR_NONE\n");
						goto fail;
					case SSL_ERROR_ZERO_RETURN:
						printf("SSL_ERROR_ZERO_RETURN\n");
						goto fail;
					case SSL_ERROR_WANT_WRITE:
						printf("SSL_ERROR_WANT_WRITE\n");
						goto fail;
					case SSL_ERROR_WANT_X509_LOOKUP:
						printf("SSL_ERROR_WANT_X509_LOOKUP\n");
						goto fail;
					case SSL_ERROR_SYSCALL:
						printf("SSL_ERROR_SYSCALL\n");
						goto fail;
					case SSL_ERROR_SSL:
						printf("SSL_ERROR_SSL\n");
						goto fail;
					default:
						printf("unknown tls error...\n");
						goto fail;
				}

				ERR_error_string(SSL_get_error(ssl, n), ssl_error_buf);
				fprintf(stderr, "buf_write_tls: SSL_write error (%s)\n", ssl_error_buf);
				goto fail;
			}
		}

		__buf_pull_head(buf, (size_t)n);
		towrite -= n;
		total += n;

	} /* while (towrite > 0) */

	__buf_reset_head(buf);
	return total;

	fail:
	return -1;
}

buf_t *
buf_dup(buf_t *copy)
{
	assert(copy);

	buf_t *new = wr_malloc(sizeof(buf_t));

	new->data = wr_calloc(copy->buf_size, 1);
	memcpy(new->data, copy->data, copy->buf_size);
	new->buf_head = (new->data + (copy->buf_head - copy->data));
	new->buf_tail = (new->data + (copy->buf_tail - copy->data));
	new->data_len = copy->data_len;

	return new;
}

void
buf_copy(buf_t *to, buf_t *from)
{
	assert(to);
	assert(from);

	if (to->buf_size < from->buf_size)
		buf_extend(to, (from->buf_size - to->buf_size));

	memcpy(to->data, from->data, from->buf_size);
	to->buf_head = (to->data + (from->buf_head - from->data));
	to->buf_tail = (to->data + (from->buf_tail - from->data));
	to->data_len = from->data_len;

	return;
}
