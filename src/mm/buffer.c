#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"

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

	buf->buf_tail -= range;

	if (buf->buf_tail < buf->buf_head)
		buf->buf_tail = buf->buf_head;

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
	else
	{
		buf->buf_tail += len;
	}

	strcat(buf->buf_tail, str);

	return 0;
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
buf_write_socket(int sock, buf_t *buf)
{
	assert(buf);

	size_t towrite = buf->data_len;
	ssize_t n = 0;

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
	}

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
	int ssl_error;
	int write_sock;
	int time_slept = 0;
	struct timeval timeout = {0};
	fd_set wrfds;

	write_sock = SSL_get_wfd(ssl);
	fcntl(write_sock, F_SETFL, O_NONBLOCK);
	
	while (towrite > 0)
	{
		n = SSL_write(ssl, buf->buf_head, towrite);
		if (n <= 5 && n > 0)
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
					case SSL_ERROR_WANT_WRITE:
						FD_ZERO(&wrfds);
						FD_SET(write_sock, &wrfds);
						timeout.tv_sec = 1;
						time_slept = select(write_sock+1, NULL, &wrfds, NULL, &timeout);
						if (time_slept < 0)
						{
							fprintf(stderr, "buf_write_tls: select error (%s)\n", strerror(errno));
							goto fail;
						}
						else
						if (time_slept == 0)
						{
							goto out;
						}
						else
						{
							continue;
						}
				}
			}
		}

		__buf_pull_head(buf, (size_t)n);
		towrite -= n;
		total += n;

	} /* while (towrite > 0) */

	__buf_reset_head(buf);

	out:
	return total;

	fail:
	return -1;
}
