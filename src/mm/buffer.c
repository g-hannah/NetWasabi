#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "malloc.h"

#define BUF_ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

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

	assert(offset >= 0);
	assert(range > 0);

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

	assert(range > 0);
	assert(offset >= 0);
	assert(offset < buf->buf_size);

	char *from;
	char *to;
	size_t slack = buf_slack(buf);
	size_t bytes;

	if (range >= slack)
		buf_extend(buf, BUF_ALIGN_SIZE(((range - slack) * 2)));

	from = (buf->buf_head + offset);
	to = (from + range);

	bytes = (buf->buf_tail - from);
	assert(bytes <= buf->buf_size);

	memmove(to, from, bytes);
	memset(from, 0, range);

	__buf_pull_tail(buf, range);

	assert(buf->buf_tail <= buf->buf_end);
	assert(buf->buf_head >= buf->buf_head);

	return;
}

int
buf_extend(buf_t *buf, size_t by)
{
	assert(buf);
	assert(buf->data);

	if (by < 0)
		return -1;
	else
	if (!by)
		return 0;

	size_t	new_size = (by + buf->buf_size);
	off_t		tail_off;
	off_t		head_off;

	tail_off = (buf->buf_tail - buf->data);
	head_off = (buf->buf_head - buf->data);

	assert(head_off >= 0);
	assert(tail_off >= 0);

	if (!(buf->data = realloc(buf->data, new_size)))
	{
		fprintf(stderr, "buf_extend: realloc error (%s)\n", strerror(errno));
		return -1;
	}

	buf->buf_end = (buf->data + new_size);
	buf->buf_head = (buf->data + head_off);
	buf->buf_tail = (buf->data + tail_off);
	buf->buf_size = new_size;

	assert(buf->data_len == (buf->buf_tail - buf->buf_head));

	return 0;
}

void
buf_clear(buf_t *buf)
{
	memset(buf->data, 0, buf->buf_size);
	buf->buf_head = buf->buf_tail = buf->data;
	buf->data_len = 0;
}

int
buf_append(buf_t *buf, char *str)
{
	size_t len = strlen(str);
	size_t slack = buf_slack(buf);

	if (len >= slack)
	{
		buf_extend(buf, BUF_ALIGN_SIZE(((len - slack) * 2)));
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

	size_t slack = buf_slack(buf);

	if (bytes >= slack)
		buf_extend(buf, BUF_ALIGN_SIZE(((bytes - slack) * 2)));

	strncpy(buf->buf_tail, str, bytes);

	__buf_pull_tail(buf, bytes);

	return 0;
}

void
buf_snip(buf_t *buf, size_t how_much)
{
	off_t tail_off = (buf->buf_tail - buf->data);

	if (how_much > tail_off)
		how_much = (size_t)tail_off;
	else
	if (how_much > buf->buf_size)
		how_much = buf->buf_size;

	__buf_push_tail(buf, how_much);
	memset(buf->buf_tail, 0, how_much);

	return;
}

int
buf_init(buf_t *buf, size_t bufsize)
{
	if (buf->magic == BUFFER_MAGIC) /* already initialised */
		return 0;

	memset(buf, 0, sizeof(*buf));

	if (!(buf->data = calloc(BUF_ALIGN_SIZE(bufsize), 1)))
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
	assert(buf->magic == BUFFER_MAGIC);

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
	int slack;

	if (bytes <= 0)
		return 0;

	if (bytes > buf_size)
		buf_extend(buf, BUF_ALIGN_SIZE((bytes - buf_size)));

	slack = buf_slack(buf);

	while (toread > 0)
	{
		n = read(fd, buf->buf_tail, toread);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			else
				goto fail;
		}

		__buf_pull_tail(buf, (size_t)n);

		toread -= n;
		total_read += n;
		slack -= n;

		if (!slack && toread)
		{
			buf_extend(buf, BUF_ALIGN_SIZE(toread));
			slack = buf_slack(buf);
		}

	}

	return total_read;

	fail:
	return (ssize_t)-1;
}

ssize_t
buf_read_socket(int sock, buf_t *buf, size_t toread)
{
	assert(buf);
	assert(buf->data);
	assert(buf_integrity(buf));

	ssize_t n = 0;
	ssize_t total = 0;
	size_t slack;

	if (toread < 0)
	{
		errno = EINVAL;
		return -1;
	}

#if 0
	int sock_flags;

	if (!SET_SOCK_FLAG_ONCE)
	{
		sock_flags = fcntl(sock, F_GETFL);
		if (!(sock_flags & O_NONBLOCK))
		{
			//__SET_ALARM(1, 0);
			fcntl(sock, F_SETFL, sock_flags | O_NONBLOCK);
			//__RESET_ALARM();
			//alarm(0);
		}

		SET_SOCK_FLAG_ONCE = 1;
	}
#endif

	slack = buf_slack(buf);

	if (toread)
	{

		if (toread >= slack)
		{
			buf_extend(buf, BUF_ALIGN_SIZE((toread - slack) * 2));
			slack = buf_slack(buf);
		}

		while (1)
		{
			n = recv(sock, buf->buf_tail, toread, 0);

			if (!n)
			{
				break;
			}
			else
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					goto out;
				}
				else
				{
					fprintf(stderr, "buf_read_socket: %s\n", strerror(errno));
					goto fail;
				}
			}
			else
			{
				__buf_pull_tail(buf, (size_t)n);

				toread -= n;
				total += n;
				slack -= n;

				if (!toread)
					break;

				if (!slack)
				{
					buf_extend(buf, BUF_ALIGN_SIZE((toread * 2)));
					slack = buf_slack(buf);
				}
			}
		}
	}
	else
	{
		while (1)
		{
			n = recv(sock, buf->buf_tail, slack-1, 0);

			if (!n)
			{
				break;
			}
			else
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					goto out;
				}
				else
				{
					fprintf(stderr, "buf_read_socket: %s\n", strerror(errno));
					goto fail;
				}
			}
			else
			{
				__buf_pull_tail(buf, (size_t)n);

				total += n;
				slack -= n;

				if (!slack)
				{
					buf_extend(buf, BUF_ALIGN_SIZE((buf->buf_size / 2)));
					slack = buf_slack(buf);
				}
			}
		}
	}

	out:
	BUF_NULL_TERMINATE(buf);
	return total;

	fail:
	fprintf(stderr, "buf_read_socket: %s\n", strerror(errno));
	return -1;
}

ssize_t
buf_read_tls(SSL *ssl, buf_t *buf, size_t toread)
{
	assert(ssl);
	assert(buf);
	assert(buf->data);
	assert(buf_integrity(buf));

	size_t slack;
	ssize_t n;
	ssize_t total = 0;

#if 0
	int ssl_error = 0;
	int slept_for = 0;
	struct timeval timeout = {0};
	int read_socket;
	fd_set rdfds;
#endif

#if 0
	int sock_flags;
	int read_socket;

	if (!SET_SSL_SOCK_FLAG_ONCE)
	{
		read_socket = SSL_get_rfd(ssl);
		sock_flags = fcntl(read_socket, F_GETFL);

		if (!(sock_flags & O_NONBLOCK))
		{
			//__SET_ALARM(1, 0);
			fcntl(read_socket, F_SETFL, sock_flags | O_NONBLOCK);
			//alarm(0);
			//__RESET_ALARM();
		}

		SET_SSL_SOCK_FLAG_ONCE = 1;
	}
#endif

	slack = buf_slack(buf);

	if (toread)
	{
		if (toread >= slack)
		{
			buf_extend(buf, BUF_ALIGN_SIZE(((toread - slack) * 2)));
			slack = buf_slack(buf);
		}

		while (1)
		{
			n = SSL_read(ssl, buf->buf_tail, toread);

			if (!n)
			{
				break;
			}
			else
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				{
					return total;
#if 0
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
								fprintf(stderr, "buf_read_tls: SSL_read error\n");
								goto fail;
							}
							else
							if (!slept_for)
							{
								goto out;
							}
							else
							{
								continue;
							}
							break;
						default:
							goto fail;
					}
#endif
				}
			}
			else
			{
				__buf_pull_tail(buf, (size_t)n);

				toread -= n;
				total += n;
				slack -= n;

				if (!toread)
					break;

				if (!slack)
				{
					buf_extend(buf, BUF_ALIGN_SIZE((toread * 2)));
					slack = buf_slack(buf);
				}
			}
		} // while (1)

		goto out;
	}
	else // !toread
	{
		while (1)
		{
			n = SSL_read(ssl, buf->buf_tail, slack-1);

			if (n == 0)
			{
				break;
			}
			else
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				{
					return total;
#if 0
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
							{
								goto out;
							}
							else
							{
								continue;
							}
						default:
							goto fail;
					}
#endif
				}
			}
			else
			{
				__buf_pull_tail(buf, (size_t)n);

				slack -= n;
				total += n;

				if (!slack)
				{
					buf_extend(buf, BUF_ALIGN_SIZE((buf->buf_size / 2)));
					slack = buf_slack(buf);
				}
			}
		} /* while (1) */
	}

	out:

	BUF_NULL_TERMINATE(buf);
	return total;

	//fail:
	return -1;
	
}

ssize_t
buf_write_fd(int fd, buf_t *buf)
{
	assert(buf);

	size_t towrite = buf->data_len;
	ssize_t n;
	ssize_t total = 0;
	char *p = buf->buf_head;

	while (towrite > 0)
	{
		n = write(fd, p, towrite);

		if (!n)
		{
			break;
		}
		else
		if (n < 0)
		{
			goto fail;
		}

		towrite -= n;
		total += n;
		p += n;
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
	ssize_t total = 0;

	while (towrite > 0)
	{
		n = send(sock, buf->buf_head, towrite, 0);

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
				fprintf(stderr, "buf_write_socket: send error (%s)\n", strerror(errno));
				goto fail;
			}
		}

		__buf_pull_head(buf, (size_t)n);
		towrite -= n;
		total += n;
	}

	__buf_reset_head(buf);

	BUF_NULL_TERMINATE(buf);
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
	//int write_socket;
	//fd_set wfds;
	//struct timeval timeout = {0};
	//int slept_for = 0;

	while (towrite > 0)
	{
		n = SSL_write(ssl, buf->buf_head, towrite);
		if (!n)
		{
			break;
		}
		else
		if (n < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
#if 0
			else
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				write_socket = SSL_get_wfd(ssl);
				FD_ZERO(&wfds);
				FD_SET(write_socket, &wfds);
				timeout.tv_sec = 1;
				slept_for = select(write_socket+1, NULL, &wfds, NULL, &timeout);
				if (slept_for < 0)
				{
					fprintf(stderr, "buf_write_tls: select error (%s)\n", strerror(errno));
					return -1;
				}
				else
				{
					continue;
				}
			}
#endif
			else
			{
				int ssl_error = SSL_get_error(ssl, n);

				switch(ssl_error)
				{
					case SSL_ERROR_NONE:
						continue;
						break;
					default:
					{
						ERR_print_errors_fp(stderr);
						goto fail;
					}
				}
			}
		}

		__buf_pull_head(buf, (size_t)n);
		towrite -= n;
		total += n;

	} /* while (towrite > 0) */

	__buf_reset_head(buf);

	BUF_NULL_TERMINATE(buf);
	return total;

	fail:
	return -1;
}

buf_t *
buf_dup(buf_t *copy)
{
	assert(copy);

	buf_t *new = nw_malloc(sizeof(buf_t));

	new->data = nw_calloc(copy->buf_size, 1);
	memcpy(new->data, copy->data, copy->buf_size);
	new->buf_end = (new->data + copy->buf_size);
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
		buf_extend(to, BUF_ALIGN_SIZE((from->buf_size - to->buf_size)));

	memcpy(to->data, from->data, from->buf_size);
	to->buf_end = (to->data + from->buf_size);
	to->buf_head = (to->data + (from->buf_head - from->data));
	to->buf_tail = (to->data + (from->buf_tail - from->data));
	to->data_len = from->data_len;
	to->magic = from->magic;

	return;
}

void
buf_replace(buf_t *buf, char *pattern, char *with)
{
	assert(buf);
	assert(pattern);
	assert(with);

	size_t pattern_len = strlen(pattern);
	size_t replace_len = strlen(with);
	char *p;
	off_t poff;

	p = strstr(buf->buf_head, pattern);

	if (!p)
		return;

	if (pattern_len > replace_len)
	{
		strncpy(p, with, replace_len);
		p += replace_len;
		buf_collapse(buf, (off_t)(p - buf->buf_head), (pattern_len - replace_len));
	}
	else
	{
		poff = (p - buf->buf_head);
		buf_shift(buf, (off_t)(p - buf->buf_head), (replace_len - pattern_len));
		p = (buf->buf_head + poff);
		strncpy(p, with, replace_len);
	}

	return;
}

void
buf_push_tail(buf_t *buf, size_t by)
{
	assert(buf);

	if ((buf->buf_tail - by) < buf->buf_head)
	{
		__buf_push_tail(buf, (buf->buf_tail - buf->buf_head));
		return;
	}

	__buf_push_tail(buf, by);
	return;
}

void
buf_pull_tail(buf_t *buf, size_t by)
{
	assert(buf);

	if ((buf->buf_tail + by) > buf->buf_end)
	{
		buf_extend(buf, BUF_ALIGN_SIZE((by - (buf->buf_end - buf->buf_tail))));
	}

	__buf_pull_tail(buf, by);
	return;
}

void
buf_push_head(buf_t *buf, size_t by)
{
	assert(buf);

	if ((buf->buf_head - by) < buf->data)
	{
		__buf_push_head(buf, (buf->buf_head - buf->data));
		return;
	}

	__buf_push_head(buf, by);
	return;
}

void
buf_pull_head(buf_t *buf, size_t by)
{
	assert(buf);

	if ((buf->buf_head + by) > buf->buf_tail)
	{
		__buf_pull_head(buf, (buf->buf_tail - buf->buf_head));
		return;
	}

	__buf_pull_head(buf, by);
	return;
}
