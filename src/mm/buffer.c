#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"

static inline void
__push_buf_tail(buf_t *buf, size_t by)
{
	buf->buf_tail += by;
	buf->data_len += by;
}

static inline void
__pull_buf_tail(buf_t *buf, size_t by)
{
	buf->buf_tail -= by;
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

		__push_buf_tail(buf, (size_t)n);
	}

	return total_read;

	fail:
	return (ssize_t)-1;
}
