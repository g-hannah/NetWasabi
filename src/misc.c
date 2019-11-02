#include "misc.h"

void
check_cookies(struct http_t *http)
{
	assert(http);

	off_t offset = 0;
	struct http_cookie_t *cookie = NULL;
	http_header_t *tmp;

	//fprintf(stderr, "allocating header obj to TMP @ %p\n", &tmp);

	tmp = (http_header_t *)wr_cache_alloc(http_hcache, &tmp);

	/*
	 * If there is a Set-Cookie header, then clear all
	 * previously-cached cookies. Otherwise, if no such
	 * header and we have cached cookies, append them
	 * to the buffer. Otherwise, do nothing.
	 */
	if (http_check_header(&http_rbuf(http), "Set-Cookie", (off_t)0, &offset))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		offset = 0;

		while(http_check_header(&http_rbuf(http), "Set-Cookie", offset, &offset))
		{
			http_fetch_header(&http_rbuf(http), "Set-Cookie", tmp, offset);

			if (!tmp->name[0] && !tmp->value[0])
			{
				break;
			}

			http_append_header(&http_wbuf(http), tmp);

			*hc_loop = (struct http_cookie_t *)wr_cache_alloc(cookies, hc_loop);

			__extract_cookie_info(*hc_loop, tmp);

			++offset;
		}
	}
	else
	{
		int nr_used = wr_cache_nr_used(cookies);
		int i;

		if (!nr_used)
			goto out_dealloc;

		cookie = (struct http_cookie_t *)cookies->cache;

		for (i = 0; i < nr_used; ++i)
		{
			while (!wr_cache_obj_used(cookies, (void *)cookie))
				++cookie;

#if 0
			if (__cookie_expired(cookie))
			{
				printf("cookie \"%s\" expired\n", cookie->data);
				wr_cache_dealloc(cookies, (void *)cookie);
				++cookie;
			}
#endif

			strncpy(tmp->value, cookie->data, cookie->data_len);
			tmp->value[cookie->data_len] = 0;
			tmp->vlen = cookie->data_len;
			strcpy(tmp->name, "Cookie");

			http_append_header(&http_wbuf(http), tmp);

			++cookie;
		}
	}

	out_dealloc:
	//fprintf(stderr, "deallocating header object TMP @ %p\n", &tmp);
	wr_cache_dealloc(http_hcache, (void *)tmp, &tmp);

	return;
}

int
connection_closed(struct http_t *http)
{
	assert(http);

	http_header_t *connection;
	buf_t *buf = &http_rbuf(http);
	int rv = 0;
	struct __http_t *__http = (struct __http_t *)http;

	//fprintf(stderr, "allocating header obj in CONNECTION @ %p\n", &connection);

	connection = wr_cache_alloc(__http->headers, &connection);
	assert(connection);

	http_fetch_header(buf, "Connection", connection, (off_t)0);

	if (connection->value[0])
	{
		if (!strcasecmp("close", connection->value))
			rv = 1;
	}

	//fprintf(stderr, "deallocting header obj CONNECTION @ %p\n", &connection);

	wr_cache_dealloc(__http->headers, connection, &connection);
	return rv;
}

void
check_host(struct http_t *http)
{
	assert(http);

	static char old_host[HTTP_HNAME_MAX];

	if (!http->full_url[0])
		return;

	assert(strlen(http->host) < HTTP_HNAME_MAX);
	strcpy(old_host, http->host);
	http_parse_host(http->full_url, http->host);

	if (strcmp(http->host, old_host))
	{
		if (wr_cache_nr_used(cookies) > 0)
			wr_cache_clear_all(cookies);

		update_operation_status("Changing host: %s ==> %s", old_host, http->host);
		http_reconnect(http);
	}

	return;
}

int
check_local_dirs(struct http_t *http, buf_t *filename)
{
	assert(http);
	assert(filename);

	char *p;
	char *e;
	char *end;
	char *name = filename->buf_head;
	buf_t _tmp;

	buf_init(&_tmp, pathconf("/", _PC_PATH_MAX));

	if (*(filename->buf_tail - 1) == '/')
		buf_snip(filename, 1);

	end = filename->buf_tail;
	p = strstr(name, WEBREAPER_DIR);

	if (!p)
	{
		put_error_msg("__check_local_dirs: failed to find webreaper directory in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	e = ++p;

	e = memchr(p, '/', (end - p));

	if (!e)
	{
		put_error_msg("__check_local_dirs: failed to find necessary '/' character in caller's filename\n");
		errno = EPROTO;
		return -1;
	}

	p = ++e;

/*
 * e.g. /home/johndoe/WR_Reaped/favourite-site.com/categories/best-rated
 *                              ^start here, work along to end, checking
 * creating a directory for each part if necessary.
 */

	while (e < end)
	{
		e = memchr(p, '/', (end - p));

		if (!e) /* The rest of the filename is the file itself */
		{
			break;
		}

		buf_append_ex(&_tmp, name, (e - name));
		BUF_NULL_TERMINATE(&_tmp);

		if(access(_tmp.buf_head, F_OK) != 0)
		{
			if (mkdir(_tmp.buf_head, S_IRWXU) < 0)
				put_error_msg("Failed to create directory: %s", strerror(errno));
		}

		p = ++e;
		buf_clear(&_tmp);
	}

	buf_destroy(&_tmp);
	return 0;
}

void
replace_with_local_urls(struct http_t *http, buf_t *buf)
{
	assert(http);
	assert(buf);

	char *tail = buf->buf_tail;
	char *p;
	char *savep;
	char *url_start;
	char *url_end;
	off_t url_start_off;
	off_t url_end_off;
	off_t savep_off;
	off_t poff;
	size_t range;
	buf_t url;
	buf_t path;
	buf_t full;
	int url_type_idx;

	buf_init(&url, HTTP_URL_MAX);
	buf_init(&path, HTTP_URL_MAX);
	buf_init(&full, HTTP_URL_MAX);

#define save_pointers()\
do {\
	savep_off = (savep - buf->buf_head);\
	poff = (savep - buf->buf_head);\
	url_start_off = (url_start - buf->buf_head);\
	url_end_off = (url_end - buf->buf_head);\
} while (0)

#define restore_pointers()\
do {\
	savep = (buf->buf_head + savep_off);\
	p = (buf->buf_head + poff);\
	url_start = (buf->buf_head + url_start_off);\
	url_end = (buf->buf_head + url_end_off);\
} while (0)

	savep = buf->buf_head;
	url_type_idx = 0;

	while (1)
	{
		buf_clear(&url);

		assert(buf->buf_tail <= buf->buf_end);
		assert(buf->buf_head >= buf->data);

		p = strstr(savep, url_types[url_type_idx].string);

		if (!p || p >= tail)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		url_start = (p += url_types[url_type_idx].len);
		url_end = memchr(url_start, url_types[url_type_idx].delim, (tail - url_start));

		if (!url_end)
		{
			++url_type_idx;

			if (url_types[url_type_idx].delim == 0)
				break;

			savep = buf->buf_head;
			continue;
		}

		assert(buf->buf_tail <= buf->buf_end);
		assert(url_start < buf->buf_tail);
		assert(url_end < buf->buf_tail);
		assert(p < buf->buf_tail);
		assert(savep < buf->buf_tail);
		assert((tail - buf->buf_head) == (buf->buf_tail - buf->buf_head));

		range = (url_end - url_start);

		if (!range)
		{
			++savep;
			continue;
		}

		if (!strncmp("http://", url_start, range) || !strncmp("https://", url_start, range))
		{
			savep = ++url_end;
			continue;
		}

		if (range >= HTTP_URL_MAX)
		{
			savep = ++url_end;
			continue;
		}

		assert(range < HTTP_URL_MAX);

		buf_append_ex(&url, url_start, range);
		BUF_NULL_TERMINATE(&url);

		if (range)
		{
			//fprintf(stderr, "turning %s into full url\n", url.buf_head);
			make_full_url(http, &url, &full);
			//fprintf(stderr, "made %s\n", full.buf_head);

			if (make_local_url(http, &full, &path) == 0)
			{
				//fprintf(stderr, "made local url %s\n", path.buf_head);
				buf_collapse(buf, (off_t)(url_start - buf->buf_head), range);
				tail = buf->buf_tail;

				save_pointers();

				assert(path.data_len < path_max);
				buf_shift(buf, (off_t)(url_start - buf->buf_head), path.data_len);
				tail = buf->buf_tail;

				restore_pointers();

				assert((url_start - buf->buf_head) == url_start_off);
				assert((url_end - buf->buf_head) == url_end_off);
				assert((p - buf->buf_head) == poff);
				assert((savep - buf->buf_head) == savep_off);

				strncpy(url_start, path.buf_head, path.data_len);
			}
		}

		assert(buf_integrity(&url));
		assert(buf_integrity(&full));
		assert(buf_integrity(&path));

		//++savep;
		savep = ++url_end;

		if (savep >= tail)
			break;
	}
}

int
archive_page(struct http_t *http)
{
	int fd = -1;
	buf_t *buf = &http_rbuf(http);
	buf_t tmp;
	buf_t local_url;
	char *p;
	int rv;

	update_operation_status("Archiving %s", http->full_url);
	p = HTTP_EOH(buf);

	if (p)
		buf_collapse(buf, (off_t)0, (p - buf->buf_head));

	if (__url_parseable(http->full_url))
		__replace_with_local_urls(http, buf);

	buf_init(&tmp, HTTP_URL_MAX);
	buf_init(&local_url, 1024);

	buf_append(&tmp, http->full_url);
	make_local_url(http, &tmp, &local_url);

/* Now we have "file:///path/to/file.extension" */
	buf_collapse(&local_url, (off_t)0, strlen("file://"));

	rv = __check_local_dirs(http, &local_url);

	if (rv < 0)
		goto fail_free_bufs;

	if (access(local_url.buf_head, F_OK) == 0)
	{
		//update_operation_status("Already archived local copy", 1);
		goto out_free_bufs;
	}

	fd = open(local_url.buf_head, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd == -1)
	{
		put_error_msg("Failed to create local copy (%s)", strerror(errno));
		goto fail_free_bufs;
	}

	update_operation_status("Created %s", local_url.buf_head);
	++nr_reaped;

	buf_write_fd(fd, buf);
	close(fd);
	fd = -1;

	out_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return 0;

	fail_free_bufs:
	buf_destroy(&tmp);
	buf_destroy(&local_url);

	return -1;
}
