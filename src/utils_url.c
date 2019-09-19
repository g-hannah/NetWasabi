#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "http.h"
#include "utils_url.h"
#include "webreaper.h"

/**
 * make_full_url - Take a URL from a page and turn it into
 * a full URL.
 * @conn: connection context
 * @in: the parsed URL
 * @out: the full URL
 */
int
make_full_url(connection_t *conn, buf_t *in, buf_t *out)
{
	assert(conn);
	assert(in);
	assert(out);

	char *p = in->buf_head;
	size_t page_len;
	static char tmp_page[1024];

	buf_clear(out);

/*
 * Some examples of what we want this function to do:
 *
 * https://something.com/
 *   ==> https://something.com.html
 * https://something.com/page
 *   ==> https://something.com/page.html
 * https://something.com/page/
 *   ==> https://something.com/page.html
 * https://something.com
 *   ==> https://something.com.html
 * //community.something.com/page
 *   ==> https://community.something.com/page.html
 * //community.something.com
 *   ==> https://community.something.com.html
 * /forum/category/page
 *   ==> https://<previously-saved-host>/forum/category/page.html
 * ./page
 *   ==> https://<previously-saved-host>/<previously-saved-page>/page.html
 */

/*
 * Handle already-full URLs.
 */
	if (!strncmp("http", p, 4))
	{
		http_parse_page(in->buf_head, tmp_page);
		page_len = strlen(tmp_page);

		buf_append(out, in->buf_head);

		if (*(out->buf_tail - 1) == '/')
			buf_snip(out, (size_t)1);

		if (!has_extension(tmp_page))
			buf_append(out, ".html");
		else
			buf_replace(out, ".php", ".html");

		return 0;
	}

/*
 * Handle relative URLs.
 */
	if (option_set(OPT_USE_TLS))
		buf_append(out, "https://");
	else
		buf_append(out, "http://");

	if (!strncmp("//", p, 2))
	{
		p += 2;
		buf_append(out, p);

		http_parse_page(out->buf_head, tmp_page);
		page_len = strlen(tmp_page);

		if (*(out->buf_tail - 1) == '/')
			buf_snip(out, (size_t)1);

		if (!has_extension(tmp_page))
			buf_append(out, ".html");
		else
			buf_replace(out, ".php", ".html");
	}
	else
	{
		buf_append(out, conn->host);

		if (*p == '.' || *p != '/') /* relative to current page */
		{
			if (*p == '.')
				p += 2;

		/*
		 * Append the current page first.
		 */
			buf_append(out, conn->page);
			page_len = strlen(conn->page);

			if (conn->page[page_len - 1] != '/')
				buf_append(out, "/");

			buf_append(out, p);
		}
		else
		{
			buf_append(out, p);
		}
	}

	if (*(out->buf_tail - 1) == '/')
		buf_snip(out, (size_t)1);

	if (!has_extension(tmp_page))
		buf_append(out, ".html");
	else
		buf_replace(out, ".php", ".html");

	return 0;
}

int
make_local_url(connection_t *conn, buf_t *url, buf_t *path)
{
	assert(url);
	assert(path);

	char *home = getenv("HOME");
	char *p;
	static char tmp_page[1024];

	http_parse_page(url->buf_head, tmp_page);

	if (strncmp("http", url->buf_head, 4))
	{
		fprintf(stderr, "make_local_url: not full url (%s)\n", url->buf_head);
		errno = EPROTO;
		return -1;
	}

	buf_clear(path);
	buf_append(path, "file://");
	buf_append(path, home);
	buf_append(path, "/" WEBREAPER_DIR "/");

	p = url->buf_head + strlen("http://");
	if (*p == '/')
		++p;

	buf_append(path, p);

	if (*(path->buf_tail - 1) == '/')
		buf_snip(path, (size_t)1);

	if (!has_extension(tmp_page))
		buf_append(path, ".html");
	else
		buf_replace(path, ".php", ".html");

	return 0;
}

int
is_xdomain(connection_t *conn, buf_t *url)
{
	assert(conn);
	assert(url);

	static char tmp_host[1024];

	http_parse_host(url->buf_head, tmp_host);

	return strcmp(tmp_host, conn->primary_host);
}

int
local_archive_exists(char *link)
{
	buf_t tmp;
	int exists = 0;
	char *home;
	static char tmp_page[1024];
	static char tmp_host[1024];

	buf_init(&tmp, path_max);

	http_parse_host(link, tmp_host);
	http_parse_page(link, tmp_page);

	home = getenv("HOME");
	buf_append(&tmp, home);
	buf_append(&tmp, "/" WEBREAPER_DIR "/");
	buf_append(&tmp, tmp_host);
	buf_append(&tmp, tmp_page);

	exists = access(tmp.buf_head, F_OK);

	buf_destroy(&tmp);

	if (exists == 0)
		return 1;
	else
		return 0;
}

int
has_extension(char *page)
{
	assert(page);

	size_t page_len = strlen(page);

	if (memchr(page, '.', page_len))
		return 1;
	else
		return 0;
}
