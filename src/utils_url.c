#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "http.h"
#include "utils_url.h"
#include "netwasabi.h"

struct url_encodings
{
	char old;
	char *new;
};

struct url_encodings url_encodings[] =
{
	{ ' ', "%20" },
	{ '"', "%22" },
	{ '\'', "%27" },
	{ '*', "%2c" },
	{ 0, "" }
};

void
encode_url(buf_t *url)
{
	assert(url);

	int url_eidx = 0;
	char *p;
	char *e;
	char *tail = url->buf_tail;

	while (url_encodings[url_eidx].old != 0)
	{
		e = url->buf_head;

		while (1)
		{
			p = memchr(e, url_encodings[url_eidx].old, (tail - e));

			if (!p)
			{
				++url_eidx;
				break;
			}

			buf_shift(url, (off_t)(p - url->buf_head), (size_t)2);
			tail = url->buf_tail;
			strncpy(p, url_encodings[url_eidx].new, (size_t)3);
			e = (p += 3);
		}
	}

	/* Remove \"&amp;" */

	e = url->buf_head;
	tail = url->buf_tail;

	while (1)
	{
		p = strstr(e, "&amp;");

		if (!p || p >= tail)
			break;

		++p;
		e = (p + 4);
		buf_collapse(url, (off_t)(p - url->buf_head), (e - p));
		tail = url->buf_tail;
		e = p;
	}

	e = url->buf_head;
	tail = url->buf_tail;

	while (1)
	{
		p = strstr(e, "\\u0026");

		if (!p || p >= tail)
			break;

		*p++ = '&';
		e = (p + 5);
		buf_collapse(url, (off_t)(p - url->buf_head), (e - p));
		tail = url->buf_tail;
		e = p;
	}

	return;
}

/**
 * make_full_url - Take a URL from a page and turn it into
 * a full URL.
 * @conn: connection context
 * @in: the parsed URL
 * @out: the full URL
 */
int
make_full_url(struct http_t *http, buf_t *in, buf_t *out)
{
	assert(http);
	assert(in);
	assert(out);

	char *p = in->buf_head;
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
	if (!strncmp("http://", p, 7) || !strncmp("https://", p, 8))
	{
		buf_append(out, in->buf_head);

		if (*(out->buf_tail - 1) == '/')
			buf_snip(out, (size_t)1);

		encode_url(out);
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

		if (*(out->buf_tail - 1) == '/')
			buf_snip(out, (size_t)1);
	}
	else
	{
		buf_append(out, http->host);

		if (*p == '.' || *p != '/')
		{
		/*
		 * Append the current page first.
		 */
			if (http->page[0] != '/' && *(out->buf_tail - 1) != '/')
				buf_append(out, "/");

			if (has_extension(http->page))
			{
				char *__e;

				__e = (http->page + strlen(http->page) - 1);
				while (*__e != '/')
					--__e;

				*__e = 0;
			}

			buf_append(out, http->page);

			if (*(out->buf_tail - 1) != '/')
				buf_append(out, "/");

			buf_append(out, p);
		}
		else
		{
			if (*(out->buf_tail - 1) != '/' && *p != '/')
				buf_append(out, "/");

			buf_append(out, p);
		}
	}

	if (!keep_tslash(&nwctx))
	{
		if (*(out->buf_tail - 1) == '/')
			buf_snip(out, (size_t)1);
	}

	encode_url(out);
	return 0;
}

int
make_local_url(struct http_t *http, buf_t *url, buf_t *path)
{
	assert(url);
	assert(path);

	char *home = getenv("HOME");
	char *p;
	static char tmp_page[1024];
	buf_t tmp_full;

	buf_init(&tmp_full, HTTP_URL_MAX);
	http_parse_page(url->buf_head, tmp_page);

	if (strncmp("http:", url->buf_head, 5) && strncmp("https:", url->buf_head, 6))
	{
		fprintf(stderr, "make_local_url: not full url (%s)\n", url->buf_head);
		errno = EPROTO;
		return -1;
	}

	buf_clear(path);
	buf_append(path, "file://");
	buf_append(path, home);
	buf_append(path, "/" NETWASABI_DIR "/");

	p = url->buf_head + strlen("http://");
	if (*p == '/')
		++p;

	buf_append(path, p);

	if (*(path->buf_tail - 1) == '/')
		buf_snip(path, (size_t)1);

	if (!has_extension(tmp_page))
	{
		buf_append(path, ".html");
	}
	else
	{
		buf_replace(path, ".php", ".html");
		buf_replace(path, ".asp", ".html");
		buf_replace(path, ".aspx", ".html");
		buf_replace(path, ".git", ".html");
	}

	buf_destroy(&tmp_full);

	return 0;
}

int
is_xdomain(struct http_t *http, buf_t *url)
{
	assert(http);
	assert(url);

	static char tmp_host[1024];

	http_parse_host(url->buf_head, tmp_host);

	return strcmp(tmp_host, http->primary_host);
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
	buf_append(&tmp, "/" NETWASABI_DIR "/");
	buf_append(&tmp, tmp_host);
	buf_append(&tmp, tmp_page);

	if (*(tmp.buf_tail - 1) == '/')
		buf_snip(&tmp, (size_t)1);

	if (!has_extension(tmp_page))
	{
		buf_append(&tmp, ".html");
	}
	else
	{
		buf_replace(&tmp, ".php", ".html");
		buf_replace(&tmp, ".asp", ".html");
		buf_replace(&tmp, ".aspx", ".html");
	}

	exists = access(tmp.buf_head, F_OK);
	buf_destroy(&tmp);

	if (exists == 0)
		return 1;
	else
		return 0;
}

static
char *__last_dot(char *url)
{
	size_t url_len = strlen(url);
	char *e;
	char *p;
	char *end = url + url_len;

	p = url;

	while (1)
	{
		e = memchr(p, '.', (end - p));

		if (!e)
			break;

		p = ++e;
	}

	if (p != url)
		return --p;
	else
		return NULL;
}

int
has_extension(char *page)
{
	assert(page);

	size_t page_len = strlen(page);
	char *dot;
	char *end = page + page_len;

	dot = __last_dot(page);

	if (!dot)
		return 0;

/*
 * We want to save files ending in .html; we
 * replace .php, .asp, etc, with .html.
 * But some can end up having a name like
 * <filename>.html?param=value&param2=value2
 * So we're really testing if the last thing
 * in the name is the extension, not whether there
 * is one in there somewhere.
 */
	if (memchr(dot, '/', (end - dot))
	|| memchr(dot, '?', (end - dot)))
		return 0;
	else
		return 1;
}

