#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "malloc.h"
#include "robots.h"
#include "webreaper.h"

#define GLOB_CHAR '*'
#define GLOB_LITERAL "\*"

static inline void __blacklist_token(const char *token);

int got_global_rules = 0;
static char line_buffer[1024];

char **forbidden_tokens;

#define CONSUME_UNTIL(c, sp, p, t) \
do {\
	(p) = memchr((sp), (c), ((t) - (sp)));\
	(sp) = (p);\
} while(0)

#define FIND_TOKEN(tok, p, sp, t) \
do {\
	(p) = strstr((sp), (tok));\
	if ((p) > (t))\
		(p) = NULL;\
} while(0)

#define GET_LINE(p, sp, t) \
do {\
	(p) = memchr((sp), '\n', ((t) - (sp)));\
	if (p)\
	{\
		strncpy(line_buffer, (sp), ((p) - (sp)));\
		line_buffer[(p) - (sp)] = 0;\
		while ((*p) == 0x0a)\
			++(p);\
		(sp) = (p);\
	}\
	else\
		(sp) = NULL;\
} while(0)

static inline void
__blacklist_token(const char *token)
{
	if (!forbidden_tokens)
	{
		forbidden_tokens = wr_calloc(TOK_FORBID_DEFAULT_NR, sizeof(char *));	

		int i;

		for (i = 0; i < TOK_FORBID_DEFAULT_NR+1; ++i)
			forbidden_tokens[i] = NULL;

		for (i = 0; i < TOK_FORBID_DEFAULT_NR; ++i)
			forbidden_tokens[i] = wr_calloc(TOK_MAXLEN, 1);
	}

	assert(forbidden_tokens);

	int i = 0;

	while (forbidden_tokens[i] && forbidden_tokens[i][0] != 0)
		++i;

	if (!forbidden_tokens[i])
	{
		forbidden_tokens = wr_realloc(forbidden_tokens, (i + TOK_FORBID_DEFAULT_NR));

		int j;

		for (j = i; j < (i + TOK_FORBID_DEFAULT_NR); ++j)
			forbidden_tokens[j] = NULL;

		int m = (i + TOK_FORBID_DEFAULT_NR - 1);

		for (j = i; j < m; ++j)
			forbidden_tokens[j] = wr_calloc(TOK_MAXLEN, 1);
	}

	strncpy(forbidden_tokens[i], token, strlen(token));
	forbidden_tokens[strlen(token)] = 0;

	return;
}

#define ADD_RULE(l) \
do {\
	char *__p = (l);\
	char *__q = (l);\
	size_t len = strlen(l);\
	char *__e = ((l) + len);\
	static char tmp[256];\
	if (strstr((l), "Disallow"))\
	{\
		__p = memchr(__q, ' ', (__e - __q));\
		if (__p)\
		{\
			++__p;\
			strncpy(tmp, __p, (__e - __p));\
			tmp[__e - __p] = 0;\
			__blacklist_token(tmp);\
		}\
	}\
} while(0)

int
parse_robots(buf_t *buf)
{
	//assert(buf);

	char *p = buf->buf_head;
	char *savep = NULL;
	char *tail = buf->buf_tail;
	static char *robots_file = "/home/oppa/Projects/WebReaper/robots.txt";
	buf_t _buf;

	struct stat statb;

	clear_struct(&statb);

	lstat(robots_file, &statb);

	buf_init(&_buf, statb.st_size);

	int fd = open(robots_file, O_RDONLY);

	if (fd < 0)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}

	buf_read_fd(fd, &_buf, statb.st_size);

	assert(_buf.buf_head != _buf.buf_tail);

	tail = _buf.buf_tail;

	savep = p = _buf.data;

	FIND_TOKEN("User-agent", p, savep, tail);

	if (!p)
		return -1;

	savep = p;

	CONSUME_UNTIL(' ', savep, p, tail);

	if (!p)
		return -1;

	if (*(p+1) == GLOB_CHAR)
		got_global_rules = 1;

	if (got_global_rules)
		printf("Got rules for \"User-agent: *\"\n");

	CONSUME_UNTIL('\n', savep, p, tail);

	if (!p)
		return -1;

	++p;
	savep = p;

	while (p < tail)
	{
		GET_LINE(p, savep, tail);
		ADD_RULE(line_buffer);
	}

	int i;

	for (i = 0; forbidden_tokens[i] != NULL; ++i)
		printf("FORBIDDEN[%d]=%s\n", i, forbidden_tokens[i]);

	return 0;
}
