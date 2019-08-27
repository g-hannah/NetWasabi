#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "webreaper.h"

#define GLOB_CHAR '*'
#define GLOB_LITERAL "\*"

extern char **token_blacklist;

int parse_robots(buf_t *) __nonnull((1)) __wur;
static inline void __blacklist_token(const char *token);

int got_global_rules = 0;
static char line_buffer[1024];

#define CONSUME_UNTIL(c, sp, p, t) \
do {\
	p = memchr((sp), (c), ((t) - (sp)));\
	(sp) = (p);\
} while(0)

#define FIND_TOKEN(tok, p, sp, t) \
do {\
	p = strstr((sp), (tok));\
	if ((p) > (t))\
		p = NULL;\
} while(0)

#define GET_LINE(p, sp, t) \
do {\
	p = memchr((sp), '\n', ((t) - (sp)));\
	if (p)\
	{\
		++(p);\
		strncpy(line_buffer, (sp), ((p) - (sp)));\
		line_buffer[(p) - (sp)] = 0;\
		++(p);\
		(sp) = (p);\
	}\
	else\
	{\
		(sp) = NULL;\
		break;\
	}\
} while(0)

static inline void __blacklist_token(const char *token)
{
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
			__q = __p;\
			__p = memchr(__q, '\n', (__e - __q));\
			strncpy(tmp, __q, (__p - __q));\
			tmp[__p - __q] = 0;\
			__blacklist_token(tmp);\
		}\
	}\
} while(0)

int
parse_robots(buf_t *buf)
{
	assert(buf);

	char *p = buf->buf_head;
	char *savep = NULL;
	char *tail = buf->buf_tail;

	savep = p;

	FIND_TOKEN("User-Agent", p, savep, tail);

	if (!p)
		return -1;

	savep = p;

	CONSUME_UNTIL(' ', savep, p, tail);

	if (!p)
		return -1;

	if (*(p+1) == GLOB_CHAR)
		got_global_rules = 1;

	CONSUME_UNTIL('\n', savep, p, tail);

	if (!p)
		return -1;

	++p;
	savep = p;

	while (p)
	{
		GET_LINE(p, savep, tail);
		ADD_RULE(line_buffer);
	}

	return 0;
}
