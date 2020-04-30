#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/string_utils.h"
//#include "xml.h"

#define INFILE "./config.xml"

#define __ctor __attribute__((constructor))
#define __dtor __attribute__((destructor))
#define ALIGN16(s) (((s) + 0xf) & ~(0xf))

// single chars
#define OTAG		'<'
#define ETAG		'>'
#define DQUOTE		'\"'
#define META		'?'
#define ASSIGNMENT	'='

// char seqs
#define META_OTAG	"<?"
#define META_ETAG	"?>"
#define OTAG_CLOSING	"</"

#define iswhitespace(p) (isspace((p)) || (p) == '\r' || (p) == '\n')

#define error(m) fprintf(stderr, "%s\n", (m))
#ifdef DEBUG
# define pr(m) fprintf(stderr, "%s\n", (m))
#else
# define pr(m)
#endif

#define isterminalchar(c) \
	isalnum((c)) || \
	(c) == '.' || \
	(c) == '-' || \
	(c) == '_' || \
	(c) == '/'

static int lex(void);
static int matches(int);
static void advance(void);
static void parse_token(void);
static void parse_terminal(void);

enum
{
	TOK_OPEN = 1,
	TOK_CLOSE,
	TOK_META,
	TOK_ASSIGN,
	TOK_META_OPEN,
	TOK_META_CLOSE,
	TOK_DQUOTE,
	TOK_CHARSEQ
};

static int current;
static int lookahead = -1;
static char *ptr = NULL;
static char *buffer = NULL;
static char *end = NULL;
static char terminal[1024];
static char token[1024];

typedef struct Parse_State
{
	int tag_depth;
	int dquote_depth;
} parse_state_t;

static void
__dtor xml_fini(void)
{
	if (NULL != buffer)
		free(buffer);

	return;
}

static int
setup(char *path)
{
	struct stat statb;
	int fd = -1;

	memset(&statb, 0, sizeof(statb));
	if (lstat(path, &statb) < 0)
		return -1;

	if ((fd = open(path, O_RDONLY)) < 0)
		return -1;

	buffer = calloc(ALIGN16(statb.st_size+1), 1);
	if (!buffer)
		return -1;

	size_t toread = statb.st_size;
	ssize_t n;
	char *p = buffer;

	while (toread > 0 && (n = read(fd, p, toread)))
	{
		if (toread < 0)
			goto fail;

		p += n;
		toread -= n;
	}

	*p = 0;

	ptr = buffer;
	end = buffer + statb.st_size;

	return 0;

fail:
	if (buffer)
		free(buffer);

	return -1;
}

static int
matches(int tok)
{
	return (lookahead == tok);
}

static void
advance(void)
{
	current = lookahead;
	lookahead = lex();
}

static void
parse_token(void)
{
	char *s = ptr;

repeat:
	while (isascii(*ptr) && *ptr != '\"' && *ptr != OTAG)
		++ptr;

	if (*ptr == '\"' && *(ptr - 1) == '\\')
	{
		++ptr;
		goto repeat;
	}

	strncpy(token, s, ptr - s);
	token[ptr - s] = 0;

#ifdef DEBUG
	fprintf(stderr, "parse_token -> %s\n", token);
#endif

	return;
}

static void
parse_terminal(void)
{
	char *s = ptr;

	while (isterminalchar(*ptr))
		++ptr;

	strncpy(terminal, s, ptr - s);
	terminal[ptr - s] = 0;
#ifdef DEBUG
	fprintf(stderr, "parse_terminal -> %s\n", terminal);
#endif

	return;
}

/*
 * meta-expr -> '<' '?' target 1(SP attribute '=' DQUOTE value DQUOTE) '?' '>'
 */
static void
meta_expr(void)
{
	parse_terminal();
	++ptr;

get_expr:
	parse_terminal();
	advance();

	if (!matches(TOK_ASSIGN))
	{
		//fprintf(stderr, "%c <- %c -> %c\n", *(ptr-1), *ptr, *(ptr+1));
		error("Missing '=' symbol");
		abort();
	}

	advance();

	if (!matches(TOK_DQUOTE))
	{
		error("Missing '\"' symbol");
		abort();
	}

	parse_token();

	++ptr;
	advance();

	if (!matches(TOK_META))
		goto get_expr;

	return;
}

static int
lex(void)
{
	char *s;

	while (iswhitespace(*ptr))
		++ptr;

	switch(*ptr)
	{
		case OTAG:
			++ptr;
			return TOK_OPEN;
		case ETAG:
			++ptr;
			return TOK_CLOSE;
		case META:
			++ptr;
			return TOK_META;
		case DQUOTE:
			++ptr;
			return TOK_DQUOTE;
		case ASSIGNMENT:
			++ptr;
			return TOK_ASSIGN;
		default:

			return TOK_CHARSEQ;
	}
}

#define XML_VERSION_PATTERN "<?xml version=\"[^\"]*\"?>"
#define pr(m) fprintf(stderr, "%s\n", (m))
int
main(void)
{
	parse_state_t state;

	if (setup(INFILE) < 0)
		goto fail;

	if (!str_find(buffer, XML_VERSION_PATTERN))
	{
		fprintf(stderr, "Not an XML file\n");
		goto fail;
	}

	memset(&state, 0, sizeof(state));

#if 0
	TOK_OPEN = 1,
	TOK_CLOSE,
	TOK_META,
	TOK_META_OPEN,
	TOK_META_CLOSE,
	TOK_DQUOTE,
	TOK_CHARSEQ
#endif

	advance();

	while (ptr < end)
	{
		switch(lookahead)
		{
			case TOK_OPEN:

				//pr("opening tag");
				advance();

				if (matches(TOK_META))
				{
					//pr("opening meta tag");
					meta_expr();
					break;
				}

				parse_terminal();

				++state.tag_depth;
				break;

			case TOK_CLOSE:

				//pr("closing tag");

				--state.tag_depth;
				//fprintf(stderr, "depth: %d\n", state.tag_depth);
				break;

			case TOK_META:

				//pr("meta symbol");
				break;

			case TOK_CHARSEQ:

				parse_token();
				//pr("character sequence");

				break;

			default:
					;
				//pr("unknown...");
		}

		advance();
	}

	return 0;
fail:
	return -1;
}
