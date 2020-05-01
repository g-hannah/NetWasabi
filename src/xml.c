#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/string_utils.h"
#include "../include/stack.h"
//#include "xml.h"

#define INFILE "./config.xml"

#define __ctor __attribute__((constructor))
#define __dtor __attribute__((destructor))
#define ALIGN16(s) (((s) + 0xf) & ~(0xf))

#define error(m) fprintf(stderr, "%s\n", (m))

// single chars
#define OTAG		'<'
#define ETAG		'>'
#define DQUOTE		'\"'
#define META		'?'
#define ASSIGNMENT	'='
#define BSLASH		'\\'
#define SLASH		'/'
#define SPACE		' '

#define iscntrlspace(p) ((p) == '\t' || (p) == '\r' || (p) == '\n')

#define istagnamechar(c) \
	isalnum((c)) || \
	(c) == '.' || \
	(c) == '-' || \
	(c) == '_' || \
	(c) == '/'

#define istokenchar(c) \
	isascii((c)) && \
	(c) != OTAG && \
	(c) != ETAG && \
	(c) != DQUOTE

static int lex(void);
static int matches(int);
static void advance(void);
static void parse_token(void);
static void parse_terminal(void);
static void parse_tagname(void);

enum
{
	TOK_OPEN = 1,
	TOK_CLOSE,
	TOK_META,
	TOK_ASSIGN,
	TOK_DQUOTE,
	TOK_SPACE,
	TOK_SLASH,
	TOK_CHARSEQ
};

static int current;
static int lookahead = -1;
static char *ptr = NULL;
static char *buffer = NULL;
static char *end = NULL;

#define TOK_MAX 1024
static char terminal[TOK_MAX];
static char token[TOK_MAX];

#define TOK_LEN_OK(l) ((l) < TOK_MAX)

typedef struct Node
{
	char *name;
	int tok;
	struct Node *children;
	int nr_children;
} Node;

static Node *root = NULL;
static Node *node = NULL;

#define NCH(n) ((n)->nr_children)
#define CHILD(n,i) (&((n)->children[(i)]))
#define NTYPE(n) ((n)->tok)
#define NAME(n) ((n)->name)

#define N_SET_TYPE(n,t) ((n)->tok = (t))
#define N_SET_NAME(n,s) ((n)->name = strdup((s)))

static Node *
new_node(void)
{
	Node *node = malloc(sizeof(Node));
	if (!node)
		return NULL;

	memset(node, 0, sizeof(*node));
	return node;
}

STACK_ALL_TYPE(char)
STACK_OBJ_TYPE_PTR(char) *stack = NULL;

typedef struct Parse_State
{
	int tag_depth;
	int dquote_depth;
} parse_state_t;

static void
Debug(char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
#else
	(void)fmt;
#endif

	return;
}

static void
__dtor xml_fini(void)
{
	if (NULL != buffer)
	{
		free(buffer);
		buffer = NULL;
	}

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
	while (istokenchar(*ptr))
		++ptr;

	if (*ptr == DQUOTE && *(ptr - 1) == BSLASH)
	{
		++ptr;
		goto repeat;
	}

	assert(TOK_LEN_OK(ptr - s));
	strncpy(token, s, ptr - s);
	token[ptr - s] = 0;

	Debug("parse_token -> %s\n", token);

	return;
}

static void
parse_tagname(void)
{
	char *s = ptr;

	while (istagnamechar(*ptr))
		++ptr;

	assert(TOK_LEN_OK(ptr - s));
	strncpy(token, s, ptr - s);
	token[ptr - s] = 0;

	Debug("parse_tagname -> %s\n", token);

	return;
}

static void
parse_terminal(void)
{
	char *s = ptr;

	while (istagnamechar(*ptr))
		++ptr;

	assert(TOK_LEN_OK(ptr - s));
	strncpy(terminal, s, ptr - s);
	terminal[ptr - s] = 0;

	Debug("parse_terminal -> %s\n", terminal);

	return;
}

/*
 * meta-expr -> '<' '?' target 1(SP attribute '=' DQUOTE value DQUOTE) '?' '>'
 */
static void
meta_expr(void)
{
	parse_terminal();
	++ptr; // skip SP

get_expr:
	parse_terminal(); // parse attribute
	advance(); // set lookahead to next char (should be '=')

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

	parse_token(); // parses until DQUOTE

	advance();

	if (!matches(TOK_DQUOTE))
	{
		error("Missing '\"' symbol");
		abort();
	}

	advance();

	/*
	 * <?target attribute="value" attribute2="value2"?>
	 */
	if (matches(TOK_SPACE))
		goto get_expr;

	if (!matches(TOK_META))
	{
		error("Missing '?' symbol");
		abort();
	}

	return;
}

static int
lex(void)
{
	while (iscntrlspace(*ptr)) // skip CR NL TAB
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
		case SPACE:
			++ptr;
			return TOK_SPACE;
		case SLASH:
			++ptr;
			return TOK_SLASH;
		default: // do not consume anything

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

	stack = STACK_object_new_char_ptr();
	assert(stack);
	//root = new_node();
	//assert(root);

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
				else
				if (matches(TOK_SLASH))
				{
					parse_terminal();
					char *last_opened = STACK_pop_char_ptr(stack);

					if (!last_opened)
					{
						fprintf(stderr, "Unexpected closing tag\n");
						abort();
					}

					if (memcmp(last_opened, terminal, strlen(terminal)))
					{
						fprintf(stderr, "Closing tag and opening tag do not correspond (%s & %s)\n",
							last_opened, terminal);
						abort();
					}

					Debug("Closing tag -> %s\n", terminal);
					break;
				}

				parse_terminal();

				STACK_push_char_ptr(stack, terminal, strlen(terminal));

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

	STACK_object_destroy_char_ptr(stack);

	return 0;
fail:
	return -1;
}
