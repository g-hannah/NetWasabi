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

enum
{
	XML_TYPE_NODE = 1,
	XML_TYPE_VALUE
};

typedef struct XML_Node
{
	char *n_value;
	int n_type;
	struct XML_Node **n_children; // array of node pointers
	int n_nr_children;
} xml_node_t;

typedef xml_node_t *node_ptr;

typedef struct XML_Tree
{
	xml_node_t *x_root;
	int x_nr_nodes;
} xml_tree_t;

#define NCH(n) ((n)->n_nr_children)
#define CHILD(n,i) ((n)->n_children[(i)])
#define LAST_CHILD(n) CHILD(n,NCH(n)-1)
#define FIRST_CHILD(n) CHILD(n, 0)
#define NVALUE(n) ((n)->n_value)
#define NTYPE(n) ((n)->n_type)

#define NSET_VALUE(n,v) ((n)->n_value = strdup((v)))
#define NSET_TYPE(n,t) ((n)->n_type = (t))

static xml_tree_t XML_tree;
static node_ptr parent = NULL;
static node_ptr node = NULL;

static node_ptr node_stack[256];
static int pnode_idx = 0;

#define CLEAR_NODE_STACK() memset(node_stack, 0, sizeof(node_ptr) * 256)
#define PUSH_PARENT(p) (assert(pnode_idx < 256), node_stack[pnode_idx++] = (p))
#define POP_PARENT() \
({ \
	if (!pnode_idx) \
	{ \
		error("stack underflow"); \
		abort(); \
	} \
	node_stack[--pnode_idx]; \
})

static node_ptr
new_node(void)
{
	node_ptr node = malloc(sizeof(xml_node_t));
	if (!node)
		return NULL;

	memset(node, 0, sizeof(*node));
	return node;
}

/**
 * Add pointer to child node to
 * parent's array of xml_node_t
 * pointers.
 */
static void
add_child(node_ptr parent, node_ptr child)
{
	assert(parent);
	assert(child);

	parent->n_children = realloc(parent->n_children, sizeof(node_ptr) * (NCH(parent) + 1));
	assert(parent->n_children);

	CHILD(parent, NCH(parent)) = child;
	++NCH(parent);

	return;
}

static int indent = 1;
static void
walk_xml_tree(node_ptr root)
{
	fprintf(stderr, "%*sNode @ %p has %d child%s\n",
		indent, " ",
		root,
		NCH(root),
		NCH(root) == 1 ? "" : "ren");

	if (!NCH(root))
		return;

	node_ptr n;
	int i;

	for (i = 0; i < NCH(root); ++i)
	{
		n = CHILD(root, i);

		fprintf(stderr, "%*sChild node: type \"%s\" --> \"%s\"\n",
			indent, " ",
			NTYPE(n) == XML_TYPE_NODE ? "XML Node" : "Node Value",
			NVALUE(n));

		if (NCH(n))
		{
			indent += 4;
			walk_xml_tree(n);
			indent -= 4;
		}
	}

	return;
}

static void
free_xml_tree(node_ptr root)
{
	if (!NCH(root))
	{
		return;
	}

	node_ptr n;
	int i;

	for (i = 0; i < NCH(root); ++i, ++n)
	{
		n = CHILD(root, i);

		if (NCH(n))
			free_xml_tree(n);

		free(NVALUE(n));
		free(n);
	}

	return;
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
	int depth = 0;

	if (setup(INFILE) < 0)
		goto fail;

	if (!str_find(buffer, XML_VERSION_PATTERN))
	{
		fprintf(stderr, "Not an XML file\n");
		goto fail;
	}

	memset(&XML_tree, 0, sizeof(xml_tree_t));

	stack = STACK_object_new_char_ptr();
	assert(stack);

	CLEAR_NODE_STACK();

	XML_tree.x_root = new_node();
	assert(XML_tree.x_root);

	parent = XML_tree.x_root;

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
						error("Unexpected closing tag");
						abort();
					}

					if (memcmp(last_opened, terminal, strlen(terminal)))
					{
						fprintf(stderr, "Open/close tag mismatch (<%s> & </%s>)\n",
							last_opened, terminal);
						abort();
					}

					free(last_opened);

					parent = POP_PARENT();
					Debug("Popped parent - at %p\n", parent);

					Debug("Closing tag -> %s\n", terminal);
					break;
				}

				parse_terminal();

				STACK_push_char_ptr(stack, terminal, strlen(terminal));
				node = new_node();

				NSET_VALUE(node, terminal);
				NSET_TYPE(node, XML_TYPE_NODE);

				Debug("Adding xml-node type node to parent @ %p\n", parent);
				add_child(parent, node);

				Debug("Pushing parent @ %p\n", parent);
				PUSH_PARENT(parent);
				parent = LAST_CHILD(parent);
				Debug("Parent now @ %p\n", parent);

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

				node = new_node();

				NSET_VALUE(node, token);
				NSET_TYPE(node, XML_TYPE_VALUE);

				Debug("Adding value node to parent @ %p\n", parent);
				add_child(parent, node);
				//pr("character sequence");

				break;

			default:
					;
				//pr("unknown...");
		}

		advance();
	}

	walk_xml_tree(XML_tree.x_root);
	free_xml_tree(XML_tree.x_root);
	free(XML_tree.x_root);
	STACK_object_destroy_char_ptr(stack);

	return 0;
fail:
	return -1;
}
