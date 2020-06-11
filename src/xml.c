#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "xml.h"

#define __ctor __attribute__((constructor))
#define __dtor __attribute__((destructor))
#define ALIGN16(s) (((s) + 0xf) & ~(0xf))
#define clear_struct(s) memset(s, 0, sizeof(*s))

#ifndef max
# define max(a,b) (a) > (b) ? (a) : (b)
#endif

#define error(m) fprintf(stderr, "%s\n", (m))

// single chars
#define OTAG		'<'
#define ETAG		'>'
#define DQUOTE		'\"'
#define META		'?'
#define ASSIGN		'='
#define BSLASH		'\\'
#define SLASH		'/'
#define SPACE		' '
#define DASH		'-'
#define UNDER		'_'
#define COLON		':'
#define EXCL		'!'
#define PERIOD		'.'

#define iscntrlspace(p) ((p) == '\t' || (p) == '\r' || (p) == '\n')

#define istagnamechar(c) \
	isalnum((c)) || \
	(c) == PERIOD || \
	(c) == DASH || \
	(c) == UNDER

#define istokenchar(c) \
	isascii((c)) && \
	(c) != OTAG && \
	(c) != ETAG && \
	(c) != DQUOTE

#define isattribnamechar(c) \
	isalpha((c)) || \
	(c) == COLON

#define isattribvaluechar(c) \
	isalnum((c)) || \
	(c) == SPACE || \
	(c) == SLASH || \
	(c) == PERIOD || \
	(c) == DASH || \
	(c) == UNDER || \
	(c) == COLON

static int lex(void);
static int matches(int);
static void advance(void);
static void parse_token(void);
static void parse_tagname(void);

static void Debug(char *, ...);

enum
{
	TOK_OPEN = 1,
	TOK_CLOSE,
	TOK_META,
	TOK_ASSIGN,
	TOK_DQUOTE,
	TOK_SPACE,
	TOK_SLASH,
	TOK_DASH,
	TOK_EXCL,
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

#if 0
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
#endif

static void
parse_tagname(void)
{
	char *s = ptr;

	while (istagnamechar(*ptr))
		++ptr;

	assert(TOK_LEN_OK(ptr - s));
	strncpy(terminal, s, ptr - s);
	terminal[ptr - s] = 0;

	Debug("parse_tagname -> %s\n", terminal);

	return;
}

#define ATTRIBUTE_NAME_MAX 256
#define ATTRIBUTE_VALUE_MAX 1024
static char attribute_name[ATTRIBUTE_NAME_MAX];
static char attribute_value[ATTRIBUTE_VALUE_MAX];

static void
parse_attribute_name(void)
{
	char *s = ptr;

	/*
	 * Might be at a space char, so skip it.
	 * If not, we're at an alpha char, and
	 * lex() will not advance PTR.
	 */
	advance();
	while (isattribnamechar(*ptr))
		++ptr;

	assert((ptr - s) < ATTRIBUTE_NAME_MAX);
	strncpy(attribute_name, s, ptr - s);
	attribute_name[ptr - s] = 0;

	Debug("Attribute name -> %s\n", attribute_name);

	advance();
	assert(matches(TOK_ASSIGN));

	return;
}

static void
parse_attribute_value(void)
{
	advance();
	assert(matches(TOK_DQUOTE));

	char *s = ptr;

repeat:
	while (isattribvaluechar(*ptr))
		++ptr;

	if (*ptr == DQUOTE && *(ptr-1) == BSLASH)
	{
		++ptr;
		goto repeat;
	}

	assert((ptr - s) < ATTRIBUTE_VALUE_MAX);
	strncpy(attribute_value, s, ptr - s);
	attribute_value[ptr - s] = 0;

	advance();
	assert(matches(TOK_DQUOTE));

	Debug("Attribute value -> %s\n", attribute_value);

	return;
}

static attribute_t *
parse_attributes(int *nr)
{
	assert(matches(TOK_SPACE));

	attribute_t *attribs = NULL;
	int i = 0;

	for (attribs = calloc(1, sizeof(attribute_t));
		;
		attribs = realloc(attribs, ((i+1) * sizeof(attribute_t))))
	{
		assert(attribs);

		parse_attribute_name();
		attribs[i].name = strdup(attribute_name);

		parse_attribute_value();
		attribs[i].value = strdup(attribute_value);

		++i;

		advance();

		if (matches(TOK_CLOSE))
			break;
	}

	*nr = i;

	return attribs;
}


void
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

/**
 * Read the XML file into BUFFER
 */
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

static void
free_token_array(char **tokens)
{
	if (NULL == tokens)
		return;

	int i = 0;
	while (NULL != tokens[i])
	{
		free(tokens[i++]);
	}

	return;
}

/**
 * Turn a query such as \"plants/rose/price\"
 * into { "plants", "rose", "price" }
 */
char **
tokenize_query(char *query)
{
	char **tokens = NULL;
	char *t = NULL;
	int n = 0;

	tokens = calloc(1, sizeof(char *));
	if (!tokens)
		goto fail;

	t = strtok(query, "/");
	if (!t)
		goto fail;

	tokens[n] = calloc(strlen(t), 1);
	strcpy(tokens[n++], t);

	while (1)
	{
		t = strtok(NULL, "/");
		if (!t)
			break;

		tokens = realloc(tokens, (sizeof(char *) * (n+1)));
		if (!tokens)
			goto fail;

		tokens[n] = calloc(strlen(t), 1);
		strcpy(tokens[n++], t);
	}

	tokens = realloc(tokens, (sizeof(char *) * (n+1)));
	if (!tokens)
		goto fail;

	tokens[n] = NULL;

	return tokens;

fail:
	free_token_array(tokens);

	return NULL;
}

#define NCH(n) ((n)->nr_children)
#define CHILD(n,i) ((n)->children[(i)])
#define LAST_CHILD(n) CHILD(n,NCH(n)-1)
#define FIRST_CHILD(n) CHILD(n, 0)
#define NVALUE(n) ((n)->value)
#define NNAME(n) ((n)->name)

#define NSET_VALUE(n,v) ((n)->value = strdup((v)))

#define STACK_MAX_DEPTH 256
static node_ptr node_stack[STACK_MAX_DEPTH];
static char *stack[STACK_MAX_DEPTH];
static int pnode_idx = 0;
static int stack_idx = 0;

#define CLEAR_STACK() memset(stack, 0, sizeof(char *) * STACK_MAX_DEPTH)

/*
 * The following macros are only used in
 * do_parse(), so we can safely have the
 * return statement in here.
 */
#define PUSH_TAG(t) \
do { \
	if (stack_idx >= STACK_MAX_DEPTH) \
	{ \
		error("tag stack overflow"); \
		return -1; \
	} \
	stack[stack_idx++] = strdup((t)); \
	Debug(":::Stack Depth::: => %d\n", stack_idx); \
} while (0)

#define POP_TAG() \
({ \
	if (!stack_idx) \
	{ \
		error("tag stack underflow"); \
		return -1; \
	} \
	Debug(":::Stack Depth::: => %d\n", stack_idx-1); \
	stack[--stack_idx]; \
})

#define PUSH_PARENT(p) \
do { \
	if (pnode_idx >= STACK_MAX_DEPTH) \
	{ \
		error("node stack overflow"); \
		return -1; \
	} \
	node_stack[pnode_idx++] = (p); \
} while (0)

#define POP_PARENT() \
({ \
	if (!pnode_idx) \
	{ \
		error("node stack underflow"); \
		return -1; \
	} \
	node_stack[--pnode_idx]; \
})

#define CLEAR_NODE_STACK() memset(node_stack, 0, sizeof(node_ptr) * STACK_MAX_DEPTH)

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

	parent->children = realloc(parent->children, sizeof(node_ptr) * (NCH(parent) + 1));
	assert(parent->children);

	CHILD(parent, NCH(parent)) = child;
	++NCH(parent);

	return;
}

static int indent = 1;
static void
do_walk_tree(node_ptr root)
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

		fprintf(stderr, "%*sNode \"%s\" -> value==\"%s\"\n",
			indent, " ",
			NNAME(n),
			NVALUE(n));

		if (NULL != n->attributes)
		{
			int j;

			for (j = 0; j < n->nr_attributes; ++j)
				fprintf(stderr, "attribute %s -> %s\n", n->attributes[j].name, n->attributes[j].value);
		}

		if (NCH(n))
		{
			indent += 4;
			do_walk_tree(n);
			indent -= 4;
		}
	}

	return;
}

void
XML_walk_tree(struct XML *xml)
{
	assert(xml);

	do_walk_tree(xml->root);

	return;
}

static void
do_free_tree(node_ptr root)
{
	if (!NCH(root))
	{
		return;
	}

	node_ptr n;
	int i;

	for (i = 0; i < NCH(root); ++i)
	{
		n = CHILD(root, i);

		if (NCH(n))
			do_free_tree(n);

		if (NULL != NNAME(n))
		{
			//Debug("Freeing node name %s\n", NNAME(n));
			free(NNAME(n));
		}

		if (NULL != NVALUE(n))
		{
			//Debug("Freeing node value %s\n", NVALUE(n));
			free(NVALUE(n));
		}

		if (NULL != n->attributes)
		{
			int j;

			for (j = 0; j < n->nr_attributes; ++j)
			{
				free(n->attributes[j].name);
				free(n->attributes[j].value);
			}
		}

		//Debug("Freeing node\n");
		free(n);
	}

	return;
}

void
XML_free(struct XML *xml)
{
	if (NULL == xml || NULL == xml->root)
		return;

	do_free_tree(xml->root);

	Debug("Freeing tree root\n");

	free(NVALUE(xml->root)); // the strdup of "XML_ROOT_NODE"
	free(xml->root);

	Debug("Freeing tree object\n");
	free(xml);
}


/**
 * Find the node whose child has VALUE
 * e.g.,
 * <option>
 *	<name>name of an option</name>
 * </option>
 *
 * Searching for "name of an option"
 * would return parent node <option>
 */
xml_node_t *
XML_find_parent_node_for_value(xml_node_t *root, char *value)
{
	assert(root);
	assert(value);

	if (0 == NCH(root))
		return NULL;

	int i;
	node_ptr node = NULL;
	node_ptr result = NULL;
	size_t vlen = strlen(value);

	for (i = 0; i < NCH(root); ++i)
	{
		node = CHILD(root, i);

		if (NULL == node->value)
			goto recur;

		if (!memcmp((void *)value, (void *)node->value, vlen))
			return root;

	recur:
		result = XML_find_parent_node_for_value(node, value);
		if (NULL != result)
			return result;
	}

	return result;
}

/**
 * Search for a path in the XML tree.
 * For example, "project/dependencies"
 *
 * Return the node corresponding to
 * dependencies if found.
 */
xml_node_t *
XML_find_by_path(struct XML *xml, char *path)
{
	assert(xml);
	assert(path);
	assert(xml->root);

	int inode;
	int itok;
	int nch;
	node_ptr parent = xml->root;
	node_ptr node;
	char **tokens = tokenize_query(path);
	char *tok;
	size_t tlen;

	assert(tokens);

	nch = NCH(parent);
	itok = 0;
	inode = 0;

	if (0 == nch)
		goto not_found;

	node = CHILD(parent, inode++);
	tok = tokens[itok++];
	assert(tok);
	tlen = strlen(tok);

	while (1)
	{
		Debug("Comparing %s with %s\n", tok, node->name);
		int cmp = memcmp((void *)tok, (void *)node->name, tlen);

		if (!cmp)
		{
			if (tokens[itok] == NULL) // we're done
			{
				goto found;
			}
			else
			{
				parent = node;
				nch = NCH(parent);
				inode = 0;

				if (0 == nch)
					goto not_found;

				node = FIRST_CHILD(parent);
				assert(node);

				tok = tokens[itok++];
				assert(tok);
				tlen = strlen(tok);

				continue;
			}
		}
		else
		{
			if (inode == nch)
				goto not_found;

			node = CHILD(parent, inode++);
			assert(node);
		}
	}

not_found:
	free_token_array(tokens);
	return NULL;

found:
	free_token_array(tokens);

	assert(NULL != node);
	return node;
}

char *
XML_get_node_value(xml_node_t *root, char *name)
{
	assert(root);
	assert(name);

	int nch = NCH(root);

	if (0 == nch)
		return NULL;

	node_ptr parent = root;
	node_ptr node = NULL;

	size_t nlen = strlen(name);
	int inode = 0;
	char *value = NULL;

	while (inode < nch)
	{
		node = CHILD(parent, inode++);

		int cmp = memcmp((void *)name, (void *)node->name, nlen);

		if (!cmp)
			return node->value;

		value = XML_get_node_value(node, name);
		if (NULL != value)
			return value;
	}

	return NULL;
}

void
XML_for_each_child(xml_node_t *root, XML_cb_t func)
{
	assert(root);
	assert(func);

	int i;
	int nch = NCH(root);
	node_ptr node = NULL;

	if (0 == nch)
		return;

	for (i = 0; i < nch; ++i)
	{
		node = CHILD(root, i);
		(*func)(node);
	}

	return;
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

/*
 * meta-expr -> '<' '?' target 1(SP attribute '=' DQUOTE value DQUOTE) '?' '>'
 *
 * TODO
 *
 * Correctly extract the information from this.
 */
static void
meta_expr(void)
{
	parse_tagname();
	++ptr; // skip SP

get_expr:
	parse_tagname(); // parse attribute
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

/**
 * Consume the next byte in the buffer
 * (skipping whitespace)
 */
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
		case ASSIGN:
			++ptr;
			return TOK_ASSIGN;
		case SPACE:
			++ptr;
			return TOK_SPACE;
		case DASH:
			++ptr;
			return TOK_DASH;
		case EXCL:
			++ptr;
			return TOK_EXCL;
		case SLASH:
			++ptr;
			return TOK_SLASH;
		default: // do not consume anything

			return TOK_CHARSEQ;
	}
}

/**
 * Create a tree of nodes representing the
 * structure of the XML file. Each node
 * in the tree represents a <tag>. Tags
 * which have values, such as
 * <tag>tag information</tag> will have
 * this stored in NODE->VALUE, otherwise
 * NODE->VALUE will be %NULL.
 *
 * When we encounter a new opening tag,
 * we push the pointer to the current
 * parent node onto the stack, and the
 * new node representing the new tag
 * becomes the new parent node.
 *
 * On encountering a corresponding closing
 * tag, the previous parent is popped
 * off the stack, becoming again the current
 * parent node of newly created nodes.
 */
int
do_parse(struct XML *xml)
{
	assert(xml);

	node_ptr parent = NULL;
	node_ptr node = NULL;

	xml->root = new_node();
	node_ptr r = xml->root;

	r->name = strdup("root");
	r->value = NULL;

	parent = r;

	CLEAR_STACK();
	CLEAR_NODE_STACK();

	advance();

	while (ptr < end)
	{
		switch(lookahead)
		{
			case TOK_OPEN:

				/*
				 * If we are at <tag...
				 *               ^
				 * lex() will not advance the pointer
				 * since we're at an alnum char.
				 */
				advance();

				if (matches(TOK_EXCL)) // comment - <!-- ... -->
				{
					advance();
					assert(matches(TOK_DASH));

					advance();
					assert(matches(TOK_DASH));

					ptr = memchr(ptr, '>', end - ptr);
					assert(ptr);

					advance();
					assert(matches(TOK_CLOSE));

					advance();

					continue;
				}
				else
				if (matches(TOK_META))
				{
					//pr("opening meta tag");
					meta_expr();
					break;
				}
				else
				if (matches(TOK_SLASH))
				{
					parse_tagname();
					char *last_opened = POP_TAG();

					if (!last_opened)
					{
						error("Unexpected closing tag");
						return -1;
					}

					if (memcmp(last_opened, terminal, strlen(terminal)))
					{
						fprintf(stderr, "Open/close tag mismatch (<%s> & </%s>)\n",
							last_opened, terminal);
						return -1;
					}

					free(last_opened);

					parent = POP_PARENT();
					//Debug("Popped parent - at %p\n", parent);

					break;
				}

				parse_tagname();

				node = new_node();
				node->name = strdup(terminal);
				node->value = NULL;

				add_child(parent, node);

				advance();

				if (matches(TOK_SPACE)) // <tagname( attrib="value")+>
				{
					node->attributes = parse_attributes(&node->nr_attributes);
					//assert(matches(TOK_CLOSE));
				}

				if (matches(TOK_SLASH))
				{
					advance();
					assert(matches(TOK_CLOSE));
				}
				else
				{
					PUSH_TAG(terminal);
					PUSH_PARENT(parent);

					parent = LAST_CHILD(parent);
				}

				Debug("Adding child node to node @ %p\n", parent);

				advance();

				if (matches(TOK_CHARSEQ))
				{
					parse_token();
					node->value = strdup(token);
				}
				else
					continue;

				break;

			case TOK_META:

				//pr("meta symbol");
				break;

/*
			case TOK_CHARSEQ:

				parse_token();

				node = new_node();

				NSET_VALUE(node, token);
				NSET_TYPE(node, XML_TYPE_VALUE);

				Debug("Adding value node to parent @ %p\n", parent);
				add_child(parent, node);
				//pr("character sequence");

				break;
*/

			default:
					;
				//pr("unknown...");
		}

		advance();
	}

	return 0;
}

//#define XML_VERSION_PATTERN "<?xml version=\"[^\"]*\"\\( [a-zA-Z]*=\"[^\"]*\"\\)*?>"
int
XML_parse_file(struct XML *xml, char *path)
{
	assert(xml);
	assert(path);

	if (access(path, F_OK) != 0)
	{
		perror("access");
		goto fail;
	}

	if (setup(path) < 0)
		goto fail;

	//if (!str_find(buffer, XML_VERSION_PATTERN))
	//{
	//	fprintf(stderr, "Not an XML file\n");
	//	goto fail;
	//}

	if (do_parse(xml) != 0)
		goto fail;

	return 0;

fail:
	return -1;
}

struct XML *
XML_new(void)
{
	struct XML *xml = malloc(sizeof(struct XML));

	if (NULL == xml)
		return NULL;

	memset(xml, 0, sizeof(*xml));

	return xml;
}

/*
int
main(int argc, char *argv[])
{
	if (setup(argv[1]) < 0) // argv[1] has xml filename
		goto fail;

	struct XML *xml = XML_new();

	if (0 != xml->parse(xml, argv[1]))
		goto fail;

	char *query = strdup("project/dependencies");
	node_ptr p = xml->find(xml, query);

	if (p)
	{
		int j;
		node_ptr n;

		for (j = 0; j < NCH(p); ++j)
		{
			n = CHILD(p, j);
			char *group = XML_get_node_value(n, "groupId");
			char *artifact = XML_get_node_value(n, "artifactId");
			char *version = XML_get_node_value(n, "version");
			char *scope = XML_get_node_value(n, "scope");

			fprintf(stderr,
				"Dependency #%d:\n\n"
				"Group ID: %s\n"
				"Artifact ID: %s\n"
				"Version: %s\n"
				"Scope: %s\n\n\n",
				j + 1,
				group ? group : "N/A",
				artifact ? artifact : "N/A",
				version ? version : "N/A",
				scope ? scope : "N/A"
			);
		}
	}

	free(query);

	xml->walk_tree(xml);
	xml->free_tree(xml);

	return 0;
fail:
	return -1;
}
*/
