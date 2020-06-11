#ifndef __XML_h__
#define __XML_h__ 1

/*
 * For saving attributes of a tag, such as
 * <tagname attribute1="value1" attribute2="value2">
 */
typedef struct Attribute
{
	char *name;
	char *value;
} attribute_t;

typedef struct XML_Node
{
	char *name;
	char *value;
	attribute_t *attributes;
	struct XML_Node **children; // array of node pointers
	int nr_children;
	int nr_attributes;
} xml_node_t;

struct XML
{
	xml_node_t *root;
	int nr_nodes;
};

typedef xml_node_t *node_ptr;

typedef void(*XML_cb_t)(xml_node_t *);

struct XML *XML_new(void);
int XML_parse_file(struct XML *, char *);
xml_node_t *XML_find_by_path(struct XML *, char *);
xml_node_t *XML_find_parent_node_for_value(xml_node_t *, char *);
char *XML_get_node_value(xml_node_t *, char *);
void XML_free(struct XML *);
void XML_for_each_child(xml_node_t *, XML_cb_t);

#endif /* !defined __XML_h__ */
