#ifndef __XML_h__
#define __XML_h__ 1

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

/*
 * Parse XML data in file specified by PATH.
 * Return an XML tree object.
 */
xml_tree_t *parse_xml_file(char *path);
void free_xml_tree(xml_tree_t *);

#endif /* !defined __XML_h__ */
