#ifndef BTREE_H
#define BTREE_H 1

/*
 * BTREE_INIT_NODE - initialise a node in the binary tree
 *
 * @NODE: the node to initialise
 * @TYPE: the type of the node
 * @ELEM_NAME: the name of the element within the node to intialise
 * @NUM: the number of elements of size SIZE for calloc'ing space for the data in the node
 * @SIZE: the size of the elements for calloc'ing space for data in node
 */
#define BTREE_INIT_NODE(NODE, TYPE, ELEM_NAME, NUM, SIZE)\
do {\
	(NODE) = malloc(sizeof(TYPE *));\
	if ((NODE))\
	{\
		(NODE)-> ## ELEM_NAME = calloc((SIZE), (NUM));\
		(NODE)->left = NULL;\
		(NODE)->right = NULL;\
	}\
} while (0)

/*
 * BTREE_ADD_NEW_NODE - iteratively add data into the binary tree
 *
 * @ROOT: root of the binary tree
 * @TYPE: the type of the nodes
 * @ELEM_NAME: the element name within the node where data is put
 * @NUM: the number of elements of size SIZE for calloc'ing space for data in node
 * @DATA: the data to insert into the node
 * @DATA_TYPE: the type of the data
 */
#define BTREE_ADD_NEW_NODE(ROOT, TYPE, ELEM_NAME, NUM, SIZE, DATA, DATA_TYPE)\
do {\
	if (!(ROOT))\
		BTREE_INIT_NODE((ROOT), TYPE, ELEM_NAME, (NUM), (SIZE));\
	(TYPE *)NPTR;\
	NPTR = (ROOT);\
	int CMP;\
	size_t DATA_LEN = strlen((char *)DATA);\
	while (1)\
	{\
		if (DATA[0] && NPTR-> ## ELEM_NAME[0])\
		{\
			CMP = memcmp(DATA, NPTR-> ## ELEM_NAME, DATA_LEN);\
			if (CMP < 0)\
			{\
				if (!NPTR->left)\
				{\
					NPTR->left = BTREE_INIT_NODE(NPTR->left, TYPE, ELEM_NAME, (NUM), (SIZE));\
					memcpy((void *)NPTR->left-> ## ELEM_NAME, (void *)(DATA), DATA_LEN);\
					((char *)NPTR->left-> ## ELEM_NAME + DATA_LEN)[0] = 0;\
				}\
				else\
				{\
					NPTR = NPTR->left;\
					continue;\
				}\
			}\
			else\
			if (CMP > 0)\
			{\
				if (!NPTR->right)\
				{\
					NPTR->right = BTREE_INIT_NODE(NPTR->right, TYPE, ELEM_NAME, (NUM), (SIZE));\
					memcpy((void *)NPTR->right-> ## ELEM_NAME, (void *)(DATA), DATA_LEN);\
					((char *)NPTR->right ## ELEM_NAME + DATA_LEN)[0] = 0;\
				}\
				else\
				{\
					NPTR = NPTR->right;\
					continue;\
				}\
			}\
			else\
			{\
				break;\
			}\
		}\
	}\
} while (0)

#endif /* !defined BTREE_H */
