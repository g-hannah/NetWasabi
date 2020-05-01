#ifndef __STACK_H__
#define __STACK_H__ 1

#define STACK_ITEM_OF_TYPE(type) \
struct Stack_item_ ## type \
{ \
	type data; \
	struct Stack_item_ ## type *next; \
	struct Stack_item_ ## type *prev; \
};

#define STACK_ITEM_OF_TYPE_PTR(type) \
struct Stack_item_ ## type ## _ptr \
{ \
	type *data; \
	struct Stack_item_ ## type ## _ptr *next; \
	struct Stack_item_ ## type ## _ptr *prev; \
};

#define STACK_OBJ_OF_TYPE(type) \
struct Stack_obj_ ## type \
{ \
	struct Stack_item_ ## type *top; \
	struct Stack_item_ ## type *bottom; \
	int nr_items; \
};

#define STACK_OBJ_OF_TYPE_PTR(type) \
struct Stack_obj_ ## type ## _ptr \
{ \
	struct Stack_item_ ## type ## _ptr *top; \
	struct Stack_item_ ## type ## _ptr *bottom; \
	int nr_items; \
};

#define STACK_ITEM_TYPE(type) struct Stack_item_ ## type
#define STACK_ITEM_TYPE_PTR(type) struct Stack_item_ ## type ## _ptr
#define STACK_OBJ_TYPE(type) struct Stack_obj_ ## type
#define STACK_OBJ_TYPE_PTR(type) struct Stack_obj_ ## type ## _ptr

#define STACK_NEW_OBJ_OF_TYPE_FUNC(type) \
STACK_OBJ_TYPE(type) * \
STACK_object_new_ ## type (void) \
{ \
	STACK_OBJ_TYPE(type) *obj = malloc(sizeof(STACK_OBJ_TYPE(type))); \
	if (!obj) \
		return NULL; \
	obj->top = obj->bottom = NULL; \
	obj->nr_items = 0; \
	return obj; \
}

#define STACK_NEW_OBJ_OF_TYPE_PTR_FUNC(type) \
STACK_OBJ_TYPE_PTR(type) * \
STACK_object_new_ ## type ## _ptr (void) \
{ \
	STACK_OBJ_TYPE_PTR(type) *obj = malloc(sizeof(STACK_OBJ_TYPE_PTR(type))); \
	if (!obj) \
		return NULL; \
	obj->top = obj->bottom = NULL; \
	obj->nr_items = 0; \
	return obj; \
}

#define STACK_DESTROY_OBJ_OF_TYPE_FUNC(type) \
void \
STACK_object_destroy_ ## type (STACK_OBJ_TYPE(type) *obj) \
{ \
	assert((obj)); \
	STACK_ITEM_TYPE(type) *item; \
	STACK_ITEM_TYPE(type) *save; \
	item = save = (obj)->top; \
	while (item) \
	{ \
		item = item->prev; \
		free(save); \
		save = item; \
	} \
	free((obj)); \
	return; \
}

#define STACK_DESTROY_OBJ_OF_TYPE_PTR_FUNC(type) \
void \
STACK_object_destroy_ ## type ## _ptr (STACK_OBJ_TYPE_PTR(type) *obj) \
{ \
	assert((obj)); \
	STACK_ITEM_TYPE_PTR(type) *item; \
	STACK_ITEM_TYPE_PTR(type) *save; \
	item = save = (obj)->top; \
	while (item) \
	{ \
		item = item->prev; \
		free(save->data); \
		free(save); \
		save = item; \
	} \
	free((obj)); \
	return; \
}

#define STACK_POP_TYPE_FUNC(type) \
type \
STACK_pop_ ## type (STACK_OBJ_TYPE(type) *obj) \
{ \
	assert((obj)); \
	if (!(obj)->top) \
		return (type)-1; \
	STACK_ITEM_TYPE(type) *item = (obj)->top; \
	if (item->prev) \
		item->prev->next = NULL; \
	(obj)->top = (obj)->top->prev; \
	item->prev = NULL; \
	--(obj)->nr_items; \
	type d = item->data; \
	free(item); \
	return d; \
}

#define STACK_POP_TYPE_PTR_FUNC(type) \
type * \
STACK_pop_ ## type ## _ptr (STACK_OBJ_TYPE_PTR(type) *obj) \
{ \
	assert((obj)); \
	if (!(obj)->top) \
		return NULL; \
	STACK_ITEM_TYPE_PTR(type) *item = (obj)->top; \
	if (item->prev) \
		item->prev->next = NULL; \
	(obj)->top = (obj)->top->prev; \
	item->prev = NULL; \
	--(obj)->nr_items; \
	type *d = item->data; \
	free(item); \
	return d; \
}

#define STACK_PUSH_TYPE_FUNC(type) \
void \
STACK_push_ ## type (STACK_OBJ_TYPE(type) *obj, type data) \
{ \
	assert((obj)); \
	STACK_ITEM_TYPE(type) *item = malloc(sizeof(STACK_ITEM_TYPE(type))); \
	if (!item) \
		return; \
	memset(item, 0, sizeof(*item)); \
	item->data = data; \
	if (!(obj)->top) \
	{ \
		(obj)->top = (item); \
		(obj)->bottom = (item); \
		(item)->next = NULL; \
		(item)->prev = NULL; \
	} \
	else \
	{ \
		(obj)->top->next = (item); \
		(item)->prev = (obj)->top; \
		(item)->next = NULL; \
		(obj)->top = (item); \
	} \
	++(obj)->nr_items; \
	return; \
}

#define STACK_PUSH_TYPE_PTR_FUNC(type) \
void \
STACK_push_ ## type ## _ptr (STACK_OBJ_TYPE_PTR(type) *obj, type *data, size_t size) \
{ \
	assert((obj)); \
	STACK_ITEM_TYPE_PTR(type) *item = malloc(sizeof(STACK_ITEM_TYPE_PTR(type))); \
	if (!item) \
		return; \
	memset(item, 0, sizeof(*item)); \
	item->data = calloc(size+1, 1); \
	memcpy((void *)item->data, (void *)(data), size); \
	((char *)item->data)[size] = 0; \
	if (!(obj)->top) \
	{ \
		(obj)->top = (item); \
		(obj)->bottom = (item); \
		(item)->next = NULL; \
		(item)->prev = NULL; \
	} \
	else \
	{ \
		(obj)->top->next = (item); \
		(item)->prev = (obj)->top; \
		(item)->next = NULL; \
		(obj)->top = (item); \
	} \
	++(obj)->nr_items; \
	return; \
}

#define STACK_ALL_TYPE(type) \
	STACK_ITEM_OF_TYPE(type) \
	STACK_ITEM_OF_TYPE_PTR(type) \
	STACK_OBJ_OF_TYPE(type) \
	STACK_OBJ_OF_TYPE_PTR(type) \
	STACK_NEW_OBJ_OF_TYPE_FUNC(type) \
	STACK_NEW_OBJ_OF_TYPE_PTR_FUNC(type) \
	STACK_DESTROY_OBJ_OF_TYPE_FUNC(type) \
	STACK_DESTROY_OBJ_OF_TYPE_PTR_FUNC(type) \
	STACK_PUSH_TYPE_FUNC(type) \
	STACK_PUSH_TYPE_PTR_FUNC(type) \
	STACK_POP_TYPE_FUNC(type) \
	STACK_POP_TYPE_PTR_FUNC(type)

#define STACK_ALL_TYPES_DECLARE() \
	STACK_ALL_TYPE(char) \
	STACK_ALL_TYPE(short) \
	STACK_ALL_TYPE(int) \
	STACK_ALL_TYPE(long) \
	STACK_ALL_TYPE(float) \
	STACK_ALL_TYPE(double)

#endif /* !defined __STACK_H__ */
