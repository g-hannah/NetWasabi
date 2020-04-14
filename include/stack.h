#ifndef __STACK_H__
#define __STACK_H__ 1

#define STACK_OF_TYPE(type) \
struct Stack_ ## type \
{ \
	type data; \
	struct Stack_ ## type *next; \
	struct Stack_ ## type *prev; \
};

#define STACK_OBJ_OF_TYPE(type) \
struct Stack_obj_ ## type \
{ \
	struct Stack_ ## type *top; \
	struct Stack_ ## type *bottom; \
	int nr_items; \
};

#define STACK_TYPE(type) struct Stack_ ## type
#define STACK_OBJ_TYPE(type) struct Stack_obj_ ## type

#define STACK_OBJECT_NEW_FUNC(type) \
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

#define STACK_OBJECT_DESTROY_FUNC(type) \
void \
STACK_object_destroy_ ## type (STACK_OBJ_TYPE(type) *obj) \
{ \
	assert((obj)); \
	STACK_TYPE(type) *item; \
	STACK_TYPE(type) *save; \
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

#define STACK_POP_FUNC(type) \
STACK_TYPE(type) * \
STACK_pop_item_ ## type (STACK_OBJ_TYPE(type) *obj) \
{ \
	assert((obj)); \
	if (!(obj)->top) \
		return NULL; \
	STACK_TYPE(type) *item = (obj)->top; \
	if (item->prev) \
		item->prev->next = NULL; \
	(obj)->top = (obj)->top->prev; \
	item->prev = NULL; \
	--(obj)->nr_items; \
	return item; \
}

#define STACK_PUSH_FUNC(type) \
void \
STACK_push_item_ ## type (STACK_OBJ_TYPE(type) *obj, STACK_TYPE(type) *item) \
{ \
	assert((obj)); \
	assert((item)); \
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
	STACK_OF_TYPE(type) \
	STACK_OBJ_OF_TYPE(type) \
	STACK_OBJECT_NEW_FUNC(type) \
	STACK_OBJECT_DESTROY_FUNC(type) \
	STACK_PUSH_FUNC(type) \
	STACK_POP_FUNC(type)

#define STACK_ALL_TYPES_DECLARE() \
	STACK_ALL_TYPE(char) \
	STACK_ALL_TYPE(short) \
	STACK_ALL_TYPE(int) \
	STACK_ALL_TYPE(long) \
	STACK_ALL_TYPE(float) \
	STACK_ALL_TYPE(double)

#endif /* !defined __STACK_H__ */
