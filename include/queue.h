#ifndef __QUEUE_H__
#define __QUEUE_H__ 1

typedef struct Queue_Item
{
	void *data;
	size_t data_len;
	struct Queue_item *prev;
	struct Queue_Item *next;
} queue_item_t;

typedef struct Queue_Object
{
	queue_item_t *front;
	queue_item_t *back;
	int nr_items;
} queue_obj_t;

queue_obj_t *QUEUE_object_new(void);
void QUEUE_object_destroy(queue_obj_t *);
int QUEUE_enqueue(queue_obj_t *, void *);
queue_item_t *QUEUE_dequeue(queue_obj_t *);

#endif /* !defined __QUEUE_H__ */
