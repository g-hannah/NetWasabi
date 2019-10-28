#include <assert.h>
#include "queue.h"
#include "webreaper.h"

/**
 * enqueue - place data into queue
 * @queue: the queue with data
 * @item: the item to enqueue
 */
int
enqueue(struct queue *queue, struct queue_item *item)
{
	assert(queue);
	assert(item);

	if (QUEUE_FULL(queue))
		return 1;

	item->next = QUEUE_BACK(queue);
	QUEUE_BACK(queue)->prev = item;
	queue->back = item;
	QUEUE_INC(queue);

	return 0;
}

/**
 * dequeue - return data of queued item
 * @queue: the queue with enqueued data
 */
void *
dequeue(struct queue *queue)
{
	assert(queue);
	assert(item);

	if (QUEUE_EMPTY(queue))
		return 1;

	struct queue_item *qi = QUEUE_FRONT(queue);
	qi->prev->next = NULL;
	QUEUE_DEC(queue);
	void *d = qi->data;
	free(qi);

	return d;
}
