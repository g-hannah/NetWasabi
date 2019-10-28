#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include "queue.h"
#include "webreaper.h"

pthread_mutex_t qmtx;

static void
__attribute__((constructor)) __queue_init(void)
{
	if (pthread_mutex_init(&qmtx) != 0)
	{
		fprintf(stderr, "__queue_init: failed to initialise queue mutex (%s)\n", strerror(errno));
		goto fail;
	}

	return;

	fail:
	exit(EXIT_FAILURE);
}

static void
__attribute__((destructor)) __queue_fini(void)
{
	pthread_mutex_destroy(&qmtx);
}

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

	int ret;
	pthread_mutex_lock(&qmtx);

	ret = 1;

	if (QUEUE_FULL(queue))
		goto out_release_mutex;

	item->next = QUEUE_BACK(queue);
	QUEUE_BACK(queue)->prev = item;
	queue->back = item;
	QUEUE_INC(queue);
	ret = 0;

	out_release_mutex:
	pthread_mutex_unlock(&qmtx);
	return ret;
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

	void *ret;

	pthread_mutex_lock(&qmtx);
	ret = (void *)NULL;

	if (QUEUE_EMPTY(queue))
		goto out_release_mutex;

	struct queue_item *qi = QUEUE_FRONT(queue);
	qi->prev->next = NULL;
	QUEUE_DEC(queue);
	void *d = qi->data;
	free(qi);
	ret = d;

	out_release_mutex:
	pthread_mutex_unlock(&qmtx);
	return ret;
}
