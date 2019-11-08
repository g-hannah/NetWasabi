#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include "netwasabi.h"

pthread_mutex_t qmtx;

static void
__ctor __queue_init(void)
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
__dtor __queue_fini(void)
{
	pthread_mutex_destroy(&qmtx);
}

int
queue_init(struct queue *queue, int max)
{
	assert(queue);
	assert(max > 0);

	if (!(queue = malloc(sizeof(struct queue))))
	{
		fprintf(stderr, "queue_init: failed to allocate memory for queue (%s)\n", strerror(errno));
		goto fail;
	}

	queue->back = NULL;
	queue->front = NULL;
	queue->nr_queue = 0;
	queue->nr_max = max;
	queue->full = 0;

	return 0;

	fail:
	return -1;
}

/**
 * enqueue - place data into queue
 * @queue: the queue with data
 * @item: the item to enqueue
 */
int
enqueue(struct queue *queue, void *data, size_t size)
{
	assert(queue);
	assert(item);

	int ret;

	pthread_mutex_lock(&qmtx);

	ret = 1;
	if (QUEUE_FULL(queue))
		goto out_release_mutex;

	struct queue_item *back = malloc(sizeof(struct queue_item));

	back->prev = NULL;
	back->next = QUEUE_BACK(queue);
	QUEUE_BACK(queue)->prev = back;
	back->data = data;
	back->size = size;

	QUEUE_BACK(queue) = back;
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

	struct queue_item *front = QUEUE_FRONT(queue);
	front->prev->next = NULL;
	QUEUE_DEC(queue);
	ret = front->data;
	free(front);

	out_release_mutex:
	pthread_mutex_unlock(&qmtx);
	return ret;
}
