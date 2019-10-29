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
enqueue(struct queue *queue, void *data, size_t size)
{
	assert(queue);
	assert(item);

	int ret;

	pthread_mutex_lock(&qmtx);

	if (QUEUE_FULL(queue))
		goto out_release_mutex;

	struct queue_item *back = malloc(sizeof(struct queue_item));
	ret = 1;

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
