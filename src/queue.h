#ifndef QUEUE_H
#define QUEUE_H 1

#define FL_QUEUE_FULL 0x1
#define FL_QUEUE_ERR 0x2

#define QUEUE_FULL(q) ((q)->full)
#define QUEUE_EMPTY(q) ((q)->nr_queue == 0)

#define QUEUE_BACK(q) ((q)->back)
#define QUEUE_FRONT(q) ((q)->front)

#define QUEUE_MAX(q) ((q)->nr_max)
#define QUEUE_SET_MAX(q, m) ((q)->nr_max = (m))

#define QUEUE_INC(q)\
do {\
	++((q)->nr_queue);\
	if ((q)->nr_queue == QUEUE_MAX(q)\
		(q)->full = 1;\
} while (0)

#define QUEUE_DEC(q)\
do {\
	--((q)->nr_queue);\
	assert((q)->nr_queue >= 0);\
} while (0)

struct queue
{
	void *front;
	void *back;
	int nr_queue;
	int nr_max;
	int full;
};

struct queue_item
{
	struct queue_item *prev;
	struct queue_item *next;
	void *data;
	size_t size;
};

int enqueue(struct queue *, void *, size_t) __nonnull((1,2)) __wur;
void *dequeue(struct queue *) __nonnull((1)) __wur;

#endif /* !defined QUEUE_H */
