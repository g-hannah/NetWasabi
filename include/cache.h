#ifndef WR_CACHE_H
#define WR_CACHE_H 1

#include <sys/types.h>
#include "webreaper.h"

/*
 * 31 ..... 16 15 ..... 0
 *   cache nr     obj nr
 */
#define WR_CACHE_SIZE 4096
#define WR_CACHE_MAX_NAME 64

#define WR_CACHE_INC_FREE(c) ++((c)->nr_free)
#define WR_CACHE_DEC_FREE(c) --((c)->nr_free)

struct wr_cache_obj_ctx
{
	int in_cache; /* active pointer resides in cache */
	void *ptr_addr; /* the address of the active pointer (it holds the address of a cache object) */
	off_t obj_offset; /* offset of cache object from start of cache */
	off_t ptr_offset; /* offset of the active pointer if it resides in the cache */
};

/*
 * Track assigned pointers, so that in case of a realloc
 * of the cache, we can adjust the address within the
 * object refered to by P.
 *
 * cookie_header = wr_cache_alloc(cookie_cache, &cookie_header);
 *
 * cookie_header is assigned the slot, and we save &cookie_header
 * in the assigned list.
 *
 * Multiple instances of the same pointer to a cache object can
 * exist. In the case of wanting to save many URLs in the link
 * cache, we are not concerned with the pointer to the objects.
 * So we can use one single pointer in a loop to store the URLs.
 * However, in such cases, we CANNOT use a local var for this
 * in a loop. So we use a global pointer allocated on the heap.
 * That way, when we need to patch addresses of cache objects
 * due to a relocation on the heap, we don't need to worry about
 * trying to access an address somewhere on the stack that is
 * now out of scope and may cause a segfault (or worse).
 */
#define WR_CACHE_ASSIGN_PTR(c, p, s)\
do {\
	struct wr_cache_obj_ctx *____ctx_p;\
	int ____nr_ = (c)->nr_assigned;\
	if ((____nr_ + 1) >= ((c)->capacity * 2));\
		(c)->assigned_list = realloc((c)->assigned_list, (((c)->capacity * 4) * sizeof(struct wr_cache_obj_ctx)));\
	____ctx_p = ((c)->assigned_list + ____nr_);\
	____ctx_p->ptr_addr = (p);\
	____ctx_p->obj_offset = (off_t)((char *)(s) - (char *)(c)->cache);\
	if ((unsigned long)(p) > (unsigned long)(c)->cache && ((char *)(p) - (char *)(c)->cache) < (c)->cache_size)\
	{\
		____ctx_p->in_cache = 1;\
		____ctx_p->ptr_offset = ((char *)(p) - (char *)(c)->cache);\
	}\
	else\
	{\
		____ctx_p->in_cache = 0;\
		____ctx_p->ptr_offset = 0;\
	}\
	++((c)->nr_assigned);\
} while (0)

/*
 * TODO: use a binary tree for the assigned list to make
 * searching for an active pointer ~ O(log(N))
 */
#define WR_CACHE_REMOVE_PTR(c, p)\
do {\
	struct wr_cache_obj_ctx *____ctx_p = (c)->assigned_list;\
	int ____nr_ = (c)->nr_assigned;\
	int ____i_d_x;\
	int ____k;\
	for (____i_d_x = 0; ____i_d_x < ____nr_; ++____i_d_x)\
	{\
		if (____ctx_p->ptr_addr == (p))\
		{\
			for (____k = ____i_d_x; ____k < (____nr_ - 1); ++____k)\
				memcpy(&____ctx_p[____k], &____ctx_p[____k+1], sizeof(struct wr_cache_obj_ctx));\
			--((c)->nr_assigned);\
			--____nr_;\
			memset(&____ctx_p[____k], 0, sizeof(struct wr_cache_obj_ctx));\
			--____i_d_x;\
		}\
		++____ctx_p;\
	}\
} while (0)

#define WR_CACHE_ADJUST_PTRS(c)\
do {\
	struct wr_cache_obj_ctx *____ctx_p;\
	int ____nr_ = (c)->nr_assigned;\
	int ____i_d_x;\
	for (____ctx_p = (c)->assigned_list, ____i_d_x = 0;\
			____i_d_x < ____nr_;\
			++____i_d_x)\
	{\
		if (____ctx_p->in_cache)\
		{\
			____ctx_p->ptr_addr = (void *)((char *)(c)->cache + ____ctx_p->ptr_offset);\
		}\
		*((unsigned long *)____ctx_p->ptr_addr) = (unsigned long)((char *)(c)->cache + ____ctx_p->obj_offset);\
		++____ctx_p;\
	}\
} while (0)

typedef int (*wr_cache_ctor_t)(void *);
typedef void (*wr_cache_dtor_t)(void *);

typedef struct wr_cache_t
{
	void *cache;
	struct wr_cache_obj_ctx *assigned_list;
	int nr_assigned;
	unsigned char *free_bitmap;
	int capacity;
	int nr_free;
	size_t objsize;
	size_t cache_size;
	uint16_t bitmap_size;
	char *name;
	wr_cache_ctor_t ctor;
	wr_cache_dtor_t dtor;
} wr_cache_t;

wr_cache_t *wr_cache_create(char *, size_t, int, wr_cache_ctor_t, wr_cache_dtor_t);
void wr_cache_destroy(wr_cache_t *) __nonnull((1));
void *wr_cache_alloc(wr_cache_t *, void *) __nonnull((1,2)) __wur;
void wr_cache_dealloc(wr_cache_t *, void *, void *) __nonnull((1,2,3));
int wr_cache_obj_used(wr_cache_t *, void *) __nonnull((1,2)) __wur;
int wr_cache_nr_used(wr_cache_t *) __nonnull((1)) __wur;
int wr_cache_capacity(wr_cache_t *) __nonnull((1)) __wur;
void wr_cache_clear_all(wr_cache_t *) __nonnull((1));

#endif /* WR_CACHE_H */
