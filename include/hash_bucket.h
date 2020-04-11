#ifndef __HASH_BUCKET_H__
#define __HASH_BUCKET_H__ 1

//#define SET_LOAD_FACTOR(bo, l) \
//	float __lf = ((l) < (float)1.0 && (l) > (float)0.4 ? (l) : (float)0.75)

#define LOAD_FACTOR(bo) \
(float)((float)(bo)->nr_buckets_used / (float)(bo)->nr_buckets)

typedef struct Bucket
{
	void *data;
	size_t data_len;
	int used;
	struct Bucket *next; // linked list of collisions
} bucket_t;

typedef struct Bucket_Object
{
	bucket_t *buckets;
	unsigned int nr_buckets;
	unsigned int nr_buckets_used;
	float load_factor;
} bucket_obj_t;

bucket_obj_t *BUCKET_object_new(void);
void BUCKET_object_destroy(bucket_obj_t *);
void BUCKET_put_data(bucket_obj_t *, char *, char *);

#endif /* !defined __HASH_BUCKET_H__ */
