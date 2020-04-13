#ifndef __HASH_BUCKET_H__
#define __HASH_BUCKET_H__ 1

#include <stdint.h>
#include <sys/types.h>

#define LOAD_FACTOR(bo) \
(float)((float)(bo)->nr_buckets_used / (float)(bo)->nr_buckets)

typedef struct Bucket
{
	char *key;
	uint32_t hash; // the hash of the key
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
void BUCKET_object_destroy(bucket_obj_t *bObj);
int BUCKET_put_data(bucket_obj_t *bObj, char *key, char *data);
int BUCKET_reset_buckets(bucket_obj_t *bObj);
void BUCKET_clear_bucket(bucket_obj_t *bObj, char *key);
bucket_t *BUCKET_get_bucket(bucket_obj_t *bObj, char *key);
bucket_t *BUCKET_get_bucket_from_list(bucket_t *bucket, char *key);
bucket_t *BUCKET_get_list_bucket_for_value(bucket_t *bucket, void *data, size_t data_len);
char *BUCKET_get_key_for_value(bucket_t *bucket, void *data, size_t data_len);

#endif /* !defined __HASH_BUCKET_H__ */
