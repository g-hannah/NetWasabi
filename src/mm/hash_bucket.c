#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hash_bucket.h"

#define HASHING_PRIME 1610612741u
#define ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

#define BUCKET(h, n) ((h)%(n))
#define DEFAULT_NUMBER_BUCKETS 256
#define DEFAULT_LOAD_FACTOR_THRESHOLD 0.75f

static void
Log(char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
#else
	(void)fmt;
#endif

	return;
}

static uint32_t
hash_Object(char *string_Obj)
{
	assert(string_Obj);
	//assert(nrBuckets > 0);

	size_t len = strlen(string_Obj);
	char *p = string_Obj;
	char c = (char)0;
	char *limit = string_Obj + len;
	uint64_t rcx = 0;

	while (p < limit)
	{
		c ^= *p++;
	}

	rcx = (c * HASHING_PRIME);
	//rcx >>= (sizeof(uint32_t)*8);

	return (uint32_t)rcx;
}

static void
free_bucket_list(bucket_t *list_start)
{
	bucket_t *current;
	bucket_t *prev;

	current = list_start;

	while (current)
	{
		prev = current;
		current = current->next;
		free(prev);
	}

	return;
}

static void
free_buckets(bucket_obj_t *bucket_obj)
{
	assert(bucket_obj);

	int i;
	unsigned nr_buckets = bucket_obj->nr_buckets;
	bucket_t *bucket;

	for (i = 0; (unsigned int)i < nr_buckets; ++i)
	{
		bucket = &bucket_obj->buckets[i];

		if (bucket->used)
		{
			if (bucket->next != NULL)
			{
				Log("Freeing linked list of buckets from bucket #%d\n", i);
				free_bucket_list(bucket->next);
			}

			Log("Freeing data at bucket #%d\n", i);
			free(bucket->data);

			bucket->data_len = 0;
			bucket->used = 0;
			bucket->next = NULL;

			--bucket_obj->nr_buckets_used;
		}
	}

	free(bucket_obj->buckets);
}

/**
 * After increasing the number of buckets, we need
 * to move the buckets around because HASH % NR_BUCKETS
 * will give a different index, which means we wouldn't
 * be able to retrieve our data.
 */
static int
adjust_buckets(bucket_obj_t *bucket_obj)
{
	assert(bucket_obj);

	bucket_t *old_bucket;
	bucket_t *buckets;
	bucket_obj_t tmp_bucket_obj;
	unsigned int i;
	unsigned int nr_buckets = bucket_obj->nr_buckets;

	buckets = calloc(nr_buckets, sizeof(bucket_t));
	memset(buckets, 0, sizeof(bucket_t) * nr_buckets);

	tmp_bucket_obj.buckets = buckets;
	tmp_bucket_obj.nr_buckets = nr_buckets;
	tmp_bucket_obj.nr_buckets_used = 0;
	tmp_bucket_obj.load_factor = bucket_obj->load_factor;

	Log("Adjusting buckets after increasing number of buckets\n");

	for (i = 0; i < nr_buckets; ++i)
	{
		old_bucket = &bucket_obj->buckets[i];
		if (BUCKET_put_data(&tmp_bucket_obj, old_bucket->key, old_bucket->data) < 0)
		{
			Log("adjust_buckets: failed to put data into new bucket array\n");
			goto fail;
		}
	}

/*
 * Free the data, linked lists, etc, from the
 * old buckets array and point to the newly
 * created one.
 */
	free_buckets(bucket_obj);

	bucket_obj->buckets = buckets;
	bucket_obj->nr_buckets_used = tmp_bucket_obj.nr_buckets_used;

	memset(&tmp_bucket_obj, 0, sizeof(bucket_obj_t));

	Log("New bucket array at %p\n", bucket_obj->buckets);
	return 0;

fail:
	free_buckets(&tmp_bucket_obj);
	free_buckets(bucket_obj);
	buckets = NULL;
	bucket_obj->buckets = NULL;

	return -1;
}

/**
 * Check if we have passed the load factor
 * threshold and double the number of
 * buckets if so.
 */
static void
check_load_factor(bucket_obj_t *bucket_obj)
{
	float load_factor = LOAD_FACTOR(bucket_obj);

	if (load_factor >= bucket_obj->load_factor)
	{
		Log("Resizing bucket array (load factor: %f)\n", load_factor);

		bucket_obj->nr_buckets <<= 1;
		bucket_obj->buckets = realloc(bucket_obj->buckets, (bucket_obj->nr_buckets*sizeof(bucket_t)));
		assert(bucket_obj->buckets);

		Log("Number of buckets now %u\n", bucket_obj->nr_buckets);

		if (adjust_buckets(bucket_obj) < 0)
			abort(); // XXX Handle this more elegantly
	}

	return;
}

static bucket_t *
new_bucket(void)
{
	bucket_t *bucket = malloc(sizeof(bucket_t));

	if (!bucket)
		return NULL;

	bucket->data = NULL;
	bucket->data_len = 0;
	bucket->used = 0;
	bucket->next = NULL;

	return bucket;
}

int
BUCKET_put_data(bucket_obj_t *bucket_obj, char *key, char *data)
{
	assert(bucket_obj);
	assert(key);
	assert(data);

	uint32_t hash = hash_Object(key);
	int index = BUCKET(hash, bucket_obj->nr_buckets);
	size_t key_len = strlen(key);
	size_t data_len = strlen(data);
	bucket_t *bucket;

	Log("Hash of key \"%s\": %X\n", key, hash);
	Log("Bucket index: %d\n", index);

	bucket = &bucket_obj->buckets[index];

	if (bucket->used)
	{
		while (bucket->next != NULL)
			bucket = bucket->next;

		bucket->next = new_bucket();
		bucket = bucket->next;
	}
	else
	{
		++bucket_obj->nr_buckets_used;
	}

	bucket->key = calloc(ALIGN_SIZE(key_len), 1);

	if (!bucket->key)
		goto fail;

	memcpy((void *)bucket->key, (void *)key, key_len);

	bucket->key[key_len] = 0;
	bucket->hash = hash;
	bucket->data = calloc(ALIGN_SIZE(data_len), 1);

	if (!bucket->data)
		goto fail;

	memcpy(bucket->data, (void *)data, data_len);

	((char *)bucket->data)[data_len] = 0;
	bucket->data_len = data_len;
	bucket->used = 1;

	Log("%s => %s\n", key, (char *)bucket->data);

	check_load_factor(bucket_obj);

	return 0;

fail:
	if (bucket->key)
		free(bucket->key);

	if (bucket->data)
		free(bucket->data);

	return -1;
}

bucket_t *
BUCKET_get_bucket(bucket_obj_t *bucket_obj, char *key)
{
	assert(key);

	uint32_t hash = hash_Object(key);
	int index = BUCKET(hash, bucket_obj->nr_buckets);
	bucket_t *bucket = &bucket_obj->buckets[index];

	if (bucket->used)
		return bucket;
	else
		return NULL;
}

bucket_t *
BUCKET_get_bucket_from_list(bucket_t *bucket, char *key)
{
	assert(bucket);
	assert(key);

	size_t key_len = strlen(key);

	while (bucket)
	{
		if (!memcmp((void *)bucket->key, (void *)key, key_len))
			return bucket;

		bucket = bucket->next;
	}

	return NULL;
}

bucket_obj_t *
BUCKET_object_new(void)
{
	bucket_obj_t *bucket_obj = malloc(sizeof(bucket_obj_t));

	if (!bucket_obj)
		return NULL;

	bucket_obj->buckets = calloc(DEFAULT_NUMBER_BUCKETS, sizeof(bucket_t));

	if (!bucket_obj->buckets)
		goto fail_release_bucket_obj;

	bucket_obj->nr_buckets = DEFAULT_NUMBER_BUCKETS;
	bucket_obj->nr_buckets_used = 0;
	bucket_obj->load_factor = DEFAULT_LOAD_FACTOR_THRESHOLD;

	memset(bucket_obj->buckets, 0, sizeof(bucket_t) * DEFAULT_NUMBER_BUCKETS);

	return bucket_obj;

fail_release_bucket_obj:

	free(bucket_obj);
	return NULL;
}

void
BUCKET_object_destroy(bucket_obj_t *bucket_obj)
{
	if (!bucket_obj)
		return;

	free_buckets(bucket_obj);
	free(bucket_obj);

	return;
}

/**
 * Free all buckets and data and create
 * a new bucket array with default
 * number of buckets.
 */
int
BUCKET_reset_buckets(bucket_obj_t *bucket_obj)
{
	assert(bucket_obj);

	free_buckets(bucket_obj);

	bucket_obj->nr_buckets = DEFAULT_NUMBER_BUCKETS;
	bucket_obj->nr_buckets_used = 0;
	bucket_obj->buckets = calloc(DEFAULT_NUMBER_BUCKETS, sizeof(bucket_t));

	if (!bucket_obj->buckets)
		return -1;

	return 0;
}

void
BUCKET_clear_bucket(bucket_obj_t *bucket_obj, char *key)
{
	assert(bucket_obj);
	assert(key);

	bucket_t *bucket = BUCKET_get_bucket(bucket_obj, key);
	if (!bucket)
		return;

	if (bucket->next)
	{
		free_bucket_list(bucket->next);
		bucket->next = NULL;
	}

	free(bucket->key);
	bucket->key = NULL;

	free(bucket->data);
	bucket->data = NULL;

	bucket->data_len = 0;
	bucket->hash = 0;
	bucket->used = 0;

	--bucket_obj->nr_buckets_used;

	return;
}

/*
int
main(void)
{
	bucket_obj_t *bObj = BUCKET_object_new();

	char string1[] = "Content-Encoding";
	char string2[] = "Vary";
	char string3[] = "Set-Cookie";
	char string4[] = "Range";
	char string5[] = "Transfer-Encoding";
	char string6[] = "Content-Length";
	char string7[] = "x-content-type-options";
	char string8[] = "strict-transport-security";
	char string9[] = "Cache-Control";

	char data1[] = "deflate";
	char data2[] = "encoding";
	char data3[] = "friday 10th april 2020; secure=true";
	char data4[] = "100 - 1024";
	char data5[] = "chunked";
	char data6[] = "21423";
	char data7[] = "no idea what this one would be";
	char data8[] = "true";
	char data9[] = "no-cache; refresh";

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_put_data(bObj, string1, data1);
	BUCKET_put_data(bObj, string2, data2);
	BUCKET_put_data(bObj, string3, data3);
	BUCKET_put_data(bObj, string4, data4);
	BUCKET_put_data(bObj, string5, data5);
	BUCKET_put_data(bObj, string6, data6);
	BUCKET_put_data(bObj, string7, data7);
	BUCKET_put_data(bObj, string8, data8);
	BUCKET_put_data(bObj, string9, data9);

	BUCKET_object_destroy(bObj);

	return 0;
}
*/
