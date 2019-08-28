#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "cache.h"
#include "http.h"
#include "robots.h"
#include "webreaper.h"

//static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * ./webreaper <url> [options]
 */
int
main(int argc, char *argv[])
{
	//if (get_opts(argc, argv) < 0)
		//goto fail;

	buf_t buffer;

	if (parse_robots(&buffer) < 0)
		goto fail;

#if 0
	wr_cache_t *http_link_cache = wr_cache_create("http_link_cache",
							sizeof(struct http_link_t),
							0,
							wr_cache_http_link_ctor,
							wr_cache_http_link_dtor);

	//http_link_t	*hl = (http_link_t *)http_link_cache->cache;
	void *obj = NULL;
	void *prev_obj = NULL;
	int capacity = wr_cache_capacity(http_link_cache);
	int i;
	int nr_used = 0;

	for (i = 0; i < capacity; ++i)
	{
		obj = wr_cache_alloc(http_link_cache);
		assert(obj);
		printf("obj @ %p\n", obj);
		assert(obj != prev_obj);
		printf("prev_obj @ %p\n", prev_obj);
		assert(wr_cache_obj_used(http_link_cache, obj));
		printf("obj used=%d\n", wr_cache_obj_used(http_link_cache, obj));
		++nr_used;
		assert(wr_cache_nr_used(http_link_cache) == nr_used);
		printf("nr_used (%d) == ->nr_used (%d)\n",
			nr_used, wr_cache_nr_used(http_link_cache));
		prev_obj = obj;
	}

	obj = http_link_cache->cache;
	for (i = 0; i < capacity; ++i)
	{
		printf("obj @ %p\n", obj);
		wr_cache_dealloc(http_link_cache, obj);
		assert(!wr_cache_obj_used(http_link_cache, obj));
		printf("obj used=%d\n", wr_cache_obj_used(http_link_cache, obj));
		obj = (void *)((char *)obj + sizeof(http_link_t));
	}
#endif

	exit(EXIT_SUCCESS);

	fail:
	fprintf(stderr, "%s\n", strerror(errno));
	exit(EXIT_FAILURE);
}

static void
__noret usage(int exit_status)
{
	printf("webreaper <url> [options]\n");
	exit(exit_status);
}

int
get_opts(int argc, char *argv[])
{
	int		i;

	for (i = 1; i < argc; ++i)
	{
		while (i < argc && argv[i][0] != '-')
			++i;

		if (i == argc)
			break;

		if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i]))
			usage(EXIT_SUCCESS);
	}

	return 0;
}
