#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "cache.h"
#include "http.h"
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

	wr_cache_t *http_link_cache = wr_cache_create("http_link_cache",
							sizeof(struct http_link_t),
							0,
							wr_cache_http_link_ctor,
							wr_cache_http_link_dtor);

	printf("created cache for http_link_t objects\n");

	http_link_t *hl = wr_cache_alloc(http_link_cache);

	printf("obtained an object from cache\n");

	wr_cache_dealloc(http_link_cache, (void *)hl);

	printf("returned object to cache\n");

	wr_cache_destroy(http_link_cache);

	printf("destroyed the cache\n");

	exit(EXIT_SUCCESS);

	//fail:
	//exit(EXIT_FAILURE);
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
