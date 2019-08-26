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

	printf("created cache\n");

	buf_t buf;

	buf_init(&buf, (size_t)16384);

	printf("initialised buffer (magic=0x%02x)\n", (unsigned)buf.magic);

	static char *filename = "/home/oppa/Projects/WebReaper/humans.txt";

	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		goto fail;

	printf("opened file on fd %d\n", fd);

	struct stat statb;

	clear_struct(&statb);
	if (lstat(filename, &statb) < 0)
		goto fail;

	printf("reading into buffer\n");
	buf_read_fd(fd, &buf, statb.st_size);

	assert(buf.buf_tail != buf.data);

	http_parse_links(http_link_cache, &buf);

	http_link_t	*hl = (http_link_t *)http_link_cache->cache;

	int capacity = http_link_cache->capacity;

	while(capacity)
	{
		if (hl->url)
			printf("%s (%ld)\n", hl->url, hl->time_reaped);

		wr_cache_dealloc(http_link_cache, (void *)hl);
		hl->used = 0;

		while (capacity && !hl->used)
		{
			++hl;
			--capacity;
		}
	}

	buf_destroy(&buf);

	wr_cache_destroy(http_link_cache);

	printf("destroyed the cache\n");

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
