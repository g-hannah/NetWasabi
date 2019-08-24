#include <stdio.h>
#include <unistd.h>
#include "http.h"
#include "webreaper.h"

static int get_opts(int, char *[]) __nonnull((2)) __wur;

/*
 * ./webreaper <url> [options]
 */
int
main(int argc, char *argv[])
{
	if (get_opts(argc, argv) < 0)
		goto fail;

	static http_state_t http_state;

	clear_struct(&http_state);
	http_state->base_page = wr_strdup(argv[1]);

	reap(

	fail:
	exit(EXIT_FAILURE);
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
