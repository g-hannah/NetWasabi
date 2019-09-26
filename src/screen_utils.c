#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "screen_utils.h"
#include "webreaper.h"

void
clear_line(void)
{
	int i;

	reset_left();

	for (i = 0; i < winsize.ws_col; ++i)
		fprintf(stderr, " ");

	reset_left();
}

void
reset_left(void)
{
	fputc(0x0d, stderr);
	return;
}

void
right(int _x)
{
	int		i;

	if (_x <= 0) return;

	for (i = 0; i < _x; ++i)
		fprintf(stderr, "\x1b[C");

	return;
}

void
left(int _x)
{
	int		i;

	if (_x <= 0) return;

	for (i = 0; i < _x; ++i)
		fprintf(stderr, "\x1b[D");

	return;
}

void
up(const int _x)
{
	int		i;

	if (_x <= 0) return;

	for (i = 0; i < _x; ++i)
		fprintf(stderr, "\x1b[A");

	return;
}

void
down(int _x)
{
	int		i;

	if (_x <= 0) return;

	for (i = 0; i < _x; ++i)
		fprintf(stderr, "\x1b[B");

	return;
}
