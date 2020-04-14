#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stack.h"

#define STACK_ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

#if 0

#ifdef DEBUG
# define STACK_LOG_FILE "./stack_log.txt"
FILE *elog_fp = NULL;
#endif

static void
log_err(char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(elog_fp, fmt, args);
	va_end(args);
#else
	(void)fmt;
#endif
}

static void
Log(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);

	return;
}

static void
__attribute__((constructor)) STACK_impl_init(void)
{
#ifdef DEBUG
	elog_fp = fdopen(open(STACK_LOG_FILE, O_RDWR), "r+");
	if (!elog_fp)
	{
		elog_fp = stderr;
	}
#endif
	return;
}

static void
__attribute__((destructor)) STACK_impl_fini(void)
{
#ifdef DEBUG
	if (elog_fp && stderr != elog_fp)
		fclose(elog_fp);
#endif
	return;
}

#endif // 0

STACK_ALL_TYPES_DECLARE();

/*
int
main(void)
{
	STACK_OBJ_TYPE(int) *stack_obj_int = STACK_object_new_int();
	if (!stack_obj_int)
		return -1;

	Log("Created stack object @ %p\n", stack_obj_int);

	STACK_TYPE(int) *stack_item_int = malloc(sizeof(STACK_TYPE(int)));
	if (!stack_item_int)
		return -1;

	Log("Created stack item @ %p\n", stack_item_int);

	STACK_push_item_int(stack_obj_int, stack_item_int);
	Log("nr items: %d\n", stack_obj_int->nr_items);

	STACK_object_destroy_int(stack_obj_int);

	return 0;
}
*/
