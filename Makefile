CC := gcc
CFLAGS := -Wall -Werror
BUILD := 0.0.1
VPATH := include
DEBUG := 0

.PHONY: clean

MM_DEP = \
	include/buffer.h \
	include/cache.h \
	include/malloc.h

MM_SOURCE = \
	src/mm/buffer.c \
	src/mm/cache.c \
	src/mm/malloc.c

MM_OBJS=$(MM_SOURCE:.c=.o)

HTTP_DEP = \
	include/http.h \
	include/buffer.h \
	include/cache.h \
	include/malloc.h

HTTP_SOURCE = \
	src/http/http.c

HTTP_OBJS=$(HTTP_SOURCE:.c=.o)

PRIMARY_DEP = \
	include/cache.h \
	include/http.h

PRIMARY_SOURCE = \
	src/main.c

PRIMARY_OBJS=$(PRIMARY_SOURCE:.c=.o)

webreaper: $(MM_OBJS) $(HTTP_OBJS) $(PRIMARY_OBJS)
	$(CC) $(CFLAGS) -Iinclude $< -o webreaper

$(PRIMARY_OBJS): $(PRIMARY_SOURCE) $(PRIMARY_DEP)
	$(CC) $(CFLAGS) -Iinclude $(PRIMARY_SOURCE) $(PRIMARY_DEP) -o $@

$(MM_OBJS): $(MM_SOURCE) $(MM_DEP)
	$(CC) $(CFLAGS) -Iinclude $(MM_SOURCE) $(MM_DEP) -o $@

$(HTTP_OBJS): $(HTTP_SOURCE) $(HTTP_DEP)
	$(CC) $(CFLAGS) -Iinclude $(HTTP_SOURCE) $(HTTP_DEP) -o $@

clean:
	rm $(OBJ)
