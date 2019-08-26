CC := gcc
CFLAGS := -Wall -Werror

INCLUDE_DIR := ../../include

MM_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/malloc.h

MM_SOURCE = \
	buffer.c \
	cache.c \
	malloc.c

MM_OBJS := $(MM_SOURCE:.c=.o)

.PHONY: clean

$(MM_OBJS): $(MM_SOURCE) $(MM_DEPENDENCIES)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^

clean:
	rm $(MM_OBJS)
