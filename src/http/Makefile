CC := gcc
CFLAGS := -Wall -Werror

INCLUDE_DIR := ../../include

HTTP_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/http.h \
	$(INCLUDE_DIR)/malloc.h

HTTP_SOURCE = \
	http.c

HTTP_OBJS := $(HTTP_SOURCE:.c=.o)

.PHONY: clean

$(HTTP_OBJS): $(HTTP_SOURCE) $(HTTP_DEPENDENCIES)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^

clean:
	rm $(HTTP_OBJS)
