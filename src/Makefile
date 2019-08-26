CC := gcc
CFLAGS := -Wall -Werror

INCLUDE_DIR := ../include

PRIMARY_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/http.h

PRIMARY_SOURCE = \
	main.c

PRIMARY_OBJS := $(PRIMARY_SOURCE:.c=.o)

.PHONY: clean

$(PRIMARY_OBJS): $(PRIMARY_SOURCE) $(PRIMARY_DEPENDENCIES)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^

clean:
	rm $(PRIMARY_OBJS)
