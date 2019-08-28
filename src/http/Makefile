CC := gcc
CFLAGS := -Wall -Werror
DEBUG := 0

INCLUDE_DIR := ../../include

HTTP_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/connection.h \
	$(INCLUDE_DIR)/http.h \
	$(INCLUDE_DIR)/malloc.h

HTTP_SOURCE = \
	http.c \
	http_parse_links.c

HTTP_OBJS := $(HTTP_SOURCE:.c=.o)

.PHONY: clean

$(HTTP_OBJS): $(HTTP_SOURCE) $(HTTP_DEPENDENCIES)
ifeq ($(DEBUG),1)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) -g -DDEBUG $^
else
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^
endif

clean:
	rm $(HTTP_OBJS)
