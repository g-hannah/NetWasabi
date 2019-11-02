CC := gcc
CFLAGS := -Wall -Werror
DEBUG := 0

INCLUDE_DIR := ../include

PRIMARY_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/http.h \
	$(INCLUDE_DIR)/graph.h \
	$(INCLUDE_DIR)/malloc.h \
	$(INCLUDE_DIR)/misc.h \
	$(INCLUDE_DIR)/request.h \
	$(INCLUDE_DIR)/robots.h \
	$(INCLUDE_DIR)/screen_utils.h \
	$(INCLUDE_DIR)/utils_url.h \
	$(INCLUDE_DIR)/webreaper.h

PRIMARY_SOURCE = \
	main.c \
	graph.c \
	misc.c \
	parse_links.c \
	request.c \
	robots.c \
	screen_utils.c \
	utils_url.c

PRIMARY_OBJS := $(PRIMARY_SOURCE:.c=.o)

.PHONY: clean

$(PRIMARY_OBJS): $(PRIMARY_SOURCE) $(PRIMARY_DEPENDENCIES)
ifeq ($(DEBUG),1)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) -g -DDEBUG $^
else
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^
endif

clean:
	rm $(PRIMARY_OBJS)
