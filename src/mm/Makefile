CC := gcc
CFLAGS := -Wall -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-all --param ssp-buffer-size=4 -Wl,-z,relro
DEBUG := 0

INCLUDE_DIR := ../../include

MM_DEPENDENCIES = \
	$(INCLUDE_DIR)/buffer.h \
	$(INCLUDE_DIR)/cache.h \
	$(INCLUDE_DIR)/hash_bucket.h \
	$(INCLUDE_DIR)/malloc.h

MM_SOURCE = \
	buffer.c \
	cache.c \
	hash_bucket.c \
	malloc.c

MM_OBJS := $(MM_SOURCE:.c=.o)

.PHONY: clean

$(MM_OBJS): $(MM_SOURCE) $(MM_DEPENDENCIES)
ifeq ($(DEBUG),1)
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) -g -DDEBUG $^
else
	$(CC) -c $(CFLAGS) -I$(INCLUDE_DIR) $^
endif

clean:
	rm $(MM_OBJS)
