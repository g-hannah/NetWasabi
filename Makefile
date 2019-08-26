CC := gcc
CFLAGS := -Wall -Werror
BUILD := 0.0.1
VPATH := include:src
DEBUG := 0

.PHONY: clean

MM_DIR := src/mm
HTTP_DIR := src/http
TOP_DIR := src

PRIMARY_OBJS := \
	$(TOP_DIR)/main.o

MM_OBJS := \
	$(MM_DIR)/buffer.o \
	$(MM_DIR)/cache.o \
	$(MM_DIR)/malloc.o

HTTP_OBJS := \
	$(HTTP_DIR)/http.o

ALL_OBJS := $(MM_OBJS) $(HTTP_OBJS) $(PRIMARY_OBJS)

webreaper: $(ALL_OBJS)
ifeq ($(DEBUG),1)
	@echo Compiling debug v$(BUILD)
	$(CC) $(CFLAGS) -Iinclude -g -DDEBUG $^ -o webreaper
else
	@echo Compiling v$(BUILD)
	$(CC) $(CFLAGS) -Iinclude $^ -o webreaper
endif
