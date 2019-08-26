CC := gcc
CFLAGS := -Wall -Werror
BUILD := 0.0.1
VPATH := include
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
	$(HTTP_DIR)/http.o \
	$(HTTP_DIR)/http_parse_links.o

ALL_OBJS := $(MM_OBJS) $(HTTP_OBJS) $(PRIMARY_OBJS)

webreaper: $(ALL_OBJS)
ifeq ($(DEBUG),1)
	@echo Compiling debug v$(BUILD)
	cd $(MM_DIR); make DEBUG=1
	cd $(HTTP_DIR); make DEBUG=1
	cd $(TOP_DIR); make DEGBUG=1
else
	@echo Compiling v$(BUILD)
	cd $(MM_DIR); make
	cd $(HTTP_DIR); make
	cd $(TOP_DIR); make
endif
	$(CC) $(CFLAGS) -Iinclude $^ -o webreaper
