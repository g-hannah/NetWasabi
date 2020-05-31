CC := gcc
CFLAGS := -Wall -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-all --param ssp-buffer-size=4 -Wl,-z,relro
BUILD := 0.0.3
DEBUG := 0

.PHONY: clean

MM_DIR := src/mm
HTTP_DIR := src/http
TOP_DIR := src

PRIMARY_OBJS := \
	$(TOP_DIR)/main.o \
	$(TOP_DIR)/cache_management.c \
	$(TOP_DIR)/fast_mode.o \
	$(TOP_DIR)/graph.o \
	$(TOP_DIR)/netwasabi.o \
	$(TOP_DIR)/robots.o \
	$(TOP_DIR)/utils_url.o \
	$(TOP_DIR)/screen_utils.o \
	$(TOP_DIR)/string_utils.o \
	$(TOP_DIR)/xml.o

MM_OBJS := \
	$(MM_DIR)/btree.o \
	$(MM_DIR)/buffer.o \
	$(MM_DIR)/cache.o \
	$(MM_DIR)/hash_bucket.o \
	$(MM_DIR)/malloc.o \
	$(MM_DIR)/queue.o \
	$(MM_DIR)/stack.o

HTTP_OBJS := \
	$(HTTP_DIR)/http.o

ALL_OBJS := $(MM_OBJS) $(HTTP_OBJS) $(PRIMARY_OBJS)

LIBS=-lcrypto -lssl -lpthread

netwasabi: $(ALL_OBJS)
ifeq ($(DEBUG),1)
	@echo Compiling debug v$(BUILD)
	cd $(MM_DIR); make DEBUG=1
	cd $(HTTP_DIR); make DEBUG=1
	cd $(TOP_DIR); make DEBUG=1
else
	@echo Compiling v$(BUILD)
	cd $(MM_DIR); make
	cd $(HTTP_DIR); make
	cd $(TOP_DIR); make
endif
	$(CC) $(CFLAGS) -Iinclude $^ -o netwasabi $(LIBS)
