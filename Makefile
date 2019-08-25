CFILES=main.c http.c cache.c buffer.c malloc.c
OBJ=main.o http.o cache.o buffer.o malloc.o
WFLAGS=-Wall -Werror
DEBUG:=0

.PHONY: clean

webreaper: $(OBJ)
	gcc $(WFLAGS) -o webreaper $(OBJ)

$(OBJ): $(CFILES)
ifeq ($(DEBUG),1)
	gcc $(WFLAGS) -g -c -DDEBUG $(CFILES)
else
	gcc $(WFLAGS) -c $(CFILES)
endif

clean:
	rm *.o
