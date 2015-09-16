CFLAGS ?= -O2 -Wall -g
CFLAGS += -std=c99 -DUTCP_DEBUG

BIN = selftest test

all: $(BIN)

utcp.o: utcp.c

test: utcp.o test.c

selftest: utcp.o selftest.c

clean:
	rm -f *.o $(BIN)

.PHONY: clean
