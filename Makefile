CFLAGS ?= -O0 -Wall -g
CFLAGS += -std=c99 -DUTCP_DEBUG

BIN = selftest test

all: $(BIN)

utcp.o: utcp.c utcp.h utcp_priv.h

test: utcp.o test.c

selftest: utcp.o selftest.c

clean:
	rm -f *.o $(BIN)

.PHONY: clean
