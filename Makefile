CFLAGS ?= -Og -Wall -g
CFLAGS += -std=c99 -DUTCP_DEBUG

BIN = selftest test unittest

all: $(BIN)

utcp.o: utcp.c utcp.h utcp_priv.h compat.h

list.o: list.c list.h

test: utcp.o list.o test.c

selftest: utcp.o list.o selftest.c

unittest: utcp.o list.o unittest.c

clean:
	rm -f *.o $(BIN)

.PHONY: clean
