CFLAGS ?= -O0 -Wall -g
CFLAGS += -std=c99

BIN = selftest test

all: $(BIN)

test: utcp.c test.c

selftest: utcp.c selftest.c

clean:
	rm -f *.o $(BIN)

.PHONY: clean
