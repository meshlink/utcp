CFLAGS ?= -O0 -Wall -g
CFLAGS += -std=c99

test: utcp.c test.c

selftest: utcp.c selftest.c

clean:
	rm -f *.o test selftest

.PHONY: clean
