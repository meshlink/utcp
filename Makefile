CFLAGS ?= -O0 -Wall -g
CFLAGS += -std=c99

BIN = utest selftest test

all: $(BIN)
check: utest
	gtester -k utest

utcp.o: utcp.c utcp.h utcp_priv.h

test: utcp.o test.c

selftest: utcp.c selftest.c
	$(CC) -o $@ $^ $(CFLAGS) -DUTCP_DEBUG

utest: utcp.o utest.c
	$(CC) -o $@ $^ $(CFLAGS) `pkg-config glib-2.0 --cflags --libs`

clean:
	rm -f *.o $(BIN)

.PHONY: all check clean
