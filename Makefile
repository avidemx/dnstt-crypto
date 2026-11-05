CC ?= $(CROSS_COMPILE)gcc
STRIP ?= $(CROSS_COMPILE)strip
CFLAGS ?= -O2 -Wall -Wextra -Werror
CFLAGS += -std=c99 -fPIC -Iinclude
LDFLAGS += -ldl

.PHONY: all clean test
all: dnstt-crypto

dnstt-crypto: src/main.o src/blake2s.o src/openssl_dyn.o
	$(CC) $(LDFLAGS) -o $@ $^

src/%.o: src/%.c include/dnstt_crypto.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: dnstt-crypto
	sh ./tests/smoke.sh ./dnstt-crypto

clean:
	rm -f src/*.o dnstt-crypto
