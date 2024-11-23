CC = clang
TARGET = ./bin/test
NUM_OTS ?= 20
NUM_OTS_POW = $(shell echo $$((1<<$(NUM_OTS))))
CFLAGS = -O3 -I./include -I../pr -I/opt/homebrew/opt/openssl/include -DNUM_OTS=$(NUM_OTS_POW)
LDFLAGS = -march=native -L/opt/homebrew/opt/openssl/lib -lcrypto -lssl -lm -maes -ffast-math

SRC = $(wildcard ./src/*.c)

OBJECTS = $(SRC:.c=.o)

$(TARGET): $(OBJECTS)
	@mkdir -p ./bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: all clean