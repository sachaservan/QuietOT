CC = clang
TARGET = ./bin/test
CFLAGS = -O3 -I./include -I../pr -I/opt/homebrew/opt/openssl/include 
LDFLAGS = -march=native -lcrypto -lssl -lm -maes -ffast-math

ifeq ($(AVX),1)
 CFLAGS += -DAVX -mavx512f
 LDFLAGS += -mavx512f
endif

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