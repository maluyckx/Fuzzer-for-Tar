CC = gcc
CFLAGS = -Wall -Wextra -o3

TARGET = fuzzer
SRC = src/main.c src/utils.c
HEADER = src/constants.h src/utils.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)