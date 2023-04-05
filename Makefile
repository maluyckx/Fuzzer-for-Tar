CC = gcc
CFLAGS = -Wall -Wextra -o3

TARGET = fuzzer
SRC = main.c utils.c
HEADER = constants.h utils.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)