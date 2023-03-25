CC = gcc
CFLAGS = -Wall -Wextra -Werror

TARGET = fuzzer
SRC = main.c
HEADER = constants.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)