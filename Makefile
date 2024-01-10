.PHONY: all install clean

CC          = gcc
TARGET      = iBoot64Patcher
INSTALL     = /usr/local/bin

CFLAGS      += -DDEBUG -I. -g3 -O3
CFLAGS      += -Wall -Wextra -Wno-format

SRC         := $(shell find . -name "*.c")
OBJECTS     := $(SRC:%.c=%.o)

default: all

all: $(TARGET)

%.o: %.c
	@echo "CC	$<"
	@$(CC) $< -c $(CFLAGS) -o $@

$(TARGET): $(OBJECTS)
	@echo "LD	$(TARGET)"
	@$(CC) $(OBJECTS) -o $(TARGET)
	@echo "[OK]: built $(TARGET) for $(shell uname -s)"

install: $(TARGET)
	@install -v $(TARGET) $(INSTALL)
	@echo "OK: installed $(TARGET)."

clean:
	@rm -f *.o $(TARGET)
	@echo "OK: cleaned some files"
