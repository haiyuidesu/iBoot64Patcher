.PHONY: all install clean

CC          = gcc
TARGET      = iBoot64Patcher
INSTALL     = /usr/local/bin

uname_s     = $(shell uname -s)

CFLAGS      = -DDEBUG -O3 -c -I. -g3 -Wall -Wextra -o

OBJECTS     = $(TARGET).o

default: all

all: $(TARGET)

%.o: %.c
	@echo "[INFO]: compiling $(TARGET)"
	@echo "CC	$<"
	@$(CC) $< $(CFLAGS) $@

$(TARGET): $(OBJECTS)
	@echo "LD	$(TARGET)"
	@$(CC) $(OBJECTS) -o $(TARGET)
	@echo "OK: built $(TARGET) for $(uname_s)"

install: $(TARGET)
	@install -v $(TARGET) $(INSTALL)
	@echo "OK: installed $(TARGET)."

clean:
	@rm -f *.o $(TARGET)
	@echo "OK: cleaned some files"
