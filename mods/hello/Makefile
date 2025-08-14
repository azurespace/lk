# Simple Makefile to build AArch64 LK module (PIC ET_DYN)

TARGET ?= hello.so
SRC := hello.c

# Choose toolchain: aarch64-elf-gcc or clang --target=aarch64-unknown-elf
CC ?= aarch64-elf-gcc

CFLAGS ?= -fPIC -ffreestanding -Os -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -pipe
LDFLAGS ?= -shared -nostdlib -Wl,-z,notext -Wl,-Bsymbolic -Wl,-e,lkmod_init

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $@"

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
