# Build AArch64 LK C++ module (PIC ET_DYN)

TARGET ?= hello_cpp.so
SRC := hello.cpp

# Choose toolchain: aarch64-elf-g++ or clang++ --target=aarch64-unknown-elf
CXX ?= aarch64-elf-g++

CXXFLAGS ?= -fPIC -ffreestanding -Os -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -pipe -I../api
LDFLAGS ?= -shared -nostdlib -Wl,-z,notext -Wl,-Bsymbolic -Wl,-e,lkmod_init

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $@"

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
