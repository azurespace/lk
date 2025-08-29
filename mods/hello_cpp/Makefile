# Build AArch64 LK C++ module (PIC ET_DYN)

TARGET ?= hello_cpp.so
SRC := hello.cpp

# Choose toolchain: aarch64-elf-g++ or clang++ --target=aarch64-unknown-elf
CXX ?= aarch64-elf-g++
OBJCOPY ?= aarch64-elf-objcopy

# Build toggles
#  DEBUG=1         -> add -g -O0 -fno-omit-frame-pointer
#  SEPDEBUG=1      -> emit separate debug file: $(TARGET).debug
#  STRIP=1         -> strip debug from $(TARGET) (keeps builtin small)
DEBUG ?= 0
SEPDEBUG ?= 1
STRIP ?= 1

CXXFLAGS ?=
CXXFLAGS += -fPIC -ffreestanding -Os -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -pipe -I../api
ifeq ($(DEBUG),1)
CXXFLAGS += -g -O0 -fno-omit-frame-pointer
endif

LDFLAGS ?= -shared -nostdlib -Wl,-z,notext -Wl,-Bsymbolic -Wl,-e,lkmod_init

SO_DEBUG := $(TARGET).debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Built $@ (DEBUG=$(DEBUG))"
	@if [ "$(SEPDEBUG)" = "1" ]; then \
		$(OBJCOPY) --only-keep-debug $@ $(SO_DEBUG); \
		echo "Wrote $(SO_DEBUG)"; \
	fi
	@if [ "$(STRIP)" = "1" ]; then \
		$(OBJCOPY) --strip-debug $@; \
		echo "Stripped debug from $@"; \
	fi

clean:
	rm -f $(TARGET) $(SO_DEBUG) *.o

.PHONY: all clean
