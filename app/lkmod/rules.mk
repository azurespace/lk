LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/lkmod_cmd.c \
	$(LOCAL_DIR)/builtin_mod.c \

# Embed a prebuilt module blob (mods/hello_cpp/hello_cpp.so) into the image and
# auto-load it at boot. We convert the binary to a relocatable object using
# objcopy with binary input format. This produces symbols:
#   _binary_mods_hello_cpp_hello_cpp_so_start/_end/_size
HELLO_SO := mods/hello_cpp/hello_cpp.so
HELLO_SO_OBJ := $(call TOBUILDDIR,$(HELLO_SO)).o

# If the .so is missing or stale, build it using its own Makefile.
$(HELLO_SO):
	$(info building $@)
	$(NOECHO)$(MAKE) -C $(dir $@) CXX=$(TOOLCHAIN_PREFIX)g++

# Convert the binary to an ELF relocatable for our target.
$(HELLO_SO_OBJ): $(HELLO_SO)
	@$(MKDIR)
	$(info objcopy $< -> $@)
	$(NOECHO)$(OBJCOPY) -I binary -O elf64-littleaarch64 -B aarch64 $< $@

MODULE_EXTRA_OBJS += $(HELLO_SO_OBJ)

include make/module.mk
