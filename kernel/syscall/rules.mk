LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
    $(LOCAL_DIR)/syscall.c \
    $(LOCAL_DIR)/uaccess.c

MODULE_DEPS += \
    kernel \
    kernel/vm \
    lib/console \
    lib/libc

include make/module.mk
