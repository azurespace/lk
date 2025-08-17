LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/lkmod.c \

GLOBAL_INCLUDES += $(LOCAL_DIR)/include
GLOBAL_INCLUDES += lib/elf/include

include make/module.mk
