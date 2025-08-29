LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/gaia_module_manager.cpp \

GLOBAL_INCLUDES += $(LOCAL_DIR)/include

include make/module.mk

