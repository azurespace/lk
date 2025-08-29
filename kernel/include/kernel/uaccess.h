// Kernel uaccess helpers: copy between kernel and user address spaces
//
// These helpers validate EL0 ranges and permissions, then copy page-safely
// via physical mappings, never directly dereferencing user pointers.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <lk/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

// Copy bytes from a user pointer into a kernel buffer.
// Returns number of bytes copied or <0 on error.
ssize_t copy_from_user(void *dst_k, vaddr_t src_u, size_t len) __NONNULL((1));

// Copy bytes from a kernel buffer into a user pointer.
// Returns number of bytes copied or <0 on error.
ssize_t copy_to_user(vaddr_t dst_u, const void *src_k, size_t len) __NONNULL((2));

#ifdef __cplusplus
}
#endif

