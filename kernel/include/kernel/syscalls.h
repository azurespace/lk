// Minimal syscall interface for AArch64 userspace
// Numbers and prototypes kept intentionally small for MVP

#pragma once

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Syscall numbers (in x8)
enum {
    SYS_exit  = 0,
    SYS_write = 1,
    SYS_yield = 2,
    SYS_log   = 3,  // write to kernel log (no fd)
    SYS_ticks = 4,  // high-resolution ticks (lk_bigtime_t)
};

#ifdef __cplusplus
}
#endif
