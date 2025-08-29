// Minimal user-space syscall wrappers for AArch64 EL0
// These mirror kernel/include/kernel/syscalls.h numbers.

#pragma once

#include <stdint.h>
#include <stddef.h>

// Keep in sync with kernel/include/kernel/syscalls.h
enum {
    SYS_exit  = 0,
    SYS_write = 1,
    SYS_yield = 2,
    SYS_log   = 3,
    SYS_ticks = 4,
};

#if defined(__aarch64__)
static inline long sys_exit(long code) {
    register long x0 asm("x0") = code;
    register long x8 asm("x8") = SYS_exit;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0; // no return in practice
}

static inline long sys_write(int fd, const void *buf, size_t len) {
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)len;
    register long x8 asm("x8") = SYS_write;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

static inline long sys_log(const void *buf, size_t len) {
    register long x0 asm("x0") = (long)buf;
    register long x1 asm("x1") = (long)len;
    register long x8 asm("x8") = SYS_log;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}

static inline long sys_yield(void) {
    register long x0 asm("x0") = 0;
    register long x8 asm("x8") = SYS_yield;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline uint64_t sys_ticks(void) {
    register uint64_t x0 asm("x0");
    register long x8 asm("x8") = SYS_ticks;
    asm volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}
#else
#error "Provide syscall wrappers for this architecture"
#endif

// Optional tiny printf that formats in user space and writes via SYS_write.
// Requires a C library which provides vsnprintf in the EL0 image.
#if defined(__aarch64__)
#include <stdarg.h>
#if __has_include(<stdio.h>)
#include <stdio.h>
static inline int u_printf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t to_write = (n < (int)sizeof(buf)) ? (size_t)n : sizeof(buf);
        sys_write(1, buf, to_write);
    }
    return n;
}
#endif
#endif

