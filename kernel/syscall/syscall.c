// Minimal AArch64 syscall handler and helpers

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <lk/debug.h>
#include <lk/err.h>
#include <printf.h>

#include <arch/arm64.h>
#include <arch/ops.h>

#include <kernel/thread.h>
#include <kernel/syscalls.h>
#include <platform.h>

// local min helper
#define UMIN(a,b) (( (a) < (b) ) ? (a) : (b))

#if WITH_KERNEL_VM
#include <kernel/vm.h>
#include <arch/mmu.h>
#endif

// Forward-declare to override weak symbol in arch layer
void arm64_syscall(struct arm64_iframe_long *iframe, bool is_64bit);

#if WITH_KERNEL_VM
// Copy from user aspace into kernel buffer using physical mappings.
// Returns number of bytes copied or <0 on error.
static ssize_t user_copy_from(const vmm_aspace_t *uas, void *dst_k, vaddr_t src_u, size_t len) {
    if (!uas || !dst_k || len == 0) return 0;

    // Validate user range is within user aspace
    if (!is_user_address(src_u) || (len > 0 && !is_user_address(src_u + len - 1))) {
        return ERR_INVALID_ARGS;
    }

    size_t copied = 0;
    while (copied < len) {
        vaddr_t uva = src_u + copied;
        paddr_t pa = 0;
        uint flags = 0;
        status_t st = arch_mmu_query(&uas->arch_aspace, uva, &pa, &flags);
        if (st < 0) return st;
        if ((flags & ARCH_MMU_FLAG_PERM_USER) == 0) return ERR_ACCESS_DENIED;

        // bytes available until page end
        size_t page_off = uva & (PAGE_SIZE - 1);
        size_t chunk = UMIN(len - copied, PAGE_SIZE - page_off);

        // kernel mapping for this physical address
        void *kv = paddr_to_kvaddr((pa & ~(PAGE_SIZE - 1)) + page_off);
        if (!kv) return ERR_FAULT;

        memcpy((uint8_t *)dst_k + copied, kv, chunk);
        copied += chunk;
    }
    return (ssize_t)copied;
}
#endif

static long sys_exit_impl(long code) {
    // terminate current thread; in a full process model, would tear down process
    thread_exit((int)code);
    return 0;
}

static long sys_yield_impl(void) {
    thread_yield();
    return 0;
}

static long sys_write_impl(long fd, vaddr_t u_buf, size_t len) {
    if (len == 0) return 0;
    if (fd != 1 && fd != 2) return ERR_NOT_SUPPORTED;
#if WITH_KERNEL_VM
    thread_t *t = get_current_thread();
    if (!t || !t->aspace) return ERR_BAD_STATE;
    const size_t max_chunk = 1024;
    char tmp[1024];
    size_t total = 0;
    while (total < len) {
        size_t n = UMIN(max_chunk, len - total);
        ssize_t r = user_copy_from(t->aspace, tmp, u_buf + total, n);
        if (r < 0) return r;
        // Raw write: print bytes as-is
        for (ssize_t i = 0; i < r; i++) {
            putchar(tmp[i]);
        }
        total += (size_t)r;
    }
    return (long)total;
#else
    (void)u_buf; (void)len;
    return ERR_NOT_SUPPORTED;
#endif
}

static long sys_log_impl(vaddr_t u_buf, size_t len) {
    if (len == 0) return 0;
#if WITH_KERNEL_VM
    thread_t *t = get_current_thread();
    if (!t || !t->aspace) return ERR_BAD_STATE;
    const size_t max_chunk = 1024;
    char tmp[1024];
    size_t total = 0;
    while (total < len) {
        size_t n = UMIN(max_chunk, len - total);
        ssize_t r = user_copy_from(t->aspace, tmp, u_buf + total, n);
        if (r < 0) return r;
        for (ssize_t i = 0; i < r; i++) {
            putchar(tmp[i]);
        }
        total += (size_t)r;
    }
    return (long)total;
#else
    (void)u_buf; (void)len;
    return ERR_NOT_SUPPORTED;
#endif
}

static long sys_ticks_impl(void) {
    return (long)current_time_hires();
}

void arm64_syscall(struct arm64_iframe_long *iframe, bool is_64bit) {
    (void)is_64bit;
    uint64_t num = iframe->r[8];
    uint64_t a0 = iframe->r[0];
    uint64_t a1 = iframe->r[1];
    uint64_t a2 = iframe->r[2];
    long ret = ERR_NOT_SUPPORTED;

    switch (num) {
        case SYS_exit:
            sys_exit_impl((long)a0);
            __UNREACHABLE;
        case SYS_write:
            ret = sys_write_impl((long)a0, (vaddr_t)a1, (size_t)a2);
            break;
        case SYS_yield:
            ret = sys_yield_impl();
            break;
        case SYS_log:
            ret = sys_log_impl((vaddr_t)a0, (size_t)a1);
            break;
        case SYS_ticks:
            ret = sys_ticks_impl();
            break;
        default:
            ret = ERR_NOT_SUPPORTED;
            break;
    }

    iframe->r[0] = (uint64_t)ret; // return value in x0
}
