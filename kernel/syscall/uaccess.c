// uaccess helpers: safe copy between kernel and user address spaces

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <lk/debug.h>
#include <lk/err.h>

#include <arch/ops.h>
#include <arch/mmu.h>

#include <kernel/thread.h>
#include <kernel/vm.h>
#include <kernel/uaccess.h>

#define UMIN(a,b) (((a) < (b)) ? (a) : (b))

#if WITH_KERNEL_VM
// Internal helper: copy from user aspace into kernel buffer.
static ssize_t user_copy_from_aspace(const vmm_aspace_t *uas, void *dst_k, vaddr_t src_u, size_t len) {
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

// Internal helper: copy from kernel buffer into user aspace.
static ssize_t user_copy_to_aspace(const vmm_aspace_t *uas, vaddr_t dst_u, const void *src_k, size_t len) {
    if (!uas || !src_k || len == 0) return 0;

    // Validate user range is within user aspace
    if (!is_user_address(dst_u) || (len > 0 && !is_user_address(dst_u + len - 1))) {
        return ERR_INVALID_ARGS;
    }

    size_t copied = 0;
    while (copied < len) {
        vaddr_t uva = dst_u + copied;
        paddr_t pa = 0;
        uint flags = 0;
        status_t st = arch_mmu_query(&uas->arch_aspace, uva, &pa, &flags);
        if (st < 0) return st;
        if ((flags & ARCH_MMU_FLAG_PERM_USER) == 0) return ERR_ACCESS_DENIED;
        // Disallow writes to RO pages
        if (flags & ARCH_MMU_FLAG_PERM_RO) return ERR_ACCESS_DENIED;

        size_t page_off = uva & (PAGE_SIZE - 1);
        size_t chunk = UMIN(len - copied, PAGE_SIZE - page_off);

        void *kv = paddr_to_kvaddr((pa & ~(PAGE_SIZE - 1)) + page_off);
        if (!kv) return ERR_FAULT;

        memcpy(kv, (const uint8_t *)src_k + copied, chunk);
        copied += chunk;
    }
    return (ssize_t)copied;
}
#endif // WITH_KERNEL_VM

ssize_t copy_from_user(void *dst_k, vaddr_t src_u, size_t len) {
#if WITH_KERNEL_VM
    if (len == 0) return 0;
    thread_t *t = get_current_thread();
    if (!t || !t->aspace) return ERR_BAD_STATE;
    return user_copy_from_aspace(t->aspace, dst_k, src_u, len);
#else
    (void)dst_k; (void)src_u; (void)len;
    return ERR_NOT_SUPPORTED;
#endif
}

ssize_t copy_to_user(vaddr_t dst_u, const void *src_k, size_t len) {
#if WITH_KERNEL_VM
    if (len == 0) return 0;
    thread_t *t = get_current_thread();
    if (!t || !t->aspace) return ERR_BAD_STATE;
    return user_copy_to_aspace(t->aspace, dst_u, src_k, len);
#else
    (void)dst_u; (void)src_k; (void)len;
    return ERR_NOT_SUPPORTED;
#endif
}

