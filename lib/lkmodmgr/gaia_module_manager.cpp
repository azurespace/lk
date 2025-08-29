// C++ slot-based module manager implementation over lib/lkmod.

#include <lkmod/gaia_module_manager.h>

#include <lk/trace.h>
#include <lk/debug.h>
#include <string.h>
#include <stdlib.h>

#include <arch/atomic.h>
#include <kernel/mutex.h>
#include <lib/page_alloc.h>
#include <kernel/vm.h>
#include <kernel/thread.h>
#include <kernel/uaccess.h>
#include <lkmod/lkmod_el0.h>
#include <lib/elf_defines.h>

#define LOCAL_TRACE 0

// --- EL0 helpers (prototype path) ---
namespace {
struct El0CallCtx {
    vmm_aspace_t *uas;
    vaddr_t entry_uva;    // code stub entry UVA
    vaddr_t user_sp;      // initial SP for user
};

static int el0_worker_thread(void *arg) {
    El0CallCtx *ctx = (El0CallCtx *)arg;
    if (!ctx || !ctx->uas || !ctx->entry_uva || !ctx->user_sp) return ERR_INVALID_ARGS;
    (void)vmm_set_active_aspace(ctx->uas);
    arch_enter_uspace(ctx->entry_uva, ctx->user_sp);
}

static status_t lookup_sym_uva_from_blob(const void *blob, size_t len,
                                         vaddr_t uva_base, uint64_t minva_page,
                                         const char *name, vaddr_t *out_uva) {
    if (!blob || !name || !out_uva) return ERR_INVALID_ARGS;
    *out_uva = 0;
    const uint8_t *p = (const uint8_t *)blob;
    if (len < sizeof(Elf64_Ehdr)) return ERR_NOT_VALID;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)p;
    if (memcmp(eh->e_ident, ELF_MAGIC, 4) != 0) return ERR_NOT_VALID;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return ERR_NOT_VALID;
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(p + eh->e_phoff);
    const Elf64_Dyn *dynamic = nullptr;
    size_t dyn_sz = 0;
    for (uint i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC && ph[i].p_memsz) {
            dynamic = (const Elf64_Dyn *)(p + ph[i].p_offset);
            dyn_sz = (size_t)ph[i].p_memsz;
            break;
        }
    }
    if (!dynamic || dyn_sz < sizeof(Elf64_Dyn)) return ERR_NOT_FOUND;
    uint64_t symtab_addr = 0, strtab_addr = 0, strsz_val = 0, syment_sz = sizeof(Elf64_Sym);
    uint64_t hash_addr = 0;
    for (size_t i = 0; i < dyn_sz / sizeof(Elf64_Dyn) && dynamic[i].d_tag != DT_NULL; i++) {
        switch (dynamic[i].d_tag) {
            case DT_SYMTAB: symtab_addr = dynamic[i].d_un.d_ptr; break;
            case DT_STRTAB: strtab_addr = dynamic[i].d_un.d_ptr; break;
            case DT_STRSZ:  strsz_val = dynamic[i].d_un.d_val; break;
            case DT_SYMENT: syment_sz = dynamic[i].d_un.d_val; break;
            case DT_HASH:   hash_addr = dynamic[i].d_un.d_ptr; break;
            default: break;
        }
    }
    if (!symtab_addr || !strtab_addr || syment_sz != sizeof(Elf64_Sym)) return ERR_NOT_SUPPORTED;
    const Elf64_Sym *dynsym = (const Elf64_Sym *)(p + (symtab_addr - minva_page));
    const char *dynstr = (const char *)(p + (strtab_addr - minva_page));
    size_t dynsym_count = 0;
    if (hash_addr) {
        const uint32_t *hash = (const uint32_t *)(p + (hash_addr - minva_page));
        dynsym_count = hash[1];
    } else {
        dynsym_count = 1024;
    }
    for (size_t i = 0; i < dynsym_count; i++) {
        const char *sname = dynstr + dynsym[i].st_name;
        if (sname && strcmp(sname, name) == 0) {
            *out_uva = uva_base + (dynsym[i].st_value - minva_page);
            return NO_ERROR;
        }
    }
    return ERR_NOT_FOUND;
}
} // namespace

struct GaiaModuleManager::Slot {
    void *blob = nullptr;
    size_t blob_size = 0;
    lkmod_module_t *mod = nullptr;
    SlotState state = SlotState::Empty;
    char entry_symbol[64] = {0};
    volatile int inflight_calls = 0;
    // EL0 path
    vmm_aspace_t *uas = nullptr;
    vaddr_t uva_base = 0;
    uint64_t minva_page = 0;
    size_t u_span = 0;
    vaddr_t entry_uva = 0;
};

// ---- Handle implementation ----
GaiaModuleManager::Handle::~Handle() {
    release();
}

void GaiaModuleManager::Handle::release() {
    if (!mgr_) return;
    GaiaModuleManager::Slot *s = &mgr_->slots_[slot_id_];
    atomic_add(&s->inflight_calls, -1);
    mgr_ = nullptr;
    slot_id_ = 0;
}

status_t GaiaModuleManager::Handle::call(const char *sym,
                                         int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                                         int64_t *ret_out) const {
    if (!mgr_) return ERR_BAD_STATE;
    return mgr_->call(slot_id_, sym, a0, a1, a2, a3, ret_out);
}

status_t GaiaModuleManager::init(const Config &cfg) {
    if (inited_) return ERR_BAD_STATE;
    if (cfg.slot_capacity == 0) return ERR_INVALID_ARGS;

    slot_capacity_ = cfg.slot_capacity;
    api_ = cfg.api;
    pool_owned_ = false;
    run_el0_ = cfg.run_el0;

    mutex_init(&lock_);

    if (cfg.pool_base) {
        if (cfg.pool_size == 0) return ERR_INVALID_ARGS;
        pool_ = cfg.pool_base;
        pool_size_ = cfg.pool_size;
        if (cfg.slot_count) {
            slot_count_ = cfg.slot_count;
            if ((size_t)slot_count_ * slot_capacity_ > pool_size_) {
                return ERR_OUT_OF_RANGE;
            }
        } else {
            slot_count_ = (uint32_t)(pool_size_ / slot_capacity_);
        }
        if (slot_count_ == 0) return ERR_NO_MEMORY;
    } else {
        if (cfg.slot_count == 0) return ERR_INVALID_ARGS;
        slot_count_ = cfg.slot_count;
        size_t want = (size_t)slot_count_ * slot_capacity_;
        size_t pages = (want + PAGE_SIZE - 1) / PAGE_SIZE;
        void *pool = page_alloc(pages, PAGE_ALLOC_ANY_ARENA);
        if (!pool) return ERR_NO_MEMORY;
        pool_ = pool;
        pool_size_ = pages * PAGE_SIZE;
        pool_owned_ = true;
    }

    // Allocate slot table
    slots_ = (Slot *)calloc(slot_count_, sizeof(Slot));
    if (!slots_) {
        if (pool_owned_ && pool_) page_free(pool_, pool_size_ / PAGE_SIZE);
        pool_ = nullptr;
        pool_size_ = 0;
        slot_count_ = 0;
        return ERR_NO_MEMORY;
    }

    // Wire blob pointers per slot
    uint8_t *base = (uint8_t *)pool_;
    for (uint32_t i = 0; i < slot_count_; i++) {
        slots_[i].blob = base + (size_t)i * slot_capacity_;
        slots_[i].blob_size = 0;
        slots_[i].state = SlotState::Empty;
        slots_[i].mod = nullptr;
        slots_[i].entry_symbol[0] = '\0';
        slots_[i].inflight_calls = 0;
        slots_[i].uas = nullptr;
        slots_[i].uva_base = 0;
        slots_[i].minva_page = 0;
        slots_[i].u_span = 0;
        slots_[i].entry_uva = 0;
    }

    inited_ = true;
    return NO_ERROR;
}

GaiaModuleManager::~GaiaModuleManager() {
    if (inited_) {
        (void)shutdown();
    }
}

status_t GaiaModuleManager::shutdown() {
    if (!inited_) return ERR_BAD_STATE;
    status_t ret = NO_ERROR;
    // Attempt to unload all loaded modules without blocking ongoing calls.
    mutex_acquire(&lock_);
    for (uint32_t i = 0; i < slot_count_; i++) {
        Slot &s = slots_[i];
        if (s.state == SlotState::Loaded && s.mod) {
            if (s.inflight_calls != 0) {
                ret = ERR_BUSY; // caller should ensure no active users
                continue;
            }
            lkmod_module_t *m = s.mod;
            s.mod = nullptr;
            s.state = (s.blob_size > 0) ? SlotState::Registered : SlotState::Empty;
            mutex_release(&lock_);
            (void)lkmod_unload(m);
            mutex_acquire(&lock_);
        }
    }
    mutex_release(&lock_);

    if (ret == NO_ERROR) {
        if (pool_owned_ && pool_) {
            page_free(pool_, pool_size_ / PAGE_SIZE);
        }
        free(slots_);
        slots_ = nullptr;
        pool_ = nullptr;
        pool_size_ = 0;
        slot_count_ = 0;
        inited_ = false;
    }
    return ret;
}

status_t GaiaModuleManager::register_blob(uint32_t slot_id, const void *blob, size_t len, bool overwrite) {
    if (!valid_slot(slot_id) || !blob || len == 0) return ERR_INVALID_ARGS;
    if (len > slot_capacity_) return ERR_TOO_BIG;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state == SlotState::Loaded) { mutex_release(&lock_); return ERR_BUSY; }
    if (s.state == SlotState::Registered && !overwrite) { mutex_release(&lock_); return ERR_ALREADY_EXISTS; }
    memcpy(s.blob, blob, len);
    s.blob_size = len;
    s.state = SlotState::Registered;
    mutex_release(&lock_);
    return NO_ERROR;
}

status_t GaiaModuleManager::unregister_blob(uint32_t slot_id) {
    if (!valid_slot(slot_id)) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state == SlotState::Loaded) { mutex_release(&lock_); return ERR_BUSY; }
    s.blob_size = 0;
    s.state = SlotState::Empty;
    mutex_release(&lock_);
    return NO_ERROR;
}

status_t GaiaModuleManager::load(uint32_t slot_id) {
    if (!valid_slot(slot_id)) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state == SlotState::Loaded) { mutex_release(&lock_); return ERR_ALREADY_EXISTS; }
    if (s.blob_size == 0) { mutex_release(&lock_); return ERR_NOT_FOUND; }
    const void *blob = s.blob;
    size_t len = s.blob_size;
    mutex_release(&lock_);

    if (!run_el0_) {
        lkmod_module_t *mod = nullptr;
        status_t st = lkmod_load_from_memory(blob, len, api_, &mod);
        if (st < 0) return st;
        mutex_acquire(&lock_);
        s.mod = mod;
        s.state = SlotState::Loaded;
        mutex_release(&lock_);
        return NO_ERROR;
    } else {
        // Create a fresh user aspace for this slot and load the image
        vmm_aspace_t *uas = nullptr;
        char nm[32];
        snprintf(nm, sizeof(nm), "lkmod-el0-%u", slot_id);
        status_t st = vmm_create_aspace(&uas, nm, 0);
        if (st < 0 || !uas) return (st < 0) ? st : ERR_NO_MEMORY;

        vaddr_t uva_base = 0, entry_uva = 0;
        uint64_t minva_page = 0;
        size_t span = 0;
        st = lkmod_el0_load_image(uas, blob, len, &uva_base, &minva_page, &span, &entry_uva);
        if (st < 0) {
            (void)vmm_free_aspace(uas);
            return st;
        }
        mutex_acquire(&lock_);
        s.uas = uas;
        s.uva_base = uva_base;
        s.minva_page = minva_page;
        s.u_span = span;
        s.entry_uva = entry_uva;
        s.mod = nullptr;
        s.state = SlotState::Loaded;
        mutex_release(&lock_);
        return NO_ERROR;
    }
}

status_t GaiaModuleManager::unload(uint32_t slot_id) {
    if (!valid_slot(slot_id)) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state != SlotState::Loaded) { mutex_release(&lock_); return ERR_NOT_FOUND; }
    if (!run_el0_ && !s.mod) { mutex_release(&lock_); return ERR_NOT_FOUND; }
    if (s.inflight_calls != 0) { mutex_release(&lock_); return ERR_BUSY; }
    if (!run_el0_) {
        lkmod_module_t *mod = s.mod;
        s.mod = nullptr;
        s.state = (s.blob_size > 0) ? SlotState::Registered : SlotState::Empty;
        mutex_release(&lock_);
        return lkmod_unload(mod);
    } else {
        vmm_aspace_t *uas = s.uas;
        s.uas = nullptr;
        s.uva_base = 0;
        s.minva_page = 0;
        s.u_span = 0;
        s.entry_uva = 0;
        s.state = (s.blob_size > 0) ? SlotState::Registered : SlotState::Empty;
        mutex_release(&lock_);
        if (uas) return vmm_free_aspace(uas);
        return NO_ERROR;
    }
}

status_t GaiaModuleManager::set_entry(uint32_t slot_id, const char *symbol) {
    if (!valid_slot(slot_id)) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (!symbol) {
        s.entry_symbol[0] = '\0';
    } else {
        size_t n = strnlen(symbol, sizeof(s.entry_symbol) - 1);
        memcpy(s.entry_symbol, symbol, n);
        s.entry_symbol[n] = '\0';
    }
    mutex_release(&lock_);
    return NO_ERROR;
}

const char *GaiaModuleManager::get_entry(uint32_t slot_id) const {
    if (!valid_slot(slot_id)) return nullptr;
    mutex_acquire(&lock_);
    const char *ret = (slots_[slot_id].entry_symbol[0] != '\0') ? slots_[slot_id].entry_symbol : nullptr;
    mutex_release(&lock_);
    return ret;
}

status_t GaiaModuleManager::call(uint32_t slot_id, const char *sym,
                                 int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                                 int64_t *ret_out) {
    if (!valid_slot(slot_id) || !sym) return ERR_INVALID_ARGS;
    Slot *s = &slots_[slot_id];
    if (s->state != SlotState::Loaded) return ERR_NOT_FOUND;
    if (!run_el0_ && !s->mod) return ERR_NOT_FOUND;

    if (run_el0_) {
        // Pin while in-flight
        atomic_add(&s->inflight_calls, 1);
        // Resolve target function UVA from the original blob
        vaddr_t func_uva = 0;
        status_t lst = lookup_sym_uva_from_blob(s->blob, s->blob_size,
                                                s->uva_base, s->minva_page,
                                                sym, &func_uva);
        if (lst < 0 || func_uva == 0) { atomic_add(&s->inflight_calls, -1); return ERR_NOT_FOUND; }

        // Allocate per-call resources in user aspace
        vaddr_t code_uva = 0, stack_uva = 0, retbuf_uva = 0;
        size_t stack_sz = 16 * 1024; // 16 KiB
        uint flags_rx = ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_USER; // user-exec allowed
        uint flags_rw = ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE;
        status_t stc = vmm_alloc(s->uas, "el0-call-code", PAGE_SIZE, (void **)&code_uva, 0, 0, flags_rx);
        if (stc < 0 || !code_uva) { atomic_add(&s->inflight_calls, -1); return (stc < 0) ? stc : ERR_NO_MEMORY; }
        status_t sts = vmm_alloc(s->uas, "el0-call-stack", stack_sz, (void **)&stack_uva, 0, 0, flags_rw);
        if (sts < 0 || !stack_uva) { (void)vmm_free_region(s->uas, code_uva); atomic_add(&s->inflight_calls, -1); return (sts < 0) ? sts : ERR_NO_MEMORY; }
        status_t str = vmm_alloc(s->uas, "el0-call-ret", PAGE_SIZE, (void **)&retbuf_uva, 0, 0, flags_rw);
        if (str < 0 || !retbuf_uva) { (void)vmm_free_region(s->uas, code_uva); (void)vmm_free_region(s->uas, stack_uva); atomic_add(&s->inflight_calls, -1); return (str < 0) ? str : ERR_NO_MEMORY; }

        // Encode a tiny stub that loads args from [sp] and calls x5, stores ret to [x4], exits
        uint32_t stub[] = {
            0xF94003E0, // ldr x0, [sp,#0]
            0xF94007E1, // ldr x1, [sp,#8]
            0xF9400BE2, // ldr x2, [sp,#16]
            0xF9400FE3, // ldr x3, [sp,#24]
            0xF94013E4, // ldr x4, [sp,#32]  ; retbuf UVA
            0xF94017E5, // ldr x5, [sp,#40]  ; func UVA
            0xD63F00A0, // blr x5
            0xF9000080, // str x0, [x4]
            0xD2800000, // mov x0, #0
            0xD2800008, // mov x8, #0 (SYS_exit)
            0xD4000001, // svc #0
        };
        ssize_t wc = copy_to_user(code_uva, stub, sizeof(stub));
        if (wc < 0 || (size_t)wc != sizeof(stub)) {
            (void)vmm_free_region(s->uas, code_uva);
            (void)vmm_free_region(s->uas, stack_uva);
            (void)vmm_free_region(s->uas, retbuf_uva);
            atomic_add(&s->inflight_calls, -1);
            return (wc < 0) ? (status_t)wc : ERR_IO;
        }

        // Prepare initial stack contents: a0..a3, retbuf UVA, func UVA
        uint64_t params[6];
        params[0] = (uint64_t)a0;
        params[1] = (uint64_t)a1;
        params[2] = (uint64_t)a2;
        params[3] = (uint64_t)a3;
        params[4] = (uint64_t)retbuf_uva;
        params[5] = (uint64_t)func_uva;
        vaddr_t sp = (stack_uva + stack_sz);
        sp = ROUNDDOWN(sp, 16) - sizeof(params);
        ssize_t ws = copy_to_user(sp, params, sizeof(params));
        if (ws < 0 || (size_t)ws != sizeof(params)) {
            (void)vmm_free_region(s->uas, code_uva);
            (void)vmm_free_region(s->uas, stack_uva);
            (void)vmm_free_region(s->uas, retbuf_uva);
            atomic_add(&s->inflight_calls, -1);
            return (ws < 0) ? (status_t)ws : ERR_IO;
        }

        // Spawn a worker thread to enter user mode and run the stub
        El0CallCtx ctx{.uas = s->uas, .entry_uva = code_uva, .user_sp = sp};
        thread_t *t = thread_create("el0-call", &el0_worker_thread, &ctx, HIGH_PRIORITY, DEFAULT_STACK_SIZE);
        if (!t) {
            (void)vmm_free_region(s->uas, code_uva);
            (void)vmm_free_region(s->uas, stack_uva);
            (void)vmm_free_region(s->uas, retbuf_uva);
            atomic_add(&s->inflight_calls, -1);
            return ERR_NO_MEMORY;
        }
        thread_resume(t);
        int exitcode = 0;
        (void)thread_join(t, &exitcode, INFINITE_TIME);

        // Read the return value
        uint64_t rv = 0;
        ssize_t rr = copy_from_user(&rv, retbuf_uva, sizeof(rv));
        // Free temp regions
        (void)vmm_free_region(s->uas, code_uva);
        (void)vmm_free_region(s->uas, stack_uva);
        (void)vmm_free_region(s->uas, retbuf_uva);

        if (rr < 0 || (size_t)rr != sizeof(rv)) {
            atomic_add(&s->inflight_calls, -1);
            return (rr < 0) ? (status_t)rr : ERR_IO;
        }
        if (ret_out) *ret_out = (int64_t)rv;
        atomic_add(&s->inflight_calls, -1);
        return NO_ERROR;
    }

    atomic_add(&s->inflight_calls, 1);
    status_t st = lkmod_call4(s->mod, sym, a0, a1, a2, a3, ret_out);
    atomic_add(&s->inflight_calls, -1);
    return st;
}

status_t GaiaModuleManager::call_entry(uint32_t slot_id,
                                       int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                                       int64_t *ret_out) {
    const char *sym = get_entry(slot_id);
    if (!sym) return ERR_NOT_FOUND;
    return call(slot_id, sym, a0, a1, a2, a3, ret_out);
}

status_t GaiaModuleManager::get_info(uint32_t slot_id, Info *out) const {
    if (!valid_slot(slot_id) || !out) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    const Slot &s = slots_[slot_id];
    out->state = s.state;
    out->blob_size = s.blob_size;
    out->blob_capacity = slot_capacity_;
    out->entry_symbol = (s.entry_symbol[0] != '\0') ? s.entry_symbol : nullptr;
    out->mod = s.mod;
    if (!run_el0_) {
        out->mod_base = s.mod ? lkmod_base(s.mod) : 0;
        out->mod_size = s.mod ? lkmod_size(s.mod) : 0;
    } else {
        out->mod_base = s.uva_base;
        out->mod_size = s.u_span;
    }
    out->inflight_calls = (uint32_t)s.inflight_calls;
    mutex_release(&lock_);
    return NO_ERROR;
}

GaiaModuleManager::Handle GaiaModuleManager::acquire(uint32_t slot_id) {
    Handle h; // empty by default
    if (!valid_slot(slot_id)) return h;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state == SlotState::Loaded && s.mod) {
        atomic_add(&s.inflight_calls, 1);
        h = Handle(this, slot_id);
    }
    mutex_release(&lock_);
    return h;
}

status_t GaiaModuleManager::acquire(uint32_t slot_id, Handle *out) {
    if (!out) return ERR_INVALID_ARGS;
    *out = Handle();
    if (!valid_slot(slot_id)) return ERR_INVALID_ARGS;
    mutex_acquire(&lock_);
    Slot &s = slots_[slot_id];
    if (s.state != SlotState::Loaded || !s.mod) {
        mutex_release(&lock_);
        return ERR_NOT_FOUND;
    }
    atomic_add(&s.inflight_calls, 1);
    *out = Handle(this, slot_id);
    mutex_release(&lock_);
    return NO_ERROR;
}
