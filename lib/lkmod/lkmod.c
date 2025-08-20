// Minimal runtime loader for AArch64 ET_DYN ELF modules with API table.
// Loads PIC shared objects, applies RELATIVE/ABS64 relocations, and
// resolves entry/exit symbols. No external imports are allowed.

#include <lk/err.h>
#include <lk/trace.h>
#include <lk/debug.h>
#include <lk/list.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <lib/elf_defines.h>
#include <lkmod/lkmod.h>

#include <lib/page_alloc.h>
#include <kernel/vm.h>
#include <kernel/thread.h>
#include <kernel/timer.h>
#include <kernel/mutex.h>
#include <platform/time.h>
#include <arch/ops.h>

#define LOCAL_TRACE 0

// Loader tuning and profiling
#ifndef LKMOD_PROFILE
#define LKMOD_PROFILE 1
#endif
#ifndef LKMOD_SYNC_ONLY_TEXT
#define LKMOD_SYNC_ONLY_TEXT 1
#endif


// AArch64 relocation types (not defined elsewhere in this tree)
#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE      0
#define R_AARCH64_ABS64     257
#define R_AARCH64_GLOB_DAT  1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE  1027
#endif

// Some toolchains in-tree define only Elf32_Dyn; provide Elf64_Dyn here.
struct Elf64_Dyn {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
};

// Provide Elf64_Sym here if not defined in headers
struct Elf64_Sym {
    Elf64_Word  st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
};

typedef int (*lkmod_init_fn)(const lkmod_api_t *api, void **handle_out);
typedef int (*lkmod_exit_fn)(void *handle);

struct lkmod_module {
    struct list_node node;
    char name[64];
    void *base;        // load base (mapped)
    size_t size;       // reserved span
    uint64_t minva;    // minimum virtual address of image (page aligned)
    bool use_vmm;      // true if mapped via vmm_alloc*
    size_t pages;      // page count if page_alloc used
    // dyn info
    struct Elf64_Sym *dynsym;
    const char *dynstr;
    size_t dynsym_count;
    // entry/exit
    lkmod_init_fn init;
    lkmod_exit_fn fini;
    void *user_handle; // module-provided handle
};

static struct list_node g_modules = LIST_INITIAL_VALUE(g_modules);
static mutex_t g_modules_lock = MUTEX_INITIAL_VALUE(g_modules_lock);

static uint64_t now_ticks(void) {
    return (uint64_t)current_time();
}

static void api_log(const char *msg) {
    if (msg) {
        printf("[mod] %s", msg);
    }
}

static void api_issue(int queue_id, void *command) {
    // Default stub: log the request; real platforms may route to a queue
    (void)command;
    printf("lkmod: issue(queue=%d, cmd=%p)\n", queue_id, command);
}

static lkmod_api_t default_api = {
    .log = api_log,
    .printf = printf,
    .alloc = malloc,
    .free = free,
    .ticks = now_ticks,
    .issue = api_issue,
};

static inline void *va_from_image(void *base, uint64_t min_vaddr, uint64_t vaddr) {
    return (uint8_t *)base + (vaddr - min_vaddr);
}


/* Flush instruction/data caches for executable regions only to reduce latency */
static void sync_exec_segments(void *base, uint64_t minva,
                               const struct Elf64_Ehdr *eh, const struct Elf64_Phdr *ph) {
#if LKMOD_SYNC_ONLY_TEXT
    if (!eh || !ph) return;
    for (uint i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if ((ph[i].p_flags & PF_X) == 0) continue;
        if (ph[i].p_memsz == 0) continue;
        void *seg = va_from_image(base, minva, ph[i].p_vaddr);
        arch_sync_cache_range((addr_t)seg, (size_t)ph[i].p_memsz);
    }
#else
    (void)base; (void)minva; (void)eh; (void)ph;
#endif
}
static status_t parse_and_load(const uint8_t *blob, size_t len, void **base_out, size_t *size_out,
                               struct Elf64_Dyn **dynamic_out, uint64_t *min_vaddr_out,
                               struct Elf64_Ehdr *ehdr_out, struct Elf64_Phdr **phdrs_out,
                               bool *used_vmm_out) {
    if (len < sizeof(struct Elf64_Ehdr)) {
        printf("lkmod: invalid ELF (too small)\n");
        return ERR_NOT_VALID;
    }
    const struct Elf64_Ehdr *eh = (const struct Elf64_Ehdr *)blob;
    if (memcmp(eh->e_ident, ELF_MAGIC, 4) != 0) { printf("lkmod: invalid ELF magic\n"); return ERR_NOT_VALID; }
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) { printf("lkmod: unsupported ELF class %u\n", eh->e_ident[EI_CLASS]); return ERR_NOT_VALID; }
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) { printf("lkmod: unsupported endianness\n"); return ERR_NOT_VALID; } // AArch64 LE only
    if (eh->e_machine != EM_AARCH64) { printf("lkmod: wrong machine %u (need AArch64)\n", eh->e_machine); return ERR_NOT_VALID; }
    if (eh->e_type != ET_DYN) { printf("lkmod: ELF type %u not supported (need ET_DYN)\n", eh->e_type); return ERR_NOT_SUPPORTED; }
    if (eh->e_phoff == 0 || eh->e_phnum == 0) { printf("lkmod: no program headers\n"); return ERR_NOT_VALID; }
    if (eh->e_phentsize != sizeof(struct Elf64_Phdr)) { printf("lkmod: bad phentsize %u\n", eh->e_phentsize); return ERR_NOT_VALID; }
    if (eh->e_ehsize != sizeof(struct Elf64_Ehdr)) { printf("lkmod: bad ehsize %u\n", eh->e_ehsize); return ERR_NOT_VALID; }

    if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(struct Elf64_Phdr) > len) {
        printf("lkmod: phdrs beyond blob length\n");
        return ERR_NOT_VALID;
    }
    const struct Elf64_Phdr *ph = (const struct Elf64_Phdr *)(blob + eh->e_phoff);

    // Compute load span
    uint64_t minva = UINT64_MAX, maxva = 0;
    for (uint i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_memsz == 0) continue;
        if (ph[i].p_vaddr < minva) minva = ph[i].p_vaddr;
        uint64_t end = ph[i].p_vaddr + ph[i].p_memsz;
        if (end > maxva) maxva = end;
    }
    if (minva == UINT64_MAX || maxva <= minva) { printf("lkmod: no PT_LOAD segments\n"); return ERR_NOT_FOUND; }

    // Page align
    uint64_t page_mask = PAGE_SIZE - 1;
    uint64_t span = (maxva - (minva & ~page_mask) + page_mask) & ~page_mask;
    size_t pages = span / PAGE_SIZE;

    void *base = NULL;
    bool used_vmm = false;
#if WITH_KERNEL_VM
    status_t err = vmm_alloc_contiguous(vmm_get_kernel_aspace(), "lkmod", span, &base,
                                        0, 0,
                                        ARCH_MMU_FLAG_CACHED /* RW, kernel-exec */);
    if (err < 0 || !base) {
        base = page_alloc(pages, PAGE_ALLOC_ANY_ARENA);
        if (!base) return ERR_NO_MEMORY;
    } else {
        used_vmm = true;
    }
#else
    base = page_alloc(pages, PAGE_ALLOC_ANY_ARENA);
    if (!base) return ERR_NO_MEMORY;
#endif
    memset(base, 0, span);

    // Copy PT_LOAD segments
    for (uint i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_filesz == 0 && ph[i].p_memsz == 0) continue;
        if (ph[i].p_offset + ph[i].p_filesz > len) {
            printf("lkmod: segment %u exceeds blob (offs=%" PRIu64 ", sz=%" PRIu64 ")\n", i, (uint64_t)ph[i].p_offset, (uint64_t)ph[i].p_filesz);
            page_free(base, pages);
            return ERR_NOT_VALID;
        }
        void *dst = va_from_image(base, minva & ~page_mask, ph[i].p_vaddr);
        memcpy(dst, blob + ph[i].p_offset, ph[i].p_filesz);
        if (ph[i].p_memsz > ph[i].p_filesz) {
            memset((uint8_t *)dst + ph[i].p_filesz, 0, ph[i].p_memsz - ph[i].p_filesz);
        }
    }

    // Find PT_DYNAMIC
    struct Elf64_Dyn *dynamic = NULL;
    for (uint i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dynamic = (struct Elf64_Dyn *)va_from_image(base, minva & ~page_mask, ph[i].p_vaddr);
            break;
        }
    }

    *base_out = base;
    *size_out = span;
    *dynamic_out = dynamic;
    *min_vaddr_out = (minva & ~page_mask);
    *ehdr_out = *eh;
    *phdrs_out = (struct Elf64_Phdr *)ph; // only for iteration fields (not used after)
    if (used_vmm_out) *used_vmm_out = used_vmm;
    return NO_ERROR;
}

static status_t do_relocations(void *base, size_t span, uint64_t minva, struct Elf64_Dyn *dyn,
                               struct Elf64_Sym **dynsym_out,
                               const char **dynstr_out, size_t *dynsym_count_out) {
    if (!dyn) return NO_ERROR; // no dynamic section → nothing to do

    uint64_t rela_addr = 0, rela_size = 0, rela_entsize = sizeof(struct Elf64_Rela);
    uint64_t jmprel_addr = 0, pltrel_size = 0;
    uint64_t symtab_addr = 0, strtab_addr = 0, strsz_val = 0;
    uint64_t hash_addr = 0; // SysV DT_HASH
    uint64_t gnu_hash_addr = 0; // GNU DT_GNU_HASH
    uint64_t syment_sz = sizeof(struct Elf64_Sym);

    for (struct Elf64_Dyn *d = dyn; d && d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_RELA:     rela_addr = d->d_un.d_ptr; break;
            case DT_RELASZ:   rela_size = d->d_un.d_val; break;
            case DT_RELAENT:  rela_entsize = d->d_un.d_val; break;
            case DT_JMPREL:   jmprel_addr = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrel_size = d->d_un.d_val; break;
            case DT_SYMTAB:   symtab_addr = d->d_un.d_ptr; break;
            case DT_STRTAB:   strtab_addr = d->d_un.d_ptr; break;
            case DT_STRSZ:    strsz_val = d->d_un.d_val; break;
            case DT_SYMENT:   syment_sz = d->d_un.d_val; break;
            case DT_HASH:     hash_addr = d->d_un.d_ptr; break;
            // Some toolchains emit GNU hash instead of SysV
            #ifndef DT_GNU_HASH
            #define DT_GNU_HASH 0x6ffffef5
            #endif
            case DT_GNU_HASH: gnu_hash_addr = d->d_un.d_ptr; break;
            default: break;
        }
    }

    if (symtab_addr && syment_sz == sizeof(struct Elf64_Sym)) {
        *dynsym_out = (struct Elf64_Sym *)va_from_image(base, minva, symtab_addr);
    } else {
        *dynsym_out = NULL;
    }
    *dynstr_out = (const char *)((strtab_addr) ? va_from_image(base, minva, strtab_addr) : NULL);

    // Attempt to compute dynsym count via DT_HASH (SysV): [nbucket, nchain, ...]
    size_t dynsym_count = 0;
    if (hash_addr) {
        uint32_t *hash = (uint32_t *)va_from_image(base, minva, hash_addr);
        uint32_t nbucket = hash[0];
        uint32_t nchain = hash[1];
        (void)nbucket;
        dynsym_count = nchain;
    } else if (gnu_hash_addr) {
        // Parse GNU hash to estimate dynsym_count = max(chain index) + 1
        // Layout: header[4] (nbuckets, symoffset, bloom_size, bloom_shift),
        // bloom[bloom_size], buckets[nbuckets], chains[...]
        uint32_t *gh = (uint32_t *)va_from_image(base, minva, gnu_hash_addr);
        uint32_t nbuckets = gh[0];
        uint32_t symoffset = gh[1];
        uint32_t bloom_size = gh[2];
        (void)bloom_size; // unused
        // bloom area starts at gh+4, then buckets, then chains
        uint32_t *buckets = gh + 4 + bloom_size * (sizeof(uint64_t) / sizeof(uint32_t));
        // Note: AArch64 uses 64-bit bloom filters
        // chains start after buckets
        uint32_t *chains = buckets + nbuckets;
        uint32_t max_index = 0;
        for (uint32_t i = 0; i < nbuckets; i++) {
            uint32_t idx = buckets[i];
            if (idx == 0) continue;
            if (idx < symoffset) continue; // should not happen, but guard
            // walk chain until LSB=1 (end of chain)
            for (uint32_t j = idx - symoffset; ; j++) {
                uint32_t val = chains[j];
                uint32_t real_index = symoffset + j;
                if (real_index > max_index) max_index = real_index;
                if (val & 1) break;
            }
        }
        if (max_index >= symoffset)
            dynsym_count = (size_t)max_index + 1;
    }

    // Helper to process a RELA range
    struct Elf64_Rela *rela;
    size_t bytes;

    // .rela.dyn
    rela = (struct Elf64_Rela *)((rela_addr) ? va_from_image(base, minva, rela_addr) : NULL);
    bytes = rela_size;
    if (rela && bytes) {
        size_t count = bytes / sizeof(struct Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = (uint32_t)ELF64_R_TYPE(rela[i].r_info);
            uint32_t symi = (uint32_t)ELF64_R_SYM(rela[i].r_info);
            uint8_t *where = (uint8_t *)va_from_image(base, minva, rela[i].r_offset);
            switch (type) {
                case R_AARCH64_RELATIVE: {
                    uint64_t load_bias = (uint64_t)((uintptr_t)base - minva);
                    uint64_t val = load_bias + (uint64_t)rela[i].r_addend;
                    *(uint64_t *)where = val;
                    break;
                }
                case R_AARCH64_ABS64: {
                    if (!*dynsym_out) return ERR_NOT_SUPPORTED;
                    const struct Elf64_Sym *s = &(*dynsym_out)[symi];
                    if (symi >= dynsym_count) dynsym_count = symi + 1;
                    if (s->st_shndx == SHN_UNDEF) {
                        const char *nm = (*dynstr_out && s) ? (*dynstr_out + s->st_name) : "<undef>";
                        printf("lkmod: undefined symbol '%s' in ABS64 relocation\n", nm);
                        return ERR_NOT_SUPPORTED;
                    }
                    uint64_t load_bias = (uint64_t)((uintptr_t)base - minva);
                    uint64_t S = (uint64_t)(s->st_value) + load_bias;
                    *(uint64_t *)where = S + (uint64_t)rela[i].r_addend;
                    break;
                }
                case R_AARCH64_JUMP_SLOT:
                case R_AARCH64_GLOB_DAT: {
                    if (!*dynsym_out) return ERR_NOT_SUPPORTED;
                    const struct Elf64_Sym *s = &(*dynsym_out)[symi];
                    if (symi >= dynsym_count) dynsym_count = symi + 1;
                    if (s->st_shndx == SHN_UNDEF) return ERR_NOT_SUPPORTED;
                    uint64_t load_bias = (uint64_t)((uintptr_t)base - minva);
                    uint64_t S = (uint64_t)(s->st_value) + load_bias;
                    *(uint64_t *)where = S + (uint64_t)rela[i].r_addend;
                    break;
                }
                case R_AARCH64_NONE:
                    break;
                default:
                    printf("lkmod: unsupported relocation type %u in .rela.dyn\n", type);
                    return ERR_NOT_SUPPORTED;
            }
        }
    }

    // .rela.plt
    rela = (struct Elf64_Rela *)((jmprel_addr) ? va_from_image(base, minva, jmprel_addr) : NULL);
    bytes = pltrel_size;
    if (rela && bytes) {
        size_t count = bytes / sizeof(struct Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = (uint32_t)ELF64_R_TYPE(rela[i].r_info);
            uint32_t symi = (uint32_t)ELF64_R_SYM(rela[i].r_info);
            uint8_t *where = (uint8_t *)va_from_image(base, minva, rela[i].r_offset);
            switch (type) {
                case R_AARCH64_JUMP_SLOT:
                case R_AARCH64_GLOB_DAT: {
                    if (!*dynsym_out) return ERR_NOT_SUPPORTED;
                    const struct Elf64_Sym *s = &(*dynsym_out)[symi];
                    if (symi >= dynsym_count) dynsym_count = symi + 1;
                    if (s->st_shndx == SHN_UNDEF) return ERR_NOT_SUPPORTED;
                    uint64_t load_bias = (uint64_t)((uintptr_t)base - minva);
                    uint64_t S = (uint64_t)(s->st_value) + load_bias;
                    *(uint64_t *)where = S + (uint64_t)rela[i].r_addend;
                    break;
                }
                case R_AARCH64_RELATIVE: {
                    uint64_t load_bias = (uint64_t)((uintptr_t)base - minva);
                    uint64_t val = load_bias + (uint64_t)rela[i].r_addend;
                    *(uint64_t *)where = val;
                    break;
                }
                case R_AARCH64_NONE:
                    break;
                default:
                    printf("lkmod: unsupported relocation type %u in .rela.plt\n", type);
                    return ERR_NOT_SUPPORTED;
            }
        }
    }

    *dynsym_count_out = dynsym_count;

    return NO_ERROR;
}

static void *find_symbol_addr(void *base, uint64_t minva, const struct Elf64_Sym *dynsym,
                              size_t dynsym_count, const char *dynstr, const char *name) {
    if (!dynsym || !dynstr || !name) return NULL;
    for (size_t i = 0; i < dynsym_count; i++) {
        const char *sname = dynstr + dynsym[i].st_name;
        if (sname && strcmp(sname, name) == 0) {
            return va_from_image(base, minva, dynsym[i].st_value);
        }
    }
    return NULL;
}

status_t lkmod_load_from_memory(const void *blob, size_t len, const lkmod_api_t *api,
                                lkmod_module_t **out_mod) {
    if (!blob || !out_mod) return ERR_INVALID_ARGS;
    *out_mod = NULL;

    void *base = NULL; size_t span = 0; struct Elf64_Dyn *dyn = NULL;
    uint64_t minva = 0; struct Elf64_Ehdr eh; struct Elf64_Phdr *ph = NULL; bool used_vmm = false;
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
#if LKMOD_PROFILE
    t0 = now_ticks();
#endif
    status_t st = parse_and_load((const uint8_t *)blob, len, &base, &span, &dyn, &minva, &eh, &ph, &used_vmm);
    if (st < 0) return st;

    struct Elf64_Sym *dynsym = NULL; const char *dynstr = NULL; size_t dynsym_count = 0;
    st = do_relocations(base, span, minva, dyn, &dynsym, &dynstr, &dynsym_count);
    if (st < 0) {
#if WITH_KERNEL_VM
        // try to detect how we allocated base: if it falls inside kernel aspace reserved regions
        // we can't reliably query here, so attempt vmm_free_region first; on failure, fall back
        if (vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)base) < 0) {
            page_free(base, span / PAGE_SIZE);
        }
#else
        page_free(base, span / PAGE_SIZE);
#endif
        return st;
    }

#if LKMOD_PROFILE
    t1 = now_ticks();
#endif

#if LKMOD_SYNC_ONLY_TEXT
    sync_exec_segments(base, minva, &eh, ph);
#else
    arch_sync_cache_range((addr_t)base, span);
#endif

#if LKMOD_PROFILE
    t2 = now_ticks();
#endif

    // Resolve entry: prefer symbol name if e_entry is unset
    lkmod_init_fn init = NULL;
    if (eh.e_entry) {
        init = (lkmod_init_fn)va_from_image(base, minva, eh.e_entry);
    }
    if (!init) {
        init = (lkmod_init_fn)find_symbol_addr(base, minva, dynsym, dynsym_count, dynstr, "lkmod_init");
    }
    lkmod_exit_fn fini = (lkmod_exit_fn)find_symbol_addr(base, minva, dynsym, dynsym_count, dynstr, "lkmod_exit");

    if (!init) {
        printf("lkmod: missing entry 'lkmod_init'\n");
        page_free(base, span / PAGE_SIZE);
        return ERR_NOT_FOUND;
    }

    lkmod_module_t *mod = (lkmod_module_t *)calloc(1, sizeof(*mod));
    if (!mod) { page_free(base, span / PAGE_SIZE); return ERR_NO_MEMORY; }
    list_clear_node(&mod->node);
    snprintf(mod->name, sizeof(mod->name), "module@%p", base);
    mod->base = base;
    mod->size = span;
    mod->dynsym = dynsym;
    mod->dynstr = dynstr;
    mod->dynsym_count = dynsym_count;
    mod->init = init;
    mod->fini = fini;
    mod->minva = minva;
    mod->pages = span / PAGE_SIZE;
    mod->use_vmm = used_vmm;

    const lkmod_api_t *use_api = api ? api : &default_api;
    void *user_handle = NULL;
    int rc = mod->init(use_api, &user_handle);
#if LKMOD_PROFILE
    t3 = now_ticks();
#endif
    if (rc != 0) {
        printf("lkmod: lkmod_init returned error %d\n", rc);
        page_free(base, span / PAGE_SIZE);
        free(mod);
        return ERR_GENERIC;
    }
    mod->user_handle = user_handle;

    mutex_acquire(&g_modules_lock);
    list_add_tail(&g_modules, &mod->node);
    mutex_release(&g_modules_lock);
    *out_mod = mod;
#if LKMOD_PROFILE
    printf("lkmod: load timings parse+reloc=%llu us, icache=%llu us, init=%llu us (total=%llu us)\n",
           (unsigned long long)(t1 - t0),
           (unsigned long long)(t2 - t1),
           (unsigned long long)(t3 - t2),
           (unsigned long long)(t3 - t0));
#endif
    return NO_ERROR;
}

status_t lkmod_unload(lkmod_module_t *mod) {
    if (!mod) return ERR_INVALID_ARGS;
    mutex_acquire(&g_modules_lock);
    list_delete(&mod->node);
    mutex_release(&g_modules_lock);
    if (mod->fini) {
        // Best-effort; assume success
        (void)mod->fini(mod->user_handle);
    }
    if (mod->use_vmm) {
        // ignore errors
        (void)vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)mod->base);
    } else {
        page_free(mod->base, mod->size / PAGE_SIZE);
    }
    free(mod);
    return NO_ERROR;
}

const char *lkmod_name(const lkmod_module_t *mod) { return mod ? mod->name : NULL; }
uintptr_t lkmod_base(const lkmod_module_t *mod) { return mod ? (uintptr_t)mod->base : 0; }
size_t lkmod_size(const lkmod_module_t *mod) { return mod ? mod->size : 0; }

uintptr_t lkmod_lookup(const lkmod_module_t *mod, const char *symname) {
    if (!mod || !symname || !mod->dynsym || !mod->dynstr) return 0;
    for (size_t i = 0; i < mod->dynsym_count; i++) {
        const char *sname = mod->dynstr + mod->dynsym[i].st_name;
        if (sname && strcmp(sname, symname) == 0) {
            return (uintptr_t)((uint8_t *)mod->base + (mod->dynsym[i].st_value - mod->minva));
        }
    }
    return 0;
}

status_t lkmod_call4(const lkmod_module_t *mod, const char *symname,
                     int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                     int64_t *ret_out) {
    if (!mod || !symname) return ERR_INVALID_ARGS;
    uintptr_t addr = lkmod_lookup(mod, symname);
    if (!addr) return ERR_NOT_FOUND;
    typedef int64_t (*fn_t)(int64_t,int64_t,int64_t,int64_t);
    fn_t fn = (fn_t)(addr);
    int64_t r = fn(a0, a1, a2, a3);
    if (ret_out) *ret_out = r;
    return NO_ERROR;
}

lkmod_module_t *lkmod_first_loaded(void) {
    mutex_acquire(&g_modules_lock);
    lkmod_module_t *m = list_peek_head_type(&g_modules, lkmod_module_t, node);
    mutex_release(&g_modules_lock);
    return m;
}

lkmod_module_t *lkmod_last_loaded(void) {
    mutex_acquire(&g_modules_lock);
    lkmod_module_t *m = list_peek_tail_type(&g_modules, lkmod_module_t, node);
    mutex_release(&g_modules_lock);
    return m;
}

lkmod_module_t *lkmod_next(lkmod_module_t *prev) {
    mutex_acquire(&g_modules_lock);
    lkmod_module_t *ret;
    if (!prev) {
        ret = list_peek_head_type(&g_modules, lkmod_module_t, node);
    } else {
        ret = list_next_type(&g_modules, &prev->node, lkmod_module_t, node);
    }
    mutex_release(&g_modules_lock);
    return ret;
}

lkmod_module_t *lkmod_find_by_name(const char *name) {
    if (!name) return NULL;
    mutex_acquire(&g_modules_lock);
    lkmod_module_t *m = list_peek_head_type(&g_modules, lkmod_module_t, node);
    while (m) {
        const char *n = lkmod_name(m);
        if (n && strcmp(n, name) == 0) {
            mutex_release(&g_modules_lock);
            return m;
        }
        m = list_next_type(&g_modules, &m->node, lkmod_module_t, node);
    }
    mutex_release(&g_modules_lock);
    return NULL;
}

const char *lkmod_status_str(status_t status) {
    switch (status) {
        case NO_ERROR: return "NO_ERROR";
        case ERR_NOT_VALID: return "ERR_NOT_VALID";
        case ERR_NOT_SUPPORTED: return "ERR_NOT_SUPPORTED";
        case ERR_NOT_FOUND: return "ERR_NOT_FOUND";
        case ERR_INVALID_ARGS: return "ERR_INVALID_ARGS";
        case ERR_NO_MEMORY: return "ERR_NO_MEMORY";
        case ERR_GENERIC: return "ERR_GENERIC";
        default: return "ERR_UNKNOWN";
    }
}
