// Minimal user-aspace loader for AArch64 ET_DYN modules.
// Copies PT_LOAD segments into a provided user aspace, applies RELATIVE/ABS64/
// JUMP_SLOT/GLOB_DAT relocations, and exposes the entry UVA.

#include <lk/err.h>
#include <lk/trace.h>
#include <lk/debug.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <printf.h>

#include <lib/elf_defines.h>

#include <kernel/vm.h>
#include <kernel/uaccess.h>
#include <arch/mmu.h>
#include <arch/ops.h>

#include <lkmod/lkmod_el0.h>

#define LOCAL_TRACE 0

#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE      0
#define R_AARCH64_ABS64     257
#define R_AARCH64_GLOB_DAT  1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE  1027
#endif

static inline vaddr_t uva_from_vaddr(vaddr_t uva_base, uint64_t minva_page, uint64_t vaddr) {
    return uva_base + (vaddr - minva_page);
}

static status_t validate_elf64_aarch64(const uint8_t *blob, size_t len,
                                       struct Elf64_Ehdr *eh_out) {
    if (len < sizeof(struct Elf64_Ehdr)) return ERR_NOT_VALID;
    const struct Elf64_Ehdr *eh = (const struct Elf64_Ehdr *)blob;
    if (memcmp(eh->e_ident, ELF_MAGIC, 4) != 0) return ERR_NOT_VALID;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return ERR_NOT_SUPPORTED;
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) return ERR_NOT_SUPPORTED;
    if (eh->e_machine != EM_AARCH64) return ERR_NOT_SUPPORTED;
    if (eh->e_type != ET_DYN) return ERR_NOT_SUPPORTED;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return ERR_NOT_VALID;
    if (eh->e_phentsize != sizeof(struct Elf64_Phdr)) return ERR_NOT_VALID;
    if (eh->e_ehsize != sizeof(struct Elf64_Ehdr)) return ERR_NOT_VALID;
    *eh_out = *eh;
    return NO_ERROR;
}

status_t lkmod_el0_load_image(vmm_aspace_t *uas,
                              const void *blob, size_t len,
                              vaddr_t *uva_base_out,
                              uint64_t *minva_out,
                              size_t *span_out,
                              vaddr_t *entry_uva_out) {
    if (!uas || !blob || len < sizeof(struct Elf64_Ehdr)) return ERR_INVALID_ARGS;
    if (uva_base_out) *uva_base_out = 0;
    if (minva_out) *minva_out = 0;
    if (span_out) *span_out = 0;
    if (entry_uva_out) *entry_uva_out = 0;

    const uint8_t *p = (const uint8_t *)blob;
    struct Elf64_Ehdr eh;
    status_t st = validate_elf64_aarch64(p, len, &eh);
    if (st < 0) return st;

    const struct Elf64_Phdr *ph = (const struct Elf64_Phdr *)(p + eh.e_phoff);
    // Compute min/max VA of PT_LOAD
    uint64_t minva = UINT64_MAX, maxva = 0;
    for (uint i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_memsz == 0) continue;
        if (ph[i].p_vaddr < minva) minva = ph[i].p_vaddr;
        uint64_t end = ph[i].p_vaddr + ph[i].p_memsz;
        if (end > maxva) maxva = end;
    }
    if (minva == UINT64_MAX || maxva <= minva) return ERR_NOT_FOUND;

    const uint64_t page_mask = PAGE_SIZE - 1;
    const uint64_t minva_page = (minva & ~page_mask);
    const size_t span = (size_t)(((maxva - minva_page) + page_mask) & ~page_mask);

    // Allocate a single contiguous RWX user region for simplicity (prototype).
    // NOTE: For finer permissions, split per segment and use RO/RX appropriately.
    vaddr_t uva_base = 0;
    uint arch_flags = ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_USER; // executable for user
    st = vmm_alloc(uas, "lkmod-el0-image", span, (void **)&uva_base, 0, 0, arch_flags);
    if (st < 0 || !uva_base) return (st < 0) ? st : ERR_NO_MEMORY;

    // Temporarily make this aspace active so copy_to/from_user use it
    vmm_aspace_t *old_as = vmm_set_active_aspace(uas);

    // Copy PT_LOAD segments into UVA
    for (uint i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_filesz == 0 && ph[i].p_memsz == 0) continue;
        if (ph[i].p_offset + ph[i].p_filesz > len) {
            (void)vmm_set_active_aspace(old_as);
            return ERR_NOT_VALID;
        }
        vaddr_t dst_uva = uva_from_vaddr(uva_base, minva_page, ph[i].p_vaddr);
        const void *src = p + ph[i].p_offset;
        if (ph[i].p_filesz) {
            ssize_t wr = copy_to_user(dst_uva, src, (size_t)ph[i].p_filesz);
            if (wr < 0 || (size_t)wr != ph[i].p_filesz) { (void)vmm_set_active_aspace(old_as); return (wr < 0) ? (status_t)wr : ERR_IO; }
        }
        size_t bss = (ph[i].p_memsz > ph[i].p_filesz) ? (size_t)(ph[i].p_memsz - ph[i].p_filesz) : 0;
        if (bss) {
            static const uint8_t zero[64] = {0};
            size_t off = 0;
            while (off < bss) {
                size_t n = bss - off;
                if (n > sizeof(zero)) n = sizeof(zero);
                ssize_t wr = copy_to_user(dst_uva + ph[i].p_filesz + off, zero, n);
                if (wr < 0 || (size_t)wr != n) { (void)vmm_set_active_aspace(old_as); return (wr < 0) ? (status_t)wr : ERR_IO; }
                off += n;
            }
        }
    }

    // Find PT_DYNAMIC and parse entries from UVA (copied data)
    vaddr_t dyn_uva = 0;
    size_t dyn_size = 0;
    for (uint i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC && ph[i].p_memsz) {
            dyn_uva = uva_from_vaddr(uva_base, minva_page, ph[i].p_vaddr);
            dyn_size = (size_t)ph[i].p_memsz;
            break;
        }
    }

    uint64_t rela_addr = 0, rela_size = 0, rela_entsize = sizeof(struct Elf64_Rela);
    uint64_t jmprel_addr = 0, pltrel_size = 0;
    uint64_t symtab_addr = 0, strtab_addr = 0, strsz_val = 0;
    uint64_t hash_addr = 0, gnu_hash_addr = 0;
    uint64_t syment_sz = sizeof(struct Elf64_Sym);

    if (dyn_uva && dyn_size >= sizeof(struct Elf64_Dyn)) {
        // Copy whole DYNAMIC into temp buffer
        struct Elf64_Dyn *dynbuf = (struct Elf64_Dyn *)malloc(dyn_size);
        if (!dynbuf) { (void)vmm_set_active_aspace(old_as); return ERR_NO_MEMORY; }
        ssize_t rd = copy_from_user(dynbuf, dyn_uva, dyn_size);
        if (rd < 0 || (size_t)rd != dyn_size) { free(dynbuf); (void)vmm_set_active_aspace(old_as); return (rd < 0) ? (status_t)rd : ERR_IO; }
        for (size_t i = 0; i < dyn_size / sizeof(struct Elf64_Dyn); i++) {
            switch (dynbuf[i].d_tag) {
                case DT_RELA:     rela_addr = dynbuf[i].d_un.d_ptr; break;
                case DT_RELASZ:   rela_size = dynbuf[i].d_un.d_val; break;
                case DT_RELAENT:  rela_entsize = dynbuf[i].d_un.d_val; break;
                case DT_JMPREL:   jmprel_addr = dynbuf[i].d_un.d_ptr; break;
                case DT_PLTRELSZ: pltrel_size = dynbuf[i].d_un.d_val; break;
                case DT_SYMTAB:   symtab_addr = dynbuf[i].d_un.d_ptr; break;
                case DT_STRTAB:   strtab_addr = dynbuf[i].d_un.d_ptr; break;
                case DT_STRSZ:    strsz_val = dynbuf[i].d_un.d_val; break;
                case DT_SYMENT:   syment_sz = dynbuf[i].d_un.d_val; break;
                case DT_HASH:     hash_addr = dynbuf[i].d_un.d_ptr; break;
                default: break;
            }
        }
        free(dynbuf);
    }

    const vaddr_t uva_sym = symtab_addr ? uva_from_vaddr(uva_base, minva_page, symtab_addr) : 0;
    const vaddr_t uva_str = strtab_addr ? uva_from_vaddr(uva_base, minva_page, strtab_addr) : 0;

    // Helper to read a dynsym by index
    auto read_sym = [&](size_t idx, struct Elf64_Sym *out) -> status_t {
        if (!uva_sym || syment_sz != sizeof(struct Elf64_Sym)) return ERR_NOT_SUPPORTED;
        vaddr_t addr = uva_sym + idx * sizeof(struct Elf64_Sym);
        ssize_t r = copy_from_user(out, addr, sizeof(*out));
        return (r < 0) ? (status_t)r : ((size_t)r == sizeof(*out) ? NO_ERROR : ERR_IO);
    };

    // Apply relocations from UVA tables (.rela.dyn and .rela.plt)
    uint64_t load_bias = (uint64_t)(uva_base - minva_page);
    if (rela_addr && rela_size) {
        vaddr_t rela_uva = uva_from_vaddr(uva_base, minva_page, rela_addr);
        struct Elf64_Rela *relas = (struct Elf64_Rela *)malloc((size_t)rela_size);
        if (!relas) { (void)vmm_set_active_aspace(old_as); return ERR_NO_MEMORY; }
        ssize_t r = copy_from_user(relas, rela_uva, (size_t)rela_size);
        if (r < 0 || (size_t)r != (size_t)rela_size) { free(relas); (void)vmm_set_active_aspace(old_as); return (r < 0) ? (status_t)r : ERR_IO; }
        size_t count = (size_t)rela_size / sizeof(struct Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = (uint32_t)ELF64_R_TYPE(relas[i].r_info);
            uint32_t symi = (uint32_t)ELF64_R_SYM(relas[i].r_info);
            vaddr_t where = uva_from_vaddr(uva_base, minva_page, relas[i].r_offset);
            uint64_t val = 0;
            switch (type) {
                case R_AARCH64_RELATIVE:
                    val = load_bias + (uint64_t)relas[i].r_addend;
                    break;
                case R_AARCH64_ABS64:
                case R_AARCH64_JUMP_SLOT:
                case R_AARCH64_GLOB_DAT: {
                    struct Elf64_Sym s;
                    st = read_sym(symi, &s);
                    if (st < 0) { free(relas); (void)vmm_set_active_aspace(old_as); return st; }
                    if (s.st_shndx == SHN_UNDEF) { free(relas); (void)vmm_set_active_aspace(old_as); return ERR_NOT_SUPPORTED; }
                    uint64_t S = (uint64_t)s.st_value + load_bias;
                    val = S + (uint64_t)relas[i].r_addend;
                    break;
                }
                case R_AARCH64_NONE:
                    continue;
                default:
                    free(relas);
                    (void)vmm_set_active_aspace(old_as);
                    return ERR_NOT_SUPPORTED;
            }
            ssize_t wr = copy_to_user(where, &val, sizeof(val));
            if (wr < 0 || (size_t)wr != sizeof(val)) { free(relas); (void)vmm_set_active_aspace(old_as); return (wr < 0) ? (status_t)wr : ERR_IO; }
        }
        free(relas);
    }
    if (jmprel_addr && pltrel_size) {
        vaddr_t plt_uva = uva_from_vaddr(uva_base, minva_page, jmprel_addr);
        struct Elf64_Rela *relas = (struct Elf64_Rela *)malloc((size_t)pltrel_size);
        if (!relas) { (void)vmm_set_active_aspace(old_as); return ERR_NO_MEMORY; }
        ssize_t r = copy_from_user(relas, plt_uva, (size_t)pltrel_size);
        if (r < 0 || (size_t)r != (size_t)pltrel_size) { free(relas); (void)vmm_set_active_aspace(old_as); return (r < 0) ? (status_t)r : ERR_IO; }
        size_t count = (size_t)pltrel_size / sizeof(struct Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = (uint32_t)ELF64_R_TYPE(relas[i].r_info);
            uint32_t symi = (uint32_t)ELF64_R_SYM(relas[i].r_info);
            vaddr_t where = uva_from_vaddr(uva_base, minva_page, relas[i].r_offset);
            uint64_t val = 0;
            switch (type) {
                case R_AARCH64_RELATIVE:
                    val = load_bias + (uint64_t)relas[i].r_addend;
                    break;
                case R_AARCH64_JUMP_SLOT:
                case R_AARCH64_GLOB_DAT: {
                    struct Elf64_Sym s;
                    st = read_sym(symi, &s);
                    if (st < 0) { free(relas); (void)vmm_set_active_aspace(old_as); return st; }
                    if (s.st_shndx == SHN_UNDEF) { free(relas); (void)vmm_set_active_aspace(old_as); return ERR_NOT_SUPPORTED; }
                    uint64_t S = (uint64_t)s.st_value + load_bias;
                    val = S + (uint64_t)relas[i].r_addend;
                    break;
                }
                case R_AARCH64_NONE:
                    continue;
                default:
                    free(relas);
                    (void)vmm_set_active_aspace(old_as);
                    return ERR_NOT_SUPPORTED;
            }
            ssize_t wr = copy_to_user(where, &val, sizeof(val));
            if (wr < 0 || (size_t)wr != sizeof(val)) { free(relas); (void)vmm_set_active_aspace(old_as); return (wr < 0) ? (status_t)wr : ERR_IO; }
        }
        free(relas);
    }

    // Determine entry UVA (prefer e_entry, else find 'lkmod_init')
    vaddr_t entry_uva = 0;
    if (eh.e_entry) {
        entry_uva = uva_from_vaddr(uva_base, minva_page, eh.e_entry);
    } else if (uva_sym && uva_str && strsz_val >= 1 && syment_sz == sizeof(struct Elf64_Sym)) {
        // Attempt to find lkmod_init via SysV DT_HASH if present
        size_t dynsym_count = 0;
        if (hash_addr) {
            vaddr_t hash_uva = uva_from_vaddr(uva_base, minva_page, hash_addr);
            uint32_t hdr[2] = {0,0};
            if (copy_from_user(hdr, hash_uva, sizeof(hdr)) == sizeof(hdr)) {
                dynsym_count = hdr[1]; // nchain
            }
        }
        // Fallback: probe up to a reasonable limit
        if (dynsym_count == 0) dynsym_count = 512;
        for (size_t i = 0; i < dynsym_count; i++) {
            struct Elf64_Sym s;
            if (read_sym(i, &s) != NO_ERROR) break;
            if (s.st_name == 0) continue;
            // Read symbol name (bounded)
            char name[64];
            size_t off = (size_t)s.st_name;
            if (off >= strsz_val) continue;
            size_t want = (strsz_val - off) < sizeof(name) ? (strsz_val - off) : sizeof(name);
            ssize_t nr = copy_from_user(name, uva_str + off, want);
            if (nr < 0) break;
            if (memchr(name, '\0', (size_t)nr) == NULL) name[sizeof(name) - 1] = '\0';
            if (strcmp(name, "lkmod_init") == 0) {
                entry_uva = uva_from_vaddr(uva_base, minva_page, s.st_value);
                break;
            }
        }
    }

    // Sync icache over executable segments (already in user aspace)
    for (uint i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if ((ph[i].p_flags & PF_X) == 0) continue;
        if (ph[i].p_memsz == 0) continue;
        vaddr_t seg = uva_from_vaddr(uva_base, minva_page, ph[i].p_vaddr);
        arch_sync_cache_range(seg, (size_t)ph[i].p_memsz);
    }
    (void)vmm_set_active_aspace(old_as);

    if (uva_base_out) *uva_base_out = uva_base;
    if (minva_out) *minva_out = minva_page;
    if (span_out) *span_out = span;
    if (entry_uva_out) *entry_uva_out = entry_uva;
    return NO_ERROR;
}
