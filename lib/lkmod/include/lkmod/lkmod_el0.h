// User-aspace loader for ET_DYN (AArch64) modules
// Maps a PIC shared object into a provided user vmm_aspace, copies PT_LOAD
// segments, applies basic relocations, syncs icache, and exposes the entry UVA.

#pragma once

#include <lk/err.h>
#include <stdint.h>
#include <stddef.h>

#include <kernel/vm.h>

#ifdef __cplusplus
extern "C" {
#endif

// Load an ET_DYN AArch64 PIC blob into a user address space.
// - uas: user vmm_aspace to map into (must be non-NULL and belong to current thread when calling)
// - blob/len: ELF image in memory
// - uva_base_out: base UVA of the loaded image (page aligned)
// - minva_out: minimum p_vaddr across PT_LOAD segments (page aligned), for offset math
// - span_out: total reserved span from minva (bytes)
// - entry_uva_out: entry point UVA (either e_entry or 'lkmod_init' if present), may be 0 if not found
status_t lkmod_el0_load_image(vmm_aspace_t *uas,
                              const void *blob, size_t len,
                              vaddr_t *uva_base_out,
                              uint64_t *minva_out,
                              size_t *span_out,
                              vaddr_t *entry_uva_out);

#ifdef __cplusplus
}
#endif

