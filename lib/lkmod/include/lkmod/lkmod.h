#pragma once

#include <sys/types.h>
#include <lk/err.h>
#include <lk/list.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Public API table exposed to modules. Keep stable and minimal.
typedef struct lkmod_api {
    void (*log)(const char *msg);
    int (*printf)(const char *fmt, ...);
    void *(*alloc)(size_t size);
    void (*free)(void *ptr);
    uint64_t (*ticks)(void);
    // Issue a command to a queue (opaque to modules)
    void (*issue)(int queue_id, void *command);
} lkmod_api_t;

// Opaque module handle
typedef struct lkmod_module lkmod_module_t;

// Load a module from an in-memory ELF(ET_DYN, AArch64, PIC) image.
status_t lkmod_load_from_memory(const void *blob, size_t len, const lkmod_api_t *api,
                                lkmod_module_t **out_mod);

// Unload a previously loaded module. Calls its lkmod_exit (if present).
status_t lkmod_unload(lkmod_module_t *mod);

// Optional helpers
const char *lkmod_name(const lkmod_module_t *mod);
uintptr_t lkmod_base(const lkmod_module_t *mod);
size_t lkmod_size(const lkmod_module_t *mod);

// Dynamic symbol lookup inside a module (STT_FUNC/STT_OBJECT).
// Returns 0 on failure.
uintptr_t lkmod_lookup(const lkmod_module_t *mod, const char *symname);

// Convenience: call a function by name with up to 4 integer args.
// Returns the function return value as int64.
// The function is assumed to have signature: long f(long,long,long,long)
// Missing args default to 0.
status_t lkmod_call4(const lkmod_module_t *mod, const char *symname,
                     int64_t a0, int64_t a1, int64_t a2, int64_t a3,
                     int64_t *ret_out);

// Convenience: convert common error codes to short strings for logs.
const char *lkmod_status_str(status_t status);

// Module registry helpers
// Get the first/last loaded module (or NULL if none).
lkmod_module_t *lkmod_first_loaded(void);
lkmod_module_t *lkmod_last_loaded(void);
// Iterate loaded modules: pass NULL to get first, pass previous to get next.
lkmod_module_t *lkmod_next(lkmod_module_t *prev);
// Find a loaded module by name (exact match), or NULL if not found.
lkmod_module_t *lkmod_find_by_name(const char *name);

#ifdef __cplusplus
}
#endif
