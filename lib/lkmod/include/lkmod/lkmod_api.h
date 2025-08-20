#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque SRAM buffer handle for accelerator ops
typedef struct sram_buffer sram_buffer;

// Public API table exposed to loadable modules. Keep stable and minimal.
typedef struct lkmod_api {
    void (*log)(const char *msg);
    int (*printf)(const char *fmt, ...);
    void *(*alloc)(size_t size);
    void (*free)(void *ptr);
    uint64_t (*ticks)(void);
    // Issue a command to a queue (opaque to modules)
    void (*issue)(int queue_id, void *command);
    // Compute APIs for SRAM buffers
    void (*add)(sram_buffer *a, sram_buffer *b, sram_buffer *out);
    void (*rmsnorm)(sram_buffer *a, sram_buffer *b, sram_buffer *out);
} lkmod_api_t;

// Expected module entry points (implemented by the module)
int lkmod_init(const lkmod_api_t *api, void **handle_out);
int lkmod_exit(void *handle);

#ifdef __cplusplus
} // extern "C"
#endif

