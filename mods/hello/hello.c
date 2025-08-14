#include <stdint.h>
#include <stddef.h>
#include "../api/lkmod_api.h"

static const lkmod_api_t *g_api;

#if defined(__GNUC__)
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif

// Example exported function: add two numbers.
EXPORT long hello_add(long a, long b) {
    return a + b;
}

// Example exported function: allocate and free memory via API, return elapsed ticks.
EXPORT long hello_bounce(size_t nbytes) {
    if (!g_api || !g_api->alloc || !g_api->free || !g_api->ticks) return -1;
    uint64_t t0 = g_api->ticks();
    void *p = g_api->alloc(nbytes);
    if (p) g_api->free(p);
    uint64_t t1 = g_api->ticks();
    return (long)(t1 - t0);
}

// Module entry/exit. Return 0 on success.
EXPORT int lkmod_init(const lkmod_api_t *api, void **handle_out) {
    g_api = api;
    if (handle_out) *handle_out = NULL;
    if (g_api) {
        if (g_api->printf) g_api->printf("hello: loaded (ticks=%llu)\n", (unsigned long long)(g_api->ticks ? g_api->ticks() : 0ULL));
        else if (g_api->log) g_api->log("hello module loaded\n");
    }
    return 0;
}

EXPORT int lkmod_exit(void *handle) {
    (void)handle;
    if (g_api) {
        if (g_api->printf) g_api->printf("hello: unloaded\n");
        else if (g_api->log) g_api->log("hello module unloaded\n");
    }
    g_api = 0;
    return 0;
}
