#include <stdint.h>
#include <stddef.h>
#include "../api/lkmod_api.h"

static const lkmod_api_t* g_api = nullptr;

// Keep C linkage for exported symbols
extern "C" __attribute__((visibility("default"))) long hello_add(long a, long b) {
    return a + b;
}

extern "C" __attribute__((visibility("default"))) long hello_bounce(size_t nbytes) {
    if (!g_api || !g_api->alloc || !g_api->free || !g_api->ticks) return -1;
    uint64_t t0 = g_api->ticks ? g_api->ticks() : 0ULL;
    void* p = g_api->alloc(nbytes);
    if (p) g_api->free(p);
    uint64_t t1 = g_api->ticks ? g_api->ticks() : 0ULL;
    return static_cast<long>(t1 - t0);
}

extern "C" __attribute__((visibility("default"))) int lkmod_init(const lkmod_api_t* api, void** handle_out) {
    g_api = api;
    if (handle_out) *handle_out = nullptr;
    if (g_api) {
        if (g_api->printf) g_api->printf("hello_cpp: loaded (ticks=%llu)\n", (unsigned long long)(g_api->ticks ? g_api->ticks() : 0ULL));
        else if (g_api->log) g_api->log("hello_cpp loaded\n");
    }
    return 0;
}

extern "C" __attribute__((visibility("default"))) int lkmod_exit(void* handle) {
    (void)handle;
    if (g_api) {
        if (g_api->printf) g_api->printf("hello_cpp: unloaded\n");
        else if (g_api->log) g_api->log("hello_cpp unloaded\n");
    }
    g_api = nullptr;
    return 0;
}
