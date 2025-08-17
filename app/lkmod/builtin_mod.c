// Auto-load a built-in module blob at boot.
#ifndef LKMOD_NO_BUILTIN

#include <lk/init.h>
#include <lk/err.h>
#include <lk/debug.h>
#include <lk/trace.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include <lkmod/lkmod.h>

#define LOCAL_TRACE 0

// Symbols produced by objcopy -I binary on mods/hello_cpp/hello_cpp.so
extern const unsigned char _binary_mods_hello_cpp_hello_cpp_so_start[];
extern const unsigned char _binary_mods_hello_cpp_hello_cpp_so_end[];

static lkmod_module_t *g_builtin_mod;

static void lkmod_builtin_init(uint level) {
    (void)level;
    const void *blob = (const void *)_binary_mods_hello_cpp_hello_cpp_so_start;
    size_t len = (size_t)(_binary_mods_hello_cpp_hello_cpp_so_end - _binary_mods_hello_cpp_hello_cpp_so_start);

    if (!blob || len == 0) {
        printf("lkmod: builtin blob missing or empty\n");
        return;
    }

    status_t st = lkmod_load_from_memory(blob, len, NULL, &g_builtin_mod);
    if (st < 0) {
        printf("lkmod: builtin load failed: %d\n", st);
        return;
    }

    printf("lkmod: builtin loaded %s @ %p (%zu bytes)\n",
           lkmod_name(g_builtin_mod), (void *)lkmod_base(g_builtin_mod), lkmod_size(g_builtin_mod));

    // Optional: quick sanity check of hello_add(2,3)
    int64_t retv = 0;
    st = lkmod_call4(g_builtin_mod, "hello_add", 2, 3, 0, 0, &retv);
    if (st == NO_ERROR) {
        printf("lkmod: hello_add(2,3) = %lld\n", (long long)retv);
    }
}

// Load after apps are up (heap/console ready)
LK_INIT_HOOK(lkmod_builtin, lkmod_builtin_init, LK_INIT_LEVEL_APPS);

#endif // LKMOD_NO_BUILTIN
