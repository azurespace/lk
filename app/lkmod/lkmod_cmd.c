// Console commands to load/unload/call functions from runtime modules.

#include <lk/console_cmd.h>
#include <lk/trace.h>
#include <lk/debug.h>
#include <lk/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lkmod/lkmod.h>
#include <lib/page_alloc.h>

#define LOCAL_TRACE 0

// Note: pass a NULL api to lkmod_load_from_memory to use the loader's
// built-in defaults (log/printf/alloc/free/ticks). This keeps the
// surface consistent without wiring local wrappers here.

static lkmod_module_t *g_last_mod;
static void *g_buf;
static size_t g_bufsz;

static int cmd_mod(int argc, const console_cmd_args *argv) {
    if (argc < 2) goto usage;

    if (!strcmp(argv[1].str, "loadat") && argc >= 4) {
        void *addr = argv[2].p;
        size_t size = (size_t)argv[3].u;
        lkmod_module_t *mod = NULL;
        status_t st = lkmod_load_from_memory(addr, size, NULL, &mod);
        if (st < 0) {
            printf("load failed: %s(%d)\n", lkmod_status_str(st), st);
        } else {
            g_last_mod = mod;
            printf("loaded module %s @ %p size %zu\n", lkmod_name(mod), (void *)lkmod_base(mod), lkmod_size(mod));
        }
        return 0;
    }

    if (!strcmp(argv[1].str, "alloc") && argc >= 3) {
        size_t sz = (size_t)argv[2].u;
        if (g_buf) { printf("already have buffer @ %p (%zu)\n", g_buf, g_bufsz); return 0; }
        // allocate page-aligned chunk using page allocator when available
        size_t pages = (sz + PAGE_SIZE - 1) / PAGE_SIZE;
        g_buf = page_alloc(pages, PAGE_ALLOC_ANY_ARENA);
        g_bufsz = pages * PAGE_SIZE;
        printf("allocated %zu bytes at %p\n", g_bufsz, g_buf);
        return 0;
    }

    if (!strcmp(argv[1].str, "list")) {
        lkmod_module_t *sel = g_last_mod ? g_last_mod : lkmod_last_loaded();
        size_t idx = 0;
        for (lkmod_module_t *m = lkmod_next(NULL); m; m = lkmod_next(m), idx++) {
            printf("%c[%zu] %s base=%p size=%zu\n",
                   (m == sel ? '*' : ' '), idx, lkmod_name(m), (void *)lkmod_base(m), lkmod_size(m));
        }
        if (idx == 0) {
            printf("(no modules loaded)\n");
        }
        return 0;
    }

    if (!strcmp(argv[1].str, "select") && argc >= 3) {
        size_t want = (size_t)argv[2].u;
        size_t idx = 0;
        for (lkmod_module_t *m = lkmod_next(NULL); m; m = lkmod_next(m), idx++) {
            if (idx == want) {
                g_last_mod = m;
                printf("selected [%zu] %s base=%p size=%zu\n", idx, lkmod_name(m), (void *)lkmod_base(m), lkmod_size(m));
                return 0;
            }
        }
        printf("invalid index %zu\n", want);
        return 0;
    }

    if (!strcmp(argv[1].str, "info")) {
        lkmod_module_t *m = NULL;
        if (argc >= 3) {
            m = lkmod_find_by_name(argv[2].str);
            if (!m) {
                printf("module '%s' not found\n", argv[2].str);
                return 0;
            }
        } else {
            m = g_last_mod ? g_last_mod : lkmod_last_loaded();
            if (!m) {
                printf("no modules loaded\n");
                return 0;
            }
        }
        printf("name=%s base=%p size=%zu\n", lkmod_name(m), (void *)lkmod_base(m), lkmod_size(m));
        return 0;
    }

    if (!strcmp(argv[1].str, "free")) {
        if (!g_buf) { printf("no buffer\n"); return 0; }
        page_free(g_buf, g_bufsz / PAGE_SIZE);
        printf("freed %zu bytes at %p\n", g_bufsz, g_buf);
        g_buf = NULL; g_bufsz = 0;
        return 0;
    }

    if (!strcmp(argv[1].str, "unload")) {
        if (!g_last_mod) {
            g_last_mod = lkmod_last_loaded();
        }
        if (!g_last_mod) { printf("no module loaded\n"); return 0; }
        lkmod_unload(g_last_mod);
        g_last_mod = NULL;
        printf("unloaded\n");
        return 0;
    }

    if (!strcmp(argv[1].str, "call") && argc >= 3) {
        if (!g_last_mod) {
            g_last_mod = lkmod_last_loaded();
        }
        if (!g_last_mod) { printf("no module loaded\n"); return 0; }
        const char *sym = argv[2].str;
        int64_t a0 = (argc > 3) ? argv[3].i : 0;
        int64_t a1 = (argc > 4) ? argv[4].i : 0;
        int64_t a2 = (argc > 5) ? argv[5].i : 0;
        int64_t a3 = (argc > 6) ? argv[6].i : 0;
        int64_t retv = 0;
        status_t st = lkmod_call4(g_last_mod, sym, a0, a1, a2, a3, &retv);
        if (st < 0) {
            printf("call failed: %d\n", st);
        } else {
            printf("ret = %lld\n", (long long)retv);
        }
        return 0;
    }

usage:
    printf("Usage:\n");
    printf("  mod alloc <size>            # alloc scratch buffer (prints address)\n");
    printf("  mod loadat <addr> <size>    # load ELF module from memory\n");
    printf("  mod call <symbol> [a0..a3]   # call function in last/builtin module\n");
    printf("  mod list                     # list loaded modules (* = selected)\n");
    printf("  mod select <index>           # select a module by index\n");
    printf("  mod info [name]              # show details for selected or by name\n");
    printf("  mod unload                   # unload last loaded module\n");
    printf("  mod free                     # free scratch buffer\n");
    return 0;
}

STATIC_COMMAND_START
STATIC_COMMAND("mod", "runtime module loader", &cmd_mod)
STATIC_COMMAND_END(lkmod);
