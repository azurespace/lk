#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct lkmod_api {
    void (*log)(const char *msg);
    int (*printf)(const char *fmt, ...);
    void *(*alloc)(size_t size);
    void (*free)(void *ptr);
    uint64_t (*ticks)(void);
    void (*issue)(int queue_id, void *command);
} lkmod_api_t;

#ifdef __cplusplus
extern "C" {
#endif

// Expected module entry points
int lkmod_init(const lkmod_api_t *api, void **handle_out);
int lkmod_exit(void *handle);

#ifdef __cplusplus
} // extern "C"
#endif
