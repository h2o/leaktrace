#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CALLSITE_BITS 16
#define CHUNK_BITS 20

static struct callsite {
    size_t alloc_cnt;
    size_t free_cnt;
    size_t collision_cnt;
    void *caller;
} callsites[1 << CALLSITE_BITS];

static struct callsite *chunks[1 << CHUNK_BITS];

static size_t hash(void *p, unsigned bits)
{
    size_t v = (uintptr_t)p;

    for (size_t i = bits; i < sizeof(size_t) * 8; i += bits)
        v ^= v >> i;

    return v % ((size_t)1 << bits);
}

static void register_chunk(void *p, struct callsite *cs)
{
    size_t chunk_slot = hash(p, CHUNK_BITS);

    if (chunks[chunk_slot] == NULL && __sync_bool_compare_and_swap(&chunks[chunk_slot], NULL, cs)) {
        __sync_fetch_and_add(&chunks[chunk_slot]->alloc_cnt, 1);
    } else {
        __sync_fetch_and_add(&chunks[chunk_slot]->collision_cnt, 1);
    }
}

static struct callsite *unregister_chunk(void *p)
{
    size_t chunk_slot = hash(p, CHUNK_BITS);
    struct callsite *cs = NULL;

    if ((cs = chunks[chunk_slot]) != NULL && __sync_bool_compare_and_swap(&chunks[chunk_slot], cs, NULL))
        __sync_fetch_and_add(&cs->free_cnt, 1);

    return cs;
}

#define DEFINE_ORIGFN(name, rettype, ...)                                                                                          \
    static rettype (*volatile origfn)(__VA_ARGS__) = NULL;                                                                         \
    do {                                                                                                                           \
        if (origfn == NULL) {                                                                                                      \
            static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;                                                               \
            pthread_mutex_lock(&lock);                                                                                             \
            if (origfn == NULL)                                                                                                    \
                origfn = (rettype(*)(__VA_ARGS__))dlsym(RTLD_NEXT, name);                                                          \
            pthread_mutex_unlock(&lock);                                                                                           \
        }                                                                                                                          \
    } while (0)

void *malloc(size_t sz)
{
    DEFINE_ORIGFN("malloc", void *, size_t sz);

    void *p = origfn(sz);
    if (p == NULL)
        return NULL;

    void *caller = __builtin_return_address(0);
    struct callsite *cs = &callsites[hash(caller, CALLSITE_BITS)];

    if (cs->caller == NULL)
        cs->caller = caller;

    register_chunk(p, cs);

    return p;
}

void *realloc(void *oldp, size_t sz)
{
    DEFINE_ORIGFN("realloc", void *, void *oldp, size_t sz);

    void *newp = origfn(oldp, sz);
    if (newp == NULL)
        return NULL;

    struct callsite *cs = unregister_chunk(oldp);
    if (cs != NULL)
        register_chunk(newp, cs);

    return newp;
}

void free(void *p)
{
    DEFINE_ORIGFN("free", void, void *p);

    unregister_chunk(p);
    origfn(p);
}

void mempt_dump(int fd)
{
    for (size_t i = 0; i < sizeof(callsites) / sizeof(callsites[0]); ++i) {
        if (callsites[i].caller != NULL) {
            char buf[256];
            sprintf(buf, "%p:alloc=%zu,free=%zu,collision=%zu\n", callsites[i].caller, callsites[i].alloc_cnt,
                    callsites[i].free_cnt, callsites[i].collision_cnt);
            write(fd, buf, strlen(buf));
        }
    }
}

void exit(int status)
{
    static void (*origfn)(int);
    if (origfn == NULL)
        origfn = (void (*)(int))dlsym(RTLD_NEXT, "exit");

    write(2, "exit\n", 6);
    mempt_dump(2);

    origfn(status);

    /* this is a no-return function, suppress warning */
    while (1)
        ;
}
