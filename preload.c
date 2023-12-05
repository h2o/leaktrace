#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#define CALLSITE_BITS 16
#define CHUNK_BITS 20

static struct callsite {
    size_t bytes_alloced;
    size_t alloc_cnt;
    size_t free_cnt;
    size_t collision_cnt;
    void *caller;
} callsites[1 << CALLSITE_BITS];

static struct chunk {
    struct callsite *cs;
    size_t sz;
} chunks[1 << CHUNK_BITS];

static size_t hash(void *p, unsigned bits)
{
    size_t v = (uintptr_t)p;

    for (size_t i = bits; i < sizeof(size_t) * 8; i += bits)
        v ^= v >> i;

    return v % ((size_t)1 << bits);
}

static int cas_chunk(struct chunk *dest, struct chunk expected, struct chunk desired)
{
    unsigned char result;

    __asm__ __volatile__("lock cmpxchg16b %1\n\t"
                         "setz %0"
                         : "=q"(result), "+m"(*dest), "+d"(expected.sz), "+a"(expected.cs)
                         : "c"(desired.sz), "b"(desired.cs)
                         : "cc");

    return result;
}

static void register_chunk(void *p, struct callsite *cs, size_t sz)
{
    size_t chunk_slot = hash(p, CHUNK_BITS);

    if (chunks[chunk_slot].cs == NULL && cas_chunk(&chunks[chunk_slot], (struct chunk){}, (struct chunk){cs, sz})) {
        __sync_fetch_and_add(&cs->bytes_alloced, sz);
        __sync_fetch_and_add(&cs->alloc_cnt, 1);
    } else {
        __sync_fetch_and_add(&cs->collision_cnt, 1);
    }
}

static struct callsite *unregister_chunk(void *p)
{
    size_t chunk_slot = hash(p, CHUNK_BITS);
    struct chunk chunk;

    if ((chunk = chunks[chunk_slot]).cs != NULL && cas_chunk(&chunks[chunk_slot], chunk, (struct chunk){})) {
        __sync_fetch_and_sub(&chunk.cs->bytes_alloced, chunk.sz);
        __sync_fetch_and_add(&chunk.cs->free_cnt, 1);
    }

    return chunk.cs;
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

    register_chunk(p, cs, sz);

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
        register_chunk(newp, cs, sz);

    return newp;
}

void free(void *p)
{
    DEFINE_ORIGFN("free", void, void *p);

    unregister_chunk(p);
    origfn(p);
}

void leaktrace_dump(int fd)
{
    for (size_t i = 0; i < sizeof(callsites) / sizeof(callsites[0]); ++i) {
        if (callsites[i].caller != NULL) {
            char buf[256];
            sprintf(buf, "%p\t%zu\t%zu\t%zu\t%zu\n", callsites[i].caller, callsites[i].bytes_alloced, callsites[i].alloc_cnt,
                    callsites[i].free_cnt, callsites[i].collision_cnt);
            write(fd, buf, strlen(buf));
        }
    }

    write(fd, "\n", 1); /* empty line indicates end of message */
}

static void on_dump_signal(int signo)
{
    const char *fn = getenv("LEAKTRACE_PATH");

    if (fn == NULL) {
        const char *msg = "leaktrace:LEAKTRACE_PATH not set\n";
        write(2, msg, strlen(msg));
        return;
    }

    int fd = open(fn, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd == -1) {
        char msg[256];
        snprintf(msg, sizeof(msg), "leaktrace:failed to create file %s for writing (errno=%d)\n", fn, errno);
        write(2, msg, strlen(msg));
        return;
    }

    leaktrace_dump(fd);

    close(fd);
}

__attribute__((constructor)) void leaktrace_setup(void)
{
    signal(SIGUSR2, on_dump_signal);
}
