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

#ifndef CALLSITE_BITS
#define CALLSITE_BITS 20
#endif
#ifndef CHUNK_BITS
#define CHUNK_BITS 24
#endif
#define STACK_DEPTH 4

static struct callsite {
    size_t bytes_alloced;
    size_t alloc_cnt;
    size_t free_cnt;
    size_t collision_cnt;
    void *callers[STACK_DEPTH];
} callsites[1 << CALLSITE_BITS];

struct chunk {
    struct callsite *cs;
    size_t sz;
} __attribute__((aligned(16)));

static struct chunk chunks[1 << CHUNK_BITS];

static void get_callstack(void **stack, void **frame)
{
    void **stack_end = (void **)(((uintptr_t)frame + 4095) / 4096 * 4096);

    for (size_t i = 0; i < STACK_DEPTH; ++i) {
        stack[i] = frame[1];
        /* check bounds */
        void **next_frame = (void **)*frame;
        if (!(frame < next_frame && next_frame < stack_end + 1))
            break;
        frame = next_frame;
    }
}

static size_t hash(void **ptrs, size_t cnt, unsigned bits)
{
    size_t v = 0;

    for (size_t i = 0; i < cnt; ++i)
        for (size_t j = 0; j < sizeof(size_t) * 8; j += bits)
            v ^= (uintptr_t)ptrs[i] >> j;

    return v % ((size_t)1 << bits);
}

static struct callsite *setup_callsite(void **callers)
{
    struct callsite *cs = &callsites[hash(callers, STACK_DEPTH, CALLSITE_BITS)];

    if (cs->callers[0] == callers[0]) {
        /* asume the slot is correct */
    } else if (__sync_bool_compare_and_swap(&cs->callers[0], NULL, callers[0])) {
        /* if we succeed in obtaining the slot, copy the rest of the callstack; no need to use atomic insns as we write only once */
        for (size_t i = 1; i < STACK_DEPTH; ++i)
            cs->callers[i] = callers[i];
    } else {
        /* detected collision TODO log */
    }

    return cs;
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
    size_t chunk_slot = hash(&p, 1, CHUNK_BITS);

    if (chunks[chunk_slot].cs == NULL && cas_chunk(&chunks[chunk_slot], (struct chunk){}, (struct chunk){cs, sz})) {
        __sync_fetch_and_add(&cs->bytes_alloced, sz);
        __sync_fetch_and_add(&cs->alloc_cnt, 1);
    } else {
        __sync_fetch_and_add(&cs->collision_cnt, 1);
    }
}

static struct callsite *unregister_chunk(void *p)
{
    size_t chunk_slot = hash(&p, 1, CHUNK_BITS);
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

    void *callers[STACK_DEPTH] = {};
    get_callstack(callers, __builtin_frame_address(0));

    struct callsite *cs = setup_callsite(callers);
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

int posix_memalign(void **p, size_t align, size_t sz)
{
    DEFINE_ORIGFN("posix_memalign", int, void **, size_t, size_t);

    int ret = origfn(p, align, sz);
    if (ret != 0)
        return ret;

    void *callers[STACK_DEPTH] = {};
    get_callstack(callers, __builtin_frame_address(0));

    struct callsite *cs = setup_callsite(callers);
    register_chunk(*p, cs, sz);

    return 0;
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
        if (callsites[i].callers[0] != NULL) {
            char buf[256];
            sprintf(buf, "%zu\t%zu\t%zu\t%zu", callsites[i].bytes_alloced, callsites[i].alloc_cnt, callsites[i].free_cnt,
                    callsites[i].collision_cnt);
            for (size_t j = 0; j < STACK_DEPTH && callsites[i].callers[j] != NULL; ++j)
                sprintf(buf + strlen(buf), "\t%p", callsites[i].callers[j]);
            strcat(buf, "\n");
            write(fd, buf, strlen(buf));
        }
    }

    write(fd, "\n", 1); /* empty line indicates end of message */
}

static void *dump_signal_main(void *unused)
{
    const char *fn = getenv("LEAKTRACE_PATH");

    if (fn == NULL) {
        const char *msg = "leaktrace:LEAKTRACE_PATH not set\n";
        write(2, msg, strlen(msg));
        return NULL;
    }

    int fd = open(fn, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd == -1) {
        char msg[256];
        snprintf(msg, sizeof(msg), "leaktrace:failed to create file %s for writing (errno=%d)\n", fn, errno);
        write(2, msg, strlen(msg));
        return NULL;
    }

    leaktrace_dump(fd);

    close(fd);

    return NULL;
}

static void on_dump_signal(int signo)
{
    pthread_t thread;
    pthread_create(&thread, NULL, dump_signal_main, NULL);
    pthread_detach(thread);
}

__attribute__((constructor)) void leaktrace_setup(void)
{
    signal(SIGUSR2, on_dump_signal);
}
