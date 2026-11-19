#include <stdint.h>
#include <stddef.h>

/* A separately compiled shared object keeps bulk operations observable to the
 * caller's compiler. This is one barrier per whole buffer operation, never a
 * volatile load/store in an inner numeric loop. It is called by ALL languages. */
void bench_observe(const void *p, int64_t n) {
    __asm__ __volatile__("" : : "r"(p), "r"(n) : "memory");
}

/* Identical full-content verification cost for the native-helper category. */
int64_t bench_buffer_hash(const unsigned char *p, int64_t n) {
    uint64_t h = 5381;
    for (int64_t i = 0; i < n; ++i) h = ((h * 33) ^ p[i]) & UINT64_C(2147483647);
    return (int64_t)h;
}
