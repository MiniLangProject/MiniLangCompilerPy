#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Separate translation unit, deliberately without LTO. The optimizer cannot
 * hoist or delete the calls merely because repeated kernels look similar. */
int64_t bench(int64_t n, int64_t seed);

static int64_t measurement_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) exit(91);
    return (int64_t)t.tv_sec * INT64_C(1000000000) + t.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 4) return 90;
    int64_t n = strtoll(argv[1], NULL, 10);
    int64_t reps = strtoll(argv[2], NULL, 10);
    int64_t seed = strtoll(argv[3], NULL, 10);
    if (n < 1 || reps < 1 || reps > 10000000 || seed < 0 || seed > 2147483647) return 90;
    int64_t warmup = bench(n, (seed + 65536) & INT64_C(2147483647));
    int64_t checksum = 0;
    int64_t start = measurement_ns();
    for (int64_t r = 0; r < reps; ++r) {
        checksum = (checksum + bench(n, (seed + (r & 7)) & INT64_C(2147483647))) & INT64_C(2147483647);
    }
    int64_t elapsed = measurement_ns() - start;
    printf("RESULT %" PRId64 " %" PRId64 " %" PRId64 "\n", checksum, elapsed, warmup);
    return 0;
}
