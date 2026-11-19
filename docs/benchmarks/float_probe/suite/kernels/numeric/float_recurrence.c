#include <stdint.h>

/* Build without fast-math and with -ffp-contract=off for matched rounding. */
int64_t bench(int64_t n, int64_t seed) {
    double x = 0.123456789012345 + (double)(seed & 65535) * 0.00000123456789;
    double y = 0.987654321098765 + (double)((seed >> 8) & 65535) * 0.00000034567891;
    double accumulated = 0.0;
    int64_t i = 0;
    while (i < n) {
        double nextX = x * 0.9999991 + y * 0.0000003 + 0.0000007;
        double nextY = y * 0.9999989 + x * 0.0000002 + 0.0000005;
        x = nextX;
        y = nextY;
        accumulated = accumulated + x * 0.333333333333333 + y * 0.142857142857143;
        i = i + 1;
    }
    return (int64_t)(accumulated * 1000.0) & INT64_C(2147483647);
}
