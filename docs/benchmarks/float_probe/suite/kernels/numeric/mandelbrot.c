#include <stdint.h>

/* Build without fast-math and with -ffp-contract=off for matched rounding. */
int64_t bench(int64_t n, int64_t seed) {
    double scale = 3.0 / (double)n;
    double offset = (double)(seed & 255) * 0.0000001;
    int64_t checksum = 0;
    int64_t py = 0;
    while (py < n) {
        double cy = -1.5 + (double)py * scale;
        int64_t px = 0;
        while (px < n) {
            double cx = -2.0 + (double)px * scale + offset;
            double zr = 0.0;
            double zi = 0.0;
            double zr2 = 0.0;
            double zi2 = 0.0;
            int64_t iteration = 0;
            while (iteration < 80 && zr2 + zi2 <= 4.0) {
                zi = 2.0 * zr * zi + cy;
                zr = zr2 - zi2 + cx;
                zr2 = zr * zr;
                zi2 = zi * zi;
                iteration = iteration + 1;
            }
            checksum = checksum + iteration;
            px = px + 1;
        }
        py = py + 1;
    }
    return checksum;
}
