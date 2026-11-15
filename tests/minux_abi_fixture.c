/* Copyright 2026 Nils Kopal. Apache-2.0. Real SysV register/stack oracle. */
#include <stdint.h>

int64_t mlc_seven(int64_t a, int64_t b, int64_t c, int64_t d,
                  int64_t e, int64_t f, int64_t g) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g;
}

double mlc_mixed(int64_t a, double b, int64_t c, double d,
                  int64_t e, double f, int64_t g, double h) {
    return (double)(a+c+e+g)+b+d+f+h;
}

double mlc_ten_floats(double a, double b, double c, double d, double e,
                      double f, double g, double h, double i, double j) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j;
}

double mlc_out(double value, double *result) {
    *result = value+0.5;
    return value;
}
