#include <stdint.h>
#include <xmmintrin.h>
uint32_t phase8_mxcsr_read(void) { return _mm_getcsr(); }
void phase8_mxcsr_write(uint32_t value) { _mm_setcsr(value); }
