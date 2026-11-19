#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <xmmintrin.h>
uint32_t phase9_mxcsr_read(void) { return _mm_getcsr(); }
void phase9_mxcsr_write(uint32_t value) { _mm_setcsr(value); }
/* Representation access only: no float conversions, comparison, or arithmetic. */
static uint64_t payload(uint64_t raw) {
    if ((raw & 7) == 5) return (uint32_t)(raw >> 3);
    if ((raw & 7) == 0 && raw) {
        uint32_t kind; uint64_t bits;
        memcpy(&kind, (const void *)(uintptr_t)raw, sizeof(kind));
        if (kind != 4) abort();
        memcpy(&bits, (const void *)(uintptr_t)(raw + 8), sizeof(bits));
        return bits;
    }
    return raw;
}
uint32_t phase9_payload_low(uint64_t raw) { return (uint32_t)payload(raw); }
uint32_t phase9_payload_high(uint64_t raw) { return (uint32_t)(payload(raw) >> 32); }
/* Persistent exact-bit input boxes, created before any measured FP mode.
   Foreign static objects are never passed to the allocator or freed. */
struct input_box { uint32_t kind, padding; uint64_t bits; };
static struct input_box boxes[32];
static unsigned next_box;
uintptr_t phase9_box(uint32_t hi, uint32_t lo) {
    if (next_box >= 32) abort();
    struct input_box *box = &boxes[next_box++];
    box->kind = 4; box->padding = 0; box->bits = ((uint64_t)hi << 32) | lo;
    return (uintptr_t)box;
}
