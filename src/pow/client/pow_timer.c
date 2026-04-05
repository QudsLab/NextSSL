/* pow_timer.c */
#include "pow_timer.h"
#include <stdint.h>

#ifdef _WIN32
#  include <windows.h>
uint64_t pow_timer_start(void) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (uint64_t)li.QuadPart;
}
double pow_timer_elapsed(uint64_t start_tick) {
    LARGE_INTEGER end, freq;
    QueryPerformanceCounter(&end);
    QueryPerformanceFrequency(&freq);
    return (double)(end.QuadPart - (LONGLONG)start_tick) / (double)freq.QuadPart;
}
#else
#  include <time.h>
uint64_t pow_timer_start(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}
double pow_timer_elapsed(uint64_t start_tick) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
    return (double)(now - start_tick) / 1.0e9;
}
#endif
