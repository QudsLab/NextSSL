#include "timer.h"
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

uint64_t pow_timer_start(void) {
#ifdef _WIN32
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (uint64_t)li.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
#endif
}

double pow_timer_stop(uint64_t start_time) {
#ifdef _WIN32
    LARGE_INTEGER end, freq;
    QueryPerformanceCounter(&end);
    QueryPerformanceFrequency(&freq);
    return (double)(end.QuadPart - start_time) / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t end_time = (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
    return (double)(end_time - start_time) / 1000000000.0;
#endif
}
