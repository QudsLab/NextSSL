#ifndef POW_TIMER_H
#define POW_TIMER_H

#include <stdint.h>

/**
 * Start a high-precision timer.
 * @return Opaque timestamp.
 */
uint64_t pow_timer_start(void);

/**
 * Stop the timer and get elapsed seconds.
 * @param start_time Timestamp from pow_timer_start.
 * @return Elapsed time in seconds.
 */
double pow_timer_stop(uint64_t start_time);

#endif // POW_TIMER_H
