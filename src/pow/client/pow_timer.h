/* pow_timer.h — high-resolution solve timer */
#ifndef POW_TIMER_H
#define POW_TIMER_H

#include <stdint.h>

/* Start the timer. Returns an opaque tick count. */
uint64_t pow_timer_start(void);

/* Stop the timer and return elapsed time in seconds. */
double   pow_timer_elapsed(uint64_t start_tick);

#endif /* POW_TIMER_H */
