/* dispatcher.h — algorithm name validation for the PoW subsystem */
#ifndef POW_DISPATCHER_H
#define POW_DISPATCHER_H

/* Returns 1 if name is a valid registered PoW algorithm, 0 otherwise. */
int pow_dispatcher_valid(const char *name);

#endif /* POW_DISPATCHER_H */
