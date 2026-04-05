/* dispatcher.h — single point of adapter lookup for the entire pow system */
#ifndef POW_DISPATCHER_H
#define POW_DISPATCHER_H

#include "core/pow_types.h"

/* Resolve a canonical hyphen-form algorithm name to its adapter.
 * Returns NULL if the name is not registered. */
const pow_adapter_t *pow_adapter_get(const char *name);

#endif /* POW_DISPATCHER_H */
