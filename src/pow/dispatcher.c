/* dispatcher.c — delegates algorithm validation to the engine. */
#include "dispatcher.h"
#include "pow_engine.h"
int pow_dispatcher_valid(const char *name) { return pow_engine_algo_valid(name); }
