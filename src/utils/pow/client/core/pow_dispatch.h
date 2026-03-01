#ifndef nextssl_POW_DISPATCH_H
#define nextssl_POW_DISPATCH_H

#include "pow_hash_types.h"

#ifdef __cplusplus
extern "C" {
#endif

PoW_HashFunc pow_get_hash_func(PoWAlgorithm algo);

#ifdef __cplusplus
}
#endif

#endif
