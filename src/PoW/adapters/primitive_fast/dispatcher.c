#include "../../core/pow_types.h"
#include <string.h>

extern POWAlgoAdapter* pow_adapter_sha256(void);
extern POWAlgoAdapter* pow_adapter_sha512(void);
extern POWAlgoAdapter* pow_adapter_blake3(void);
extern POWAlgoAdapter* pow_adapter_blake2b(void);
extern POWAlgoAdapter* pow_adapter_blake2s(void);

// Dispatcher function
POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "sha256") == 0) return pow_adapter_sha256();
    if (strcmp(algorithm_id, "sha512") == 0) return pow_adapter_sha512();
    if (strcmp(algorithm_id, "blake3") == 0) return pow_adapter_blake3();
    if (strcmp(algorithm_id, "blake2b") == 0) return pow_adapter_blake2b();
    if (strcmp(algorithm_id, "blake2s") == 0) return pow_adapter_blake2s();
    
    // Unknown algorithm for this partial module
    return NULL;
}
