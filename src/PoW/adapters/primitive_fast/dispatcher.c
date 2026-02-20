#include "../../core/pow_types.h"
#include <string.h>

// Forward declarations of adapter getters
extern POWAlgoAdapter* pow_adapter_sha256(void);
extern POWAlgoAdapter* pow_adapter_blake3(void);

// Dispatcher function
POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "sha256") == 0) {
        return pow_adapter_sha256();
    }
    if (strcmp(algorithm_id, "blake3") == 0) {
        return pow_adapter_blake3();
    }
    
    // Unknown algorithm for this partial module
    return NULL;
}
