#include "../../core/pow_types.h"
#include <string.h>

extern POWAlgoAdapter* pow_adapter_argon2id(void);
extern POWAlgoAdapter* pow_adapter_argon2i(void);
extern POWAlgoAdapter* pow_adapter_argon2d(void);

POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "argon2id") == 0) {
        return pow_adapter_argon2id();
    }
    if (strcmp(algorithm_id, "argon2i") == 0) {
        return pow_adapter_argon2i();
    }
    if (strcmp(algorithm_id, "argon2d") == 0) {
        return pow_adapter_argon2d();
    }
    
    return NULL;
}
