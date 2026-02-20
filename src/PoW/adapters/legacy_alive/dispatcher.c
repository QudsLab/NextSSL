#include "../../core/pow_types.h"
#include <string.h>

extern POWAlgoAdapter* pow_adapter_md5(void);
extern POWAlgoAdapter* pow_adapter_sha1(void);
extern POWAlgoAdapter* pow_adapter_ripemd160(void);
extern POWAlgoAdapter* pow_adapter_whirlpool(void);
extern POWAlgoAdapter* pow_adapter_nt(void);

POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "md5") == 0) return pow_adapter_md5();
    if (strcmp(algorithm_id, "sha1") == 0) return pow_adapter_sha1();
    if (strcmp(algorithm_id, "ripemd160") == 0) return pow_adapter_ripemd160();
    if (strcmp(algorithm_id, "whirlpool") == 0) return pow_adapter_whirlpool();
    if (strcmp(algorithm_id, "nt") == 0) return pow_adapter_nt();
    
    return NULL;
}
