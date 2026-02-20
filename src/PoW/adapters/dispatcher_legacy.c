#include "../core/pow_types.h"
#include <string.h>

// Legacy Alive
extern POWAlgoAdapter* pow_adapter_md5(void);
extern POWAlgoAdapter* pow_adapter_sha1(void);
extern POWAlgoAdapter* pow_adapter_ripemd160(void);
extern POWAlgoAdapter* pow_adapter_whirlpool(void);
extern POWAlgoAdapter* pow_adapter_nt(void);

// Legacy Unsafe
extern POWAlgoAdapter* pow_adapter_md2(void);
extern POWAlgoAdapter* pow_adapter_md4(void);
extern POWAlgoAdapter* pow_adapter_sha0(void);
extern POWAlgoAdapter* pow_adapter_has160(void);
extern POWAlgoAdapter* pow_adapter_ripemd128(void);
extern POWAlgoAdapter* pow_adapter_ripemd256(void);
extern POWAlgoAdapter* pow_adapter_ripemd320(void);

POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "md5") == 0) return pow_adapter_md5();
    if (strcmp(algorithm_id, "sha1") == 0) return pow_adapter_sha1();
    if (strcmp(algorithm_id, "ripemd160") == 0) return pow_adapter_ripemd160();
    if (strcmp(algorithm_id, "whirlpool") == 0) return pow_adapter_whirlpool();
    if (strcmp(algorithm_id, "nt") == 0) return pow_adapter_nt();
    
    if (strcmp(algorithm_id, "md2") == 0) return pow_adapter_md2();
    if (strcmp(algorithm_id, "md4") == 0) return pow_adapter_md4();
    if (strcmp(algorithm_id, "sha0") == 0) return pow_adapter_sha0();
    if (strcmp(algorithm_id, "has160") == 0) return pow_adapter_has160();
    if (strcmp(algorithm_id, "ripemd128") == 0) return pow_adapter_ripemd128();
    if (strcmp(algorithm_id, "ripemd256") == 0) return pow_adapter_ripemd256();
    if (strcmp(algorithm_id, "ripemd320") == 0) return pow_adapter_ripemd320();
    
    return NULL;
}
