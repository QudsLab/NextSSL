#include "../core/pow_types.h"
#include <string.h>

// Primitive Fast
extern POWAlgoAdapter* pow_adapter_sha256(void);
extern POWAlgoAdapter* pow_adapter_blake3(void);

// Primitive Memory Hard
extern POWAlgoAdapter* pow_adapter_argon2id(void);
extern POWAlgoAdapter* pow_adapter_argon2i(void);
extern POWAlgoAdapter* pow_adapter_argon2d(void);

// Primitive Sponge XOF
extern POWAlgoAdapter* pow_adapter_shake128(void);
extern POWAlgoAdapter* pow_adapter_shake256(void);
extern POWAlgoAdapter* pow_adapter_sha3_256(void);
extern POWAlgoAdapter* pow_adapter_sha3_512(void);
extern POWAlgoAdapter* pow_adapter_keccak_256(void);

POWAlgoAdapter* pow_adapter_get(const char* algorithm_id) {
    if (!algorithm_id) return NULL;
    
    if (strcmp(algorithm_id, "sha256") == 0) return pow_adapter_sha256();
    if (strcmp(algorithm_id, "blake3") == 0) return pow_adapter_blake3();
    
    if (strcmp(algorithm_id, "argon2id") == 0) return pow_adapter_argon2id();
    if (strcmp(algorithm_id, "argon2i") == 0) return pow_adapter_argon2i();
    if (strcmp(algorithm_id, "argon2d") == 0) return pow_adapter_argon2d();
    
    if (strcmp(algorithm_id, "shake128") == 0) return pow_adapter_shake128();
    if (strcmp(algorithm_id, "shake256") == 0) return pow_adapter_shake256();
    if (strcmp(algorithm_id, "sha3_256") == 0) return pow_adapter_sha3_256();
    if (strcmp(algorithm_id, "sha3_512") == 0) return pow_adapter_sha3_512();
    if (strcmp(algorithm_id, "keccak_256") == 0) return pow_adapter_keccak_256();
    
    return NULL;
}
