#include "../core/pow_types.h"
#include <string.h>

extern POWAlgoAdapter* pow_adapter_sha256(void);
extern POWAlgoAdapter* pow_adapter_sha512(void);
extern POWAlgoAdapter* pow_adapter_blake3(void);
extern POWAlgoAdapter* pow_adapter_blake2b(void);
extern POWAlgoAdapter* pow_adapter_blake2s(void);

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
    
    if (strcmp(algorithm_id, "sha256") == 0) return pow_adapter_sha256();
    if (strcmp(algorithm_id, "sha512") == 0) return pow_adapter_sha512();
    if (strcmp(algorithm_id, "blake3") == 0) return pow_adapter_blake3();
    if (strcmp(algorithm_id, "blake2b") == 0) return pow_adapter_blake2b();
    if (strcmp(algorithm_id, "blake2s") == 0) return pow_adapter_blake2s();
    
    if (strcmp(algorithm_id, "argon2id") == 0) return pow_adapter_argon2id();
    if (strcmp(algorithm_id, "argon2i") == 0) return pow_adapter_argon2i();
    if (strcmp(algorithm_id, "argon2d") == 0) return pow_adapter_argon2d();
    
    if (strcmp(algorithm_id, "shake128") == 0) return pow_adapter_shake128();
    if (strcmp(algorithm_id, "shake256") == 0) return pow_adapter_shake256();
    if (strcmp(algorithm_id, "sha3_256") == 0) return pow_adapter_sha3_256();
    if (strcmp(algorithm_id, "sha3_512") == 0) return pow_adapter_sha3_512();
    if (strcmp(algorithm_id, "keccak_256") == 0) return pow_adapter_keccak_256();
    
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
