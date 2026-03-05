/**
 * @file adapters/dispatcher_lite.c
 * @brief PoW algorithm dispatcher -- LITE BUILD
 *
 * Registers only the 4 algorithms supported in the lite build:
 *   sha256, sha512, blake3, argon2id
 *
 * Full build uses dispatcher_main.c (28 algorithms).
 * Do NOT link both dispatcher_lite.c and dispatcher_main.c.
 */

#include "../core/pow_types.h"
#include <string.h>

/* Forward declarations for lite adapters */
extern POWAlgoAdapter *pow_adapter_sha256(void);
extern POWAlgoAdapter *pow_adapter_sha512(void);
extern POWAlgoAdapter *pow_adapter_blake3(void);
extern POWAlgoAdapter *pow_adapter_argon2id(void);

POWAlgoAdapter *pow_adapter_get(const char *algorithm_id) {
    if (!algorithm_id) return NULL;
    if (strcmp(algorithm_id, "sha256")   == 0) return pow_adapter_sha256();
    if (strcmp(algorithm_id, "sha512")   == 0) return pow_adapter_sha512();
    if (strcmp(algorithm_id, "blake3")   == 0) return pow_adapter_blake3();
    if (strcmp(algorithm_id, "argon2id") == 0) return pow_adapter_argon2id();
    return NULL;
}
