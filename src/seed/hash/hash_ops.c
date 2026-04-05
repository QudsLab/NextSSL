/* hash_ops.c — Hash Vtable Instances for Seed System (Plan 404)
 *
 * The actual vtable instances (sha256_ops, blake3_ops, etc.) are defined in
 * src/hash/interface/hash_registry.c and linked into the build.
 *
 * This translation unit exists so seed/hash/ is a self-contained module:
 * clients #include "hash_ops.h" to obtain all extern declarations without
 * reaching into src/hash/interface/ directly.
 *
 * No new symbols are defined here — all vtable objects are owned by the
 * main hash registry to avoid duplicate symbol link errors.
 */
#include "hash_ops.h"
