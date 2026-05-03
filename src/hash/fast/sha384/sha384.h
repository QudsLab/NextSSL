/* sha384.h — SHA-384 thin alias header (Plan 202)
 *
 * SHA-384 shares SHA512_CTX with SHA-512.  See sha512.h for the context
 * definition and for sha384_init / sha384_final / sha384_hash declarations.
 *
 * Including this header pulls in sha512.h and provides a typedef:
 *     SHA384_CTX  ≡  SHA512_CTX
 *
 * Client code that wants only SHA-384 can include this header instead of
 * sha512.h for clarity.  Both headers are safe to include together.
 */
#ifndef SHA384_H
#define SHA384_H

#include "sha512.h"

/* SHA-384 uses the same context struct as SHA-512. */
typedef SHA512_CTX SHA384_CTX;

#endif /* SHA384_H */
