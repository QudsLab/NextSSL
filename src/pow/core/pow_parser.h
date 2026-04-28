/* pow_parser.h — challenge/solution encode/decode and name normalisation */
#ifndef POW_PARSER_H
#define POW_PARSER_H

#include "pow_types.h"
#include <stddef.h>

/* Normalise an algorithm name in-place.
 * Converts underscores to hyphens so "sha3_256" becomes "sha3-256".
 * This lets callers use either form; canonical is always hyphen. */
void pow_algo_name_normalise(char *name);

/* Decode a base64-encoded JSON challenge string into *out.
 * Returns 0 on success. */
int pow_challenge_decode(const char   *base64_str,
                         pow_challenge_t *out);

/* Encode a challenge to a NUL-terminated base64-JSON string in out_buf.
 * Returns 0 on success, -1 if buffer too small. */
int pow_challenge_encode(const pow_challenge_t *challenge,
                         char                  *out_buf,
                         size_t                 out_len);

/* Encode/decode solution — same convention as challenge. */
int pow_solution_decode(const char     *base64_str,
                        pow_solution_t *out);
int pow_solution_encode(const pow_solution_t *solution,
                        char                 *out_buf,
                        size_t                out_len);

#endif /* POW_PARSER_H */
