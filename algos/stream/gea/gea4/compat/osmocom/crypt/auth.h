/* ours: replaces libosmocore's crypt/auth.h (needs linuxlist, plugins, talloc). Declares the three tiny conversion helpers
 * the wired files call; their definitions are verbatim excerpts of src/gsm/auth_core.c in shim.c. */
#pragma once
#include <stddef.h>
#include <stdint.h>
void osmo_c4(uint8_t *ck, const uint8_t *kc);
void osmo_auth_c3(uint8_t kc[], const uint8_t ck[], const uint8_t ik[]);
void osmo_auth_c2(uint8_t sres[4], const uint8_t *res, size_t res_len, uint8_t sres_deriv_func);
