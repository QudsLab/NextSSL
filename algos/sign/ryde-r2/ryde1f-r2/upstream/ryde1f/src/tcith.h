/**
 * @file ryde_1f_tcith.h
 * @brief Functions concerning the TCitH part of the RYDE scheme
 */

#ifndef RYDE_1F_TCITH_H
#define RYDE_1F_TCITH_H

#include "rbc_53_vec.h"
#include "rbc_53_mat.h"
#include "rbc_53_mat_fq.h"
#include "parameters.h"
#include "parsing.h"

#define DOMAIN_SEPARATOR_MESSAGE 0
#define DOMAIN_SEPARATOR_HASH1 1
#define DOMAIN_SEPARATOR_HASH2 2

#define RYDE_1F_BLOCK_LENGTH ((RYDE_1F_VEC_R_MINUS_ONE_BYTES + RYDE_1F_MAT_FQ_BYTES + RYDE_1F_VEC_RHO_BYTES + (RYDE_1F_SECURITY_BYTES - 1)) / RYDE_1F_SECURITY_BYTES)

#if (RYDE_1F_BLOCK_LENGTH > 0xFF)
#error RYDE_1F_BLOCK_LENGTH must fit in uint8_t
#endif

typedef struct {
    rbc_53_vec s[RYDE_1F_PARAM_TAU];
    rbc_53_mat C[RYDE_1F_PARAM_TAU];
    rbc_53_vec v[RYDE_1F_PARAM_TAU];
} ryde_1f_tcith_shares_t;

typedef uint8_t ryde_1f_tcith_alpha_t[RYDE_1F_VEC_RHO_BYTES];
typedef uint8_t ryde_1f_tcith_share_s_t[RYDE_1F_VEC_R_MINUS_ONE_BYTES];
typedef uint8_t ryde_1f_tcith_share_C_t[RYDE_1F_MAT_FQ_BYTES];
typedef size_t ryde_1f_tcith_challenge_t[RYDE_1F_PARAM_TAU];

void ryde_1f_tcith_shares_init(ryde_1f_tcith_shares_t *rnd_shares);
void ryde_1f_tcith_shares_clear(ryde_1f_tcith_shares_t *rnd_shares);

typedef uint8_t ryde_1f_tcith_seed_t[RYDE_1F_SECURITY_BYTES];
typedef uint8_t ryde_1f_tcith_commit_t[RYDE_1F_HASH_BYTES];

void ryde_1f_tcith_phi(rbc_53_elt phi_i, size_t i);
size_t ryde_1f_tcith_psi(size_t i, size_t e);
void ryde_1f_tcith_commit(ryde_1f_tcith_commit_t commit, const uint8_t *salt, uint8_t e, size_t i, const uint8_t *seed);
void ryde_1f_tcith_expand_share(rbc_53_vec s, rbc_53_mat_fq C, rbc_53_vec v, const uint8_t *seed, const uint8_t *salt);
void ryde_1f_tcith_expand_challenge_1(rbc_53_mat challenge, const uint8_t *seed_input, const uint8_t *salt);
void ryde_1f_tcith_expand_challenge_2(ryde_1f_tcith_challenge_t challenge, uint8_t *v_grinding, const uint8_t *string_input);
uint8_t ryde_1f_tcith_discard_input_challenge_2(const uint8_t *v_grinding);

#define ryde_1f_tcith_shift_to_right(shiftOut, highIn, lowIn, shift, DigitSize)  \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << ((DigitSize) - (shift)));
void ryde_1f_tcith_shift_to_right_array(uint8_t *string, size_t length);

void ryde_1f_pack_matrices_and_vectors(uint8_t *output, const rbc_53_vec *aux_s, const rbc_53_mat_fq *aux_C, const rbc_53_vec *mid_alpha);
void ryde_1f_unpack_matrices_and_vectors(rbc_53_vec *aux_s, rbc_53_mat_fq *aux_C, rbc_53_vec *mid_alpha, const uint8_t *output);

#endif
