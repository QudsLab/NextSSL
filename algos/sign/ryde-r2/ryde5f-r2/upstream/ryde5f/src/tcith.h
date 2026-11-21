/**
 * @file ryde_5f_tcith.h
 * @brief Functions concerning the TCitH part of the RYDE scheme
 */

#ifndef RYDE_5F_TCITH_H
#define RYDE_5F_TCITH_H

#include "rbc_67_vec.h"
#include "rbc_67_mat.h"
#include "rbc_67_mat_fq.h"
#include "parameters.h"
#include "parsing.h"

#define DOMAIN_SEPARATOR_MESSAGE 0
#define DOMAIN_SEPARATOR_HASH1 1
#define DOMAIN_SEPARATOR_HASH2 2

#define RYDE_5F_BLOCK_LENGTH ((RYDE_5F_VEC_R_MINUS_ONE_BYTES + RYDE_5F_MAT_FQ_BYTES + RYDE_5F_VEC_RHO_BYTES + (RYDE_5F_SECURITY_BYTES - 1)) / RYDE_5F_SECURITY_BYTES)

#if (RYDE_5F_BLOCK_LENGTH > 0xFF)
#error RYDE_5F_BLOCK_LENGTH must fit in uint8_t
#endif

typedef struct {
    rbc_67_vec s[RYDE_5F_PARAM_TAU];
    rbc_67_mat C[RYDE_5F_PARAM_TAU];
    rbc_67_vec v[RYDE_5F_PARAM_TAU];
} ryde_5f_tcith_shares_t;

typedef uint8_t ryde_5f_tcith_alpha_t[RYDE_5F_VEC_RHO_BYTES];
typedef uint8_t ryde_5f_tcith_share_s_t[RYDE_5F_VEC_R_MINUS_ONE_BYTES];
typedef uint8_t ryde_5f_tcith_share_C_t[RYDE_5F_MAT_FQ_BYTES];
typedef size_t ryde_5f_tcith_challenge_t[RYDE_5F_PARAM_TAU];

void ryde_5f_tcith_shares_init(ryde_5f_tcith_shares_t *rnd_shares);
void ryde_5f_tcith_shares_clear(ryde_5f_tcith_shares_t *rnd_shares);

typedef uint8_t ryde_5f_tcith_seed_t[RYDE_5F_SECURITY_BYTES];
typedef uint8_t ryde_5f_tcith_commit_t[RYDE_5F_HASH_BYTES];

void ryde_5f_tcith_phi(rbc_67_elt phi_i, size_t i);
size_t ryde_5f_tcith_psi(size_t i, size_t e);
void ryde_5f_tcith_commit(ryde_5f_tcith_commit_t commit, const uint8_t *salt, uint8_t e, size_t i, const uint8_t *seed);
void ryde_5f_tcith_expand_share(rbc_67_vec s, rbc_67_mat_fq C, rbc_67_vec v, const uint8_t *seed, const uint8_t *salt);
void ryde_5f_tcith_expand_challenge_1(rbc_67_mat challenge, const uint8_t *seed_input, const uint8_t *salt);
void ryde_5f_tcith_expand_challenge_2(ryde_5f_tcith_challenge_t challenge, uint8_t *v_grinding, const uint8_t *string_input);
uint8_t ryde_5f_tcith_discard_input_challenge_2(const uint8_t *v_grinding);

#define ryde_5f_tcith_shift_to_right(shiftOut, highIn, lowIn, shift, DigitSize)  \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << ((DigitSize) - (shift)));
void ryde_5f_tcith_shift_to_right_array(uint8_t *string, size_t length);

void ryde_5f_pack_matrices_and_vectors(uint8_t *output, const rbc_67_vec *aux_s, const rbc_67_mat_fq *aux_C, const rbc_67_vec *mid_alpha);
void ryde_5f_unpack_matrices_and_vectors(rbc_67_vec *aux_s, rbc_67_mat_fq *aux_C, rbc_67_vec *mid_alpha, const uint8_t *output);

#endif
