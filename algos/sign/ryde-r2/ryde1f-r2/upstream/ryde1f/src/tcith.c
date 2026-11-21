/**
 * @file ryde_1f_tcith.c
 * @brief Implementation of tcith.h
 */

#include "tcith.h"
#include "ggm_tree.h"
#include "hash_fips202.h"

#ifdef OPT_AVX
#include "seed_expand_functions_avx.h"
#else
#include "seed_expand_functions_ref.h"
#endif

#ifndef _SHA3_
static inline void ryde_1f_commit(uint8_t pair_node[2][RYDE_1F_SECURITY_BYTES],
                               const uint8_t salt[RYDE_1F_SECURITY_BYTES],
                               const uint32_t i,
                               const uint8_t seed[RYDE_1F_SECURITY_BYTES]) {
    aes_128_commit(pair_node, salt, RYDE_1F_PARAM_TREE_LEAVES + i, seed);
}
#else
static inline void ryde_1f_commit(uint8_t pair_node[2][RYDE_1F_SECURITY_BYTES],
                               const uint8_t salt[RYDE_1F_SALT_BYTES],
                               const uint32_t i,
                               const uint8_t seed[RYDE_1F_SECURITY_BYTES]) {
    uint8_t domain_separator = DOMAIN_SEPARATOR_CMT;
    hash_sha3_ctx ctx;
    hash_sha3_init(&ctx);
    hash_sha3_absorb(&ctx, &domain_separator, sizeof(uint8_t));
    hash_sha3_absorb(&ctx, salt, RYDE_1F_SALT_BYTES);
    hash_sha3_absorb(&ctx, (uint8_t * ) & i, sizeof(uint32_t));
    hash_sha3_absorb(&ctx, seed, RYDE_1F_SECURITY_BYTES);
    hash_sha3_finalize((uint8_t *)pair_node, &ctx);
}
#endif

static inline void ryde_1f_expand_share(uint8_t sample[RYDE_1F_BLOCK_LENGTH][RYDE_1F_SECURITY_BYTES],
                                     const uint8_t salt[RYDE_1F_SECURITY_BYTES],
                                     const uint8_t seed[RYDE_1F_SECURITY_BYTES],
                                     uint8_t length) {
    aes_128_expand_share(sample, salt, seed, length);
}

/**
* \fn void ryde_1f_tcith_shares_init(ryde_1f_tcith_shares_t *rnd_shares)
* \brief This function initializes the TCitH randomized shares as required in the signature scheme
*
* \param[in,out] rnd_shares ryde_1f_tcith_shares_t Representation of the randomized shares
*/
void ryde_1f_tcith_shares_init(ryde_1f_tcith_shares_t *rnd_shares) {
    for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
        rbc_53_vec_init(&(rnd_shares->s[i]), RYDE_1F_PARAM_R - 1);
        rbc_53_mat_init(&(rnd_shares->C[i]), RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
        rbc_53_vec_init(&(rnd_shares->v[i]), RYDE_1F_PARAM_RHO);
    }
}

/**
* \fn void ryde_1f_tcith_shares_clear(ryde_1f_acc_shares_t *rnd_shares)
* \brief This function clears the randomized shares as required in the signature scheme
*
* \param[in,out] acc_shares ryde_1f_acc_shares_t Representation of the randomized shares
*/
void ryde_1f_tcith_shares_clear(ryde_1f_tcith_shares_t *rnd_shares) {
    for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
        rbc_53_vec_clear(rnd_shares->s[i]);
        rbc_53_mat_clear(rnd_shares->C[i]);
        rbc_53_vec_clear(rnd_shares->v[i]);
    }
}


/**
* \fn void ryde_1f_tcith_phi(rbc_53_elt phi_i, size_t i)
* \brief This function implements the mapping phi
*
* \param[out] phi rbc_53_elt representation of element phi(i)
* \param[in] i Integer corresponding with position i
*/
void ryde_1f_tcith_phi(rbc_53_elt phi_i, size_t i) {
    size_t i_cast[RYDE_1F_PARAM_M_WORDS] = {0};
    i_cast[0] = i + 1;
    rbc_53_elt_set_from_uint64(phi_i, (uint64_t *)i_cast);
}


/**
* \fn void ryde_1f_tcith_psi(size_t i, size_t e)
* \brief This function implements the mapping psi
*
* \param[in] i Integer corresponding with position i
* \param[in] e Integer corresponding with iteration e
*/
size_t ryde_1f_tcith_psi(size_t i, size_t e) {
    if (i < RYDE_1F_PARAM_N_2) {
        return i * RYDE_1F_PARAM_TAU + e;
    }
    else {
        return RYDE_1F_PARAM_N_2 * RYDE_1F_PARAM_TAU + (i - RYDE_1F_PARAM_N_2) * RYDE_1F_PARAM_TAU_1 + e;
    }
}


/**
* \fn ryde_1f_tcith_commit(ryde_1f_tcith_commit_t commit, const uint8_t *salt, uint8_t e, size_t i, const uint8_t *seed)
* \brief This function calculates one commitment
*
* \param[out] commit ryde_1f_tcith_commit_t representation of the commitment(s)
* \param[in] salt String containing the salt
* \param[in] e Integer corresponding with iteration e
* \param[in] i Integer corresponding with position i
* \param[in] seed String containing the input seed
*/
void ryde_1f_tcith_commit(ryde_1f_tcith_commit_t commit, const uint8_t *salt, uint8_t e, size_t i, const uint8_t *seed) {
    size_t idx = ryde_1f_tcith_psi(i, e);
    ryde_1f_commit((uint8_t (*)[RYDE_1F_SECURITY_BYTES])commit, salt, (uint32_t)idx, seed);
}


/**
* \fn ryde_1f_tcith_expand_share(rbc_53_vec s, rbc_53_mat_fq C, rbc_53_vec v, const uint8_t *seed, const uint8_t *salt)
* \brief This function samples (s, C, v) from an input seed and salt
*
* \param[out] s rbc_53_vec representation of vector s
* \param[out] C rbc_53_mat_fq representation of matrix C
* \param[out] v rbc_53_vec representation of vector v
* \param[in] seed String containing the input seed
* \param[in] salt String containing the salt
*/
void ryde_1f_tcith_expand_share(rbc_53_vec s, rbc_53_mat_fq C, rbc_53_vec v, const uint8_t *seed, const uint8_t *salt) {
    // Remark: (RYDE_1F_VEC_R_MINUS_ONE_BYTES + RYDE_1F_MAT_FQ_BYTES + RYDE_1F_VEC_RHO_BYTES) is less than or equal to
    // (RYDE_1F_BLOCK_LENGTH * RYDE_1F_SECURITY_BYTES)
    uint8_t random[RYDE_1F_BLOCK_LENGTH * RYDE_1F_SECURITY_BYTES] = {0};
    ryde_1f_expand_share((uint8_t (*)[RYDE_1F_SECURITY_BYTES])random, salt, seed, RYDE_1F_BLOCK_LENGTH);

    // ToDo: Remove line from below
    // printf("\nrandom: "); for(int i = 0 ; i < (RYDE_1F_BLOCK_LENGTH * RYDE_1F_SECURITY_BYTES) ; ++i) printf("%02X", random[i]);

    random[RYDE_1F_VEC_R_MINUS_ONE_BYTES - 1] &= RYDE_1F_VEC_R_MINUS_ONE_MASK;
    random[RYDE_1F_VEC_R_MINUS_ONE_BYTES + RYDE_1F_MAT_FQ_BYTES - 1] &= RYDE_1F_MAT_FQ_MASK;
    random[RYDE_1F_VEC_R_MINUS_ONE_BYTES + RYDE_1F_MAT_FQ_BYTES + RYDE_1F_VEC_RHO_BYTES - 1] &= RYDE_1F_VEC_RHO_MASK;

    rbc_53_vec_from_string(s, RYDE_1F_PARAM_R - 1, &random[0]);
    rbc_53_mat_fq_from_string(C, RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R, &random[RYDE_1F_VEC_R_MINUS_ONE_BYTES]);
    rbc_53_vec_from_string(v, RYDE_1F_PARAM_RHO, &random[RYDE_1F_VEC_R_MINUS_ONE_BYTES + RYDE_1F_MAT_FQ_BYTES]);
}


/**
* \fn void ryde_1f_tcith_expand_challenge_1(rbc_53_mat challenge, const uint8_t *seed_input, const uint8_t *salt)
* \brief This function generates the first challenges from an input seed
*
* \param[out] challenge rbc_53_mat Representation of challenge
* \param[in] seed_input String containing the input seed
* \param[in] salt String containing the salt
*/
void ryde_1f_tcith_expand_challenge_1(rbc_53_mat challenge, const uint8_t *seed_input, const uint8_t *salt) {

    uint8_t random[RYDE_1F_PARAM_CHALLENGE_1_BYTES] = {0};
    seedexpander_shake_t seedexpander;
    seedexpander_shake_init(&seedexpander, seed_input, RYDE_1F_HASH_BYTES, salt, RYDE_1F_SALT_BYTES);

    seedexpander_shake_get_bytes(&seedexpander, random, RYDE_1F_PARAM_CHALLENGE_1_BYTES);
    rbc_53_mat_from_string(challenge, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K, RYDE_1F_PARAM_RHO, random);

    memset(random, 0, RYDE_1F_PARAM_CHALLENGE_1_BYTES);
}

/**
* \fn void ryde_1f_tcith_shift_to_left_array(uint8_t *inout_a, size_t length)
* \brief This function performs a shift to right of the input.
*
* \param[in/out] inout_a uint8_t* Representation of a byte string
* \param[in] length size_t Representation of the byte string length
*/
void ryde_1f_tcith_shift_to_right_array(uint8_t *string, size_t length) {
    for(size_t i = 0; i < length - 1; i++) {
        ryde_1f_tcith_shift_to_right(string[i], string[i + 1], string[i], 1, 8);
    }
    string[length - 1] >>= 1;
}

/**
void ryde_1f_tcith_expand_challenge_2(ryde_1f_tcith_challenge_t challenge, uint8_t *v_grinding, const uint8_t *string_input)
* \brief This function generates the second challenges from an input seed
*
* \param[out] challenge ryde_1f_tcith_challenge_t Representation of challenge
* \param[out] v_grinding String containing w bits
* \param[in] string_input String containing (h2_partial || ctr)
*/
void ryde_1f_tcith_expand_challenge_2(ryde_1f_tcith_challenge_t challenge, uint8_t *v_grinding, const uint8_t *string_input) {
    uint8_t random[RYDE_1F_PARAM_CHALLENGE_2_BYTES + RYDE_1F_PARAM_W_BYTES] = {0}, mask = 0x00;
    memset(challenge, 0, sizeof(ryde_1f_tcith_challenge_t));

    hash_shake(random,
               RYDE_1F_PARAM_CHALLENGE_2_BYTES + RYDE_1F_PARAM_W_BYTES,
               string_input,
               RYDE_1F_HASH_BYTES + sizeof(uint64_t));

    memcpy(v_grinding, &random[RYDE_1F_PARAM_CHALLENGE_2_BYTES], RYDE_1F_PARAM_W_BYTES);  // Obtain v_grinding from random
    v_grinding[RYDE_1F_PARAM_W_BYTES - 1] &= (uint8_t)RYDE_1F_PARAM_W_MASK;
    memset(&random[RYDE_1F_PARAM_CHALLENGE_2_BYTES], 0, RYDE_1F_PARAM_W_BYTES);           // Remove v_grinding from random

    // Challenges concerning N_1
    mask = RYDE_1F_PARAM_N_1_MASK;
    for(size_t i = 0; i < RYDE_1F_PARAM_TAU_1; i++) {
        uint8_t block[RYDE_1F_PARAM_N_1_BYTES] = {0};
        memcpy(block, random, RYDE_1F_PARAM_N_1_BYTES);
        block[RYDE_1F_PARAM_N_1_BYTES - 1] &= mask;
        memcpy((uint8_t *)&challenge[i], block, RYDE_1F_PARAM_N_1_BYTES);
        // Left shift bits: starts
        for (size_t j = 0; j < RYDE_1F_PARAM_N_1_BITS; j++) {
            ryde_1f_tcith_shift_to_right_array(random, RYDE_1F_PARAM_CHALLENGE_2_BYTES);
        }
        // Left shift bits: ends
    }

    // Challenges concerning N_2
    mask = RYDE_1F_PARAM_N_2_MASK;
    for(size_t i = 0; i < RYDE_1F_PARAM_TAU_2; i++) {
        uint8_t block[RYDE_1F_PARAM_N_2_BYTES] = {0};
        memcpy(block, random, RYDE_1F_PARAM_N_2_BYTES);
        block[RYDE_1F_PARAM_N_2_BYTES - 1] &= mask;
        memcpy((uint8_t *)&challenge[i + RYDE_1F_PARAM_TAU_1], block, RYDE_1F_PARAM_N_2_BYTES);
        // Left shift bits: starts
        for (size_t j = 0; j < RYDE_1F_PARAM_N_2_BITS; j++) {
            ryde_1f_tcith_shift_to_right_array(random, RYDE_1F_PARAM_CHALLENGE_2_BYTES);
        }
        // Left shift bits: ends
    }
}

/**
* \fn uint8_t ryde_1f_tcith_discard_input_challenge_2(const uint8_t *v_grinding)
* \brief This function determines if the w most significant bits of the input are zero.
*
* \param[in] v_grinding String containing the input seed
*/
uint8_t ryde_1f_tcith_discard_input_challenge_2(const uint8_t *v_grinding) {
    uint8_t output = 0x00;
    uint8_t mask = RYDE_1F_PARAM_W_MASK;
    for(size_t i = 0; i < RYDE_1F_PARAM_W_BYTES; i++) {
        output |= (uint8_t)((v_grinding[i] & mask) != 0);
        mask = 0xFF;
    }

    return output;
}

/**
* \fn void ryde_1f_pack_matrices_and_vectors(uint8_t *output, const rbc_53_vec *aux_s, const rbc_53_mat_fq *aux_C, const rbc_53_vec mid_alpha)
* \brief This function parse/pack the list of vectors aux_s, aux_C, and mid_alpha into a byte string.
*
* \param[out] output uint8_t* String containing the packed list of elements aux_s (vector), aux_C (matrix), aux_v (vector)
* \param[in] aux_s rbc_53_vec* Representation of the list of the vectors concerning aux_s
* \param[in] aux_C rbc_53_mat_fq* Representation of the list of the vectors concerning aux_C
* \param[in] mid_alpha rbc_53_vec* Representation of the list of the vectors concerning aux_v
*/
void ryde_1f_pack_matrices_and_vectors(uint8_t *output, const rbc_53_vec *aux_s, const rbc_53_mat_fq *aux_C, const rbc_53_vec *mid_alpha) {
    const size_t BLOCK_VEC = ((RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU * RYDE_1F_PARAM_M + 7) / 8;
    const size_t BLOCK_MAT = (RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU * (RYDE_1F_PARAM_N - RYDE_1F_PARAM_R) + 7) / 8;

    memset(output, 0, BLOCK_VEC + BLOCK_MAT);

    size_t element = 0;
    rbc_53_vec vectors;
    rbc_53_vec_init(&vectors, (RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU);

    for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
        for (size_t j = 0; j < (RYDE_1F_PARAM_R - 1); j++) {
            rbc_53_elt_set(vectors[element], aux_s[i][j]);
            element += 1;
        }
    }

    for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++){
        for(size_t j = 0; j < RYDE_1F_PARAM_RHO; j++){
            rbc_53_elt_set(vectors[element], mid_alpha[i][j]);
            element += 1;
        }
    }
    rbc_53_vec_to_string(output, vectors, (RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU);
    rbc_53_vec_clear(vectors);

    uint32_t WORDS = (RYDE_1F_PARAM_N - RYDE_1F_PARAM_R + 63) / 64;
    element = 0;
    rbc_53_mat_fq matrices;
    rbc_53_mat_fq_init(&matrices, RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
    for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++){
        for(size_t j = 0; j < RYDE_1F_PARAM_R; j++) {
            memcpy(matrices[element], aux_C[i][j], WORDS * sizeof(uint64_t));
            element += 1;
        }
    }
    rbc_53_mat_fq_to_string(&output[BLOCK_VEC], matrices, RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
    rbc_53_mat_fq_clear(matrices);
}

/**
* \fn void ryde_1f_unpack_matrices_and_vectors(rbc_53_vec *aux_s, rbc_53_mat_fq *aux_C, rbc_53_vec *mid_alpha, const uint8_t *output)
* \brief This function unparse/unpack the list of vectors aux_s, aux_C, and mid_alpha from a byte string.
*
* \param[out] aux_s rbc_53_vec* Representation of the list of the vectors concerning aux_s
* \param[out] aux_C rbc_53_mat_fq* Representation of the list of the vectors concerning aux_C
* \param[out] mid_alpha rbc_53_vec* Representation of the list of the vectors concerning aux_v
* \param[in] output uint8_t* String containing the packed list of elements aux_s (vector), aux_C (matrix), aux_v (vector)
*/
void ryde_1f_unpack_matrices_and_vectors(rbc_53_vec *aux_s, rbc_53_mat_fq *aux_C, rbc_53_vec *mid_alpha, const uint8_t *input) {

    // We first determine if the input is valid (i.e., it has the right amount of bits)
    size_t TMP_VEC = ((RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU * RYDE_1F_PARAM_M) % 8;
    uint8_t MASK_VEC = 0xFF;
    if (TMP_VEC) { MASK_VEC = (1 << TMP_VEC) - 1; }

    size_t TMP_MAT = (RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU * (RYDE_1F_PARAM_N - RYDE_1F_PARAM_R)) % 8;
    uint8_t MASK_MAT = 0xFF;
    if (TMP_MAT) { MASK_MAT = (1 << TMP_MAT) - 1; }

    const size_t BLOCK_VEC = ((RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU * RYDE_1F_PARAM_M + 7) / 8;
    const size_t BLOCK_MAT = (RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU * (RYDE_1F_PARAM_N - RYDE_1F_PARAM_R) + 7) / 8;

    uint8_t invalid_input_vec = (input[BLOCK_VEC - 1] & MASK_VEC) ^ input[BLOCK_VEC - 1];
    uint8_t invalid_input_mat = (input[BLOCK_VEC + BLOCK_MAT- 1] & MASK_MAT) ^ input[BLOCK_VEC + BLOCK_MAT - 1];
    if (invalid_input_vec | invalid_input_mat) {
        // This branch is for avoiding trivial forgery on the bytes determining aux_s, aux_C, and mid_alpha
        // If the input byt string has more bits than expected, then return zero by default
        for(size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
            rbc_53_vec_set_zero(aux_s[i], RYDE_1F_PARAM_R - 1);
            rbc_53_mat_fq_set_zero(aux_C[i], RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
            rbc_53_vec_set_zero(mid_alpha[i], RYDE_1F_PARAM_RHO);
        }
    }
    else {
        size_t element = 0;
        rbc_53_vec vectors;
        rbc_53_vec_init(&vectors, (RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU);
        rbc_53_vec_from_string(vectors, (RYDE_1F_PARAM_R - 1 + RYDE_1F_PARAM_RHO) * RYDE_1F_PARAM_TAU, input);

        for (size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
            for (size_t j = 0; j < (RYDE_1F_PARAM_R - 1); j++) {
                rbc_53_elt_set(aux_s[i][j], vectors[element]);
                element += 1;
            }
        }

        for (size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
            for (size_t j = 0; j < RYDE_1F_PARAM_RHO; j++) {
                rbc_53_elt_set(mid_alpha[i][j], vectors[element]);
                element += 1;
            }
        }
        rbc_53_vec_clear(vectors);


        uint32_t WORDS = (RYDE_1F_PARAM_N - RYDE_1F_PARAM_R + 63) / 64;
        element = 0;
        rbc_53_mat_fq matrices;
        rbc_53_mat_fq_init(&matrices, RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
        rbc_53_mat_fq_from_string(matrices, RYDE_1F_PARAM_R * RYDE_1F_PARAM_TAU, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R, &input[BLOCK_VEC]);

        for (size_t i = 0; i < RYDE_1F_PARAM_TAU; i++) {
            for (size_t j = 0; j < RYDE_1F_PARAM_R; j++) {
                memcpy(aux_C[i][j], matrices[element], WORDS * sizeof(uint64_t));
                element += 1;
            }
        }
        rbc_53_mat_fq_clear(matrices);
    }
}
