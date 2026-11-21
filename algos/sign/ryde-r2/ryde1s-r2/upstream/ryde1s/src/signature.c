/** 
 * @file ryde_1s_sign.c
 * @brief Implementation of sign.h
 */

#include "string.h"
#include <assert.h>
#include "randombytes.h"
#include "hash_fips202.h"
#include "parameters.h"
#include "parsing.h"
#include "tcith.h"
#include "ggm_tree.h"
#include "signature.h"


/**
 * \fn int ryde_1s_sign(uint8_t* signature, const uint8_t* message, size_t message_size, const uint8_t* sk)
 * \brief Sign algorithm of the RYDE scheme
 *
 * \param[out] signature String containing the signature
 * \param[in] message String containing the message to be signed
 * \param[in] message_size Length of the message to be signed
 * \param[in] sk String containing the secret key
 * \return EXIT_SUCCESS if no issues appear when sampling the salt and master seed. Otherwise, it returns EXIT_FAILURE.
 */
int ryde_1s_sign(uint8_t* signature, const uint8_t* message, size_t message_size, const uint8_t* sk) {



  // ---------------------------------------------------------------------------------------------------- Initialization

  rbc_53_field_init();

  if (message == NULL || signature == NULL || sk == NULL) { return EXIT_FAILURE; }
  if (message_size <= 0) { return EXIT_FAILURE; }
  memset(signature, 0, RYDE_1S_SIGNATURE_BYTES);

  // Setup variables related to randomness, hash and challenges
  ryde_1s_tcith_commit_t commit = {0};

  ryde_1s_tcith_seed_t seed = {0};
  ryde_1s_ggm_tree_leaves_t seeds = {0};
  ryde_1s_ggm_tree_t tree = {0};
  uint8_t salt_and_rseed[RYDE_1S_SALT_BYTES + RYDE_1S_SECURITY_BYTES] = {0};
  uint8_t salt[RYDE_1S_SALT_BYTES] = {0};

  uint8_t domain_separator;
  uint8_t h1[RYDE_1S_HASH_BYTES] = {0};
  uint8_t h2[RYDE_1S_HASH_BYTES] = {0};
  uint8_t v_grinding[RYDE_1S_PARAM_W_BYTES] = {0};
  hash_sha3_ctx ctx_m, ctx_h1, ctx_h2;
  hash_sha3_init(&ctx_m);
  hash_sha3_init(&ctx_h1);

  uint8_t m_digest[RYDE_1S_HASH_BYTES] = {0};

  // Setup variables related to base
  rbc_53_vec overline_v, acc_v[RYDE_1S_PARAM_TAU];
  rbc_53_vec overline_s_, acc_s[RYDE_1S_PARAM_TAU];
  rbc_53_mat_fq overline_C, acc_C[RYDE_1S_PARAM_TAU];
  rbc_53_mat overline_D;
  ryde_1s_tcith_shares_t base;
  rbc_53_mat gamma;
  rbc_53_vec sC, base_x, base_xL, base_xR, base_a, mid_a, mid_x, mid_xL, mid_xR, tmp_nk, tmp_nk1, tmp_nr, aux_nr;
  ryde_1s_tcith_alpha_t base_a_str[RYDE_1S_PARAM_TAU] = {0};
  ryde_1s_tcith_alpha_t mid_a_str[RYDE_1S_PARAM_TAU] = {0};
  ryde_1s_tcith_challenge_t i_star = {0}, psi_i_star = {0};

  ryde_1s_ggm_tree_node_t path[RYDE_1S_PARAM_MAX_OPEN] = {0};

  ryde_1s_tcith_share_s_t aux_s_str[RYDE_1S_PARAM_TAU] = {0};
  ryde_1s_tcith_share_C_t aux_C_str[RYDE_1S_PARAM_TAU] = {0};

  // Setup variables related to sk and pk
  uint8_t pk[RYDE_1S_PUBLIC_KEY_BYTES] = {0};
  rbc_53_mat H;
  rbc_53_vec y, s; // By construction, s refers to the vector (1 | s')
  rbc_53_mat_fq C;

  // Initialize variables related to secret key and public key
  rbc_53_mat_init(&H, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_K);
  rbc_53_vec_init(&y, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K);
  rbc_53_vec_init(&s, RYDE_1S_PARAM_R);
  rbc_53_mat_fq_init(&C, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

  // Initialize variables related to base
  rbc_53_vec_init(&overline_s_, RYDE_1S_PARAM_R - 1);
  rbc_53_mat_fq_init(&overline_C, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
  rbc_53_mat_init(&overline_D, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
  rbc_53_vec_init(&overline_v, RYDE_1S_PARAM_RHO);
  for(size_t i = 0; i < RYDE_1S_PARAM_TAU; i++ ) {
    rbc_53_vec_init(&(acc_s[i]), RYDE_1S_PARAM_R - 1);
    rbc_53_mat_fq_init(&(acc_C[i]), RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_init(&(acc_v[i]), RYDE_1S_PARAM_RHO);
  }

  rbc_53_vec mid_alpha[RYDE_1S_PARAM_TAU];
  for(size_t i = 0; i < RYDE_1S_PARAM_TAU; i++ ) {
    rbc_53_vec_init(&(mid_alpha[i]), RYDE_1S_PARAM_RHO);
  }

  ryde_1s_tcith_shares_init(&base);
  rbc_53_mat_init(&gamma, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_RHO);
  rbc_53_vec_init(&base_x, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
  rbc_53_vec_init(&base_xL, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R - RYDE_1S_PARAM_K);
  rbc_53_vec_init(&base_xR, RYDE_1S_PARAM_K);
  rbc_53_vec_init(&base_a, RYDE_1S_PARAM_RHO);
  rbc_53_vec_init(&mid_a, RYDE_1S_PARAM_RHO);
  rbc_53_vec_init(&mid_x, RYDE_1S_PARAM_N - 1);
  rbc_53_vec_init(&mid_xL, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
  rbc_53_vec_init(&mid_xR, RYDE_1S_PARAM_K);
  rbc_53_vec_init(&tmp_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
  rbc_53_vec_init(&tmp_nk, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K);
  rbc_53_vec_init(&tmp_nk1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
  rbc_53_vec_init(&aux_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
  rbc_53_vec_init(&sC, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

  // Parse secret key and public key
  ryde_1s_secret_key_from_string(y, H, s, C, sk);
  ryde_1s_public_key_to_string(pk, &sk[RYDE_1S_SECURITY_BYTES], y);

  rbc_53_mat_fq_mul_by_vec_left(sC, (rbc_53_mat_fq)&(C[1]), (rbc_53_vec)&s[1], RYDE_1S_PARAM_R - 1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

  // Hash message
  domain_separator = DOMAIN_SEPARATOR_MESSAGE;
  hash_sha3_absorb(&ctx_m, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_m, message, message_size);
  hash_sha3_finalize(m_digest, &ctx_m);

  // -------------------------------------------------------------------------------------------- Shares and commitments

  // Sample salt and root seed
  if (randombytes(salt_and_rseed, RYDE_1S_SALT_BYTES + RYDE_1S_SECURITY_BYTES) != EXIT_SUCCESS) {
    memset(salt_and_rseed, 0, RYDE_1S_SALT_BYTES + RYDE_1S_SECURITY_BYTES);

    rbc_53_vec_clear(sC);

    rbc_53_vec_clear(aux_nr);
    rbc_53_vec_clear(tmp_nr);
    rbc_53_vec_clear(tmp_nk1);
    rbc_53_vec_clear(tmp_nk);
    rbc_53_vec_clear(mid_a);
    rbc_53_vec_clear(mid_xL);
    rbc_53_vec_clear(mid_xR);
    rbc_53_vec_clear(mid_x);
    rbc_53_vec_clear(base_a);
    rbc_53_vec_clear(base_xL);
    rbc_53_vec_clear(base_xR);
    rbc_53_vec_clear(base_x);

    rbc_53_mat_clear(gamma);
    ryde_1s_tcith_shares_clear(&base);
    rbc_53_vec_clear(overline_s_);
    rbc_53_mat_clear(overline_D);
    rbc_53_mat_fq_clear(overline_C);
    rbc_53_vec_clear(overline_v);
    for(size_t i = 0; i < RYDE_1S_PARAM_TAU; i++ ) {
      rbc_53_vec_clear(mid_alpha[i]);
      rbc_53_vec_clear(acc_s[i]);
      rbc_53_mat_fq_clear(acc_C[i]);
      rbc_53_vec_clear(acc_v[i]);
    }

    rbc_53_mat_fq_clear(C);
    rbc_53_vec_clear(s);
    rbc_53_vec_clear(y);
    rbc_53_mat_clear(H);

    return EXIT_FAILURE;
  }

  // Initialize tree

  memcpy(&salt, salt_and_rseed, RYDE_1S_SALT_BYTES);                           // salt
  memcpy(tree[0], &salt_and_rseed[RYDE_1S_SALT_BYTES], RYDE_1S_SECURITY_BYTES);   // root seed
  ryde_1s_ggm_tree_expand(tree, salt);
  ryde_1s_ggm_tree_get_leaves(seeds, tree);


  // Add salt to ctx_h1
  domain_separator = DOMAIN_SEPARATOR_HASH1;
  hash_sha3_absorb(&ctx_h1, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_h1, salt, RYDE_1S_SALT_BYTES);

  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
    // Set to zero the accumulator vector and matrix
    rbc_53_vec_set_zero(base.s[e], RYDE_1S_PARAM_R - 1);
    rbc_53_mat_set_zero(base.C[e], RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_set_zero(base.v[e], RYDE_1S_PARAM_RHO);

    rbc_53_vec_set_zero(acc_s[e], RYDE_1S_PARAM_R - 1);
    rbc_53_mat_fq_set_zero(acc_C[e], RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_set_zero(acc_v[e], RYDE_1S_PARAM_RHO);

    size_t N = e < RYDE_1S_PARAM_TAU_1? RYDE_1S_PARAM_N_1 : RYDE_1S_PARAM_N_2;
    for(size_t i = 0; i < N; i++) {
      size_t idx = ryde_1s_tcith_psi(i, e);
      memcpy(seed, &seeds[idx], RYDE_1S_SECURITY_BYTES);

      // Compute commit and add it to ctx_h1
      ryde_1s_tcith_commit(commit, salt, e, i, seed);

      // Set to zero the accumulator vector and matrix
      rbc_53_vec_set_zero(overline_s_, RYDE_1S_PARAM_R - 1);
      rbc_53_mat_fq_set_zero(overline_C, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
      rbc_53_mat_set_zero(overline_D, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
      rbc_53_vec_set_zero(overline_v, RYDE_1S_PARAM_RHO);

      hash_sha3_absorb(&ctx_h1, commit, RYDE_1S_HASH_BYTES);

      ryde_1s_tcith_expand_share(overline_s_, overline_C, overline_v, seed, salt);

      rbc_53_vec_add(acc_s[e], acc_s[e], overline_s_, RYDE_1S_PARAM_R - 1);
      rbc_53_mat_fq_add(acc_C[e], acc_C[e], overline_C, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
      rbc_53_vec_add(acc_v[e], acc_v[e], overline_v, RYDE_1S_PARAM_RHO);

      // Compute random base
      rbc_53_elt phi_i;
      ryde_1s_tcith_phi(phi_i, i);

      rbc_53_vec_scalar_mul(overline_s_, overline_s_, phi_i, RYDE_1S_PARAM_R - 1);
      rbc_53_mat_fq_mul_by_constant(overline_D, overline_C, phi_i, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
      rbc_53_vec_scalar_mul(overline_v, overline_v, phi_i, RYDE_1S_PARAM_RHO);

      rbc_53_vec_add(base.s[e], base.s[e], overline_s_, RYDE_1S_PARAM_R - 1);
      rbc_53_mat_add(base.C[e], base.C[e], overline_D, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
      rbc_53_vec_add(base.v[e], base.v[e], overline_v, RYDE_1S_PARAM_RHO);
    }


    // Compute (s - acc_s[e])
    rbc_53_vec_add(acc_s[e], (rbc_53_vec)&s[1], acc_s[e], RYDE_1S_PARAM_R - 1);
    rbc_53_vec_to_string(aux_s_str[e], acc_s[e], RYDE_1S_PARAM_R - 1);

    // Compute (C - acc_C[e])
    rbc_53_mat_fq_add(acc_C[e], C, acc_C[e], RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_mat_fq_to_string(aux_C_str[e], acc_C[e], RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

  }

  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
    hash_sha3_absorb(&ctx_h1, aux_s_str[e], RYDE_1S_VEC_R_MINUS_ONE_BYTES);
    hash_sha3_absorb(&ctx_h1, aux_C_str[e], RYDE_1S_MAT_FQ_BYTES);
  }

  // --------------------------------------------------------------------------------------------------- First challenge

  // Generate h1 and gamma
  hash_sha3_finalize(h1, &ctx_h1);
  ryde_1s_tcith_expand_challenge_1(gamma, h1, salt);

  // ---------------------------------------------------------------------------------------------------- MPC simulation

  // We next Compute the Polynomial Proof
  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
    rbc_53_vec_set_zero(overline_s_, RYDE_1S_PARAM_R - 1);
    rbc_53_vec_set_zero(tmp_nk, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K);
    rbc_53_vec_set_zero(tmp_nk1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
    rbc_53_vec_set_zero(tmp_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_set_zero(aux_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_set_zero(base_a, RYDE_1S_PARAM_RHO);
    rbc_53_vec_set_zero(mid_a, RYDE_1S_PARAM_RHO);

    // Calculate base_x = (base_xL | base_xR)
    rbc_53_mat_mul_by_vec_left(base_x,
                            (rbc_53_mat)&(base.C[e][1]),
                            base.s[e],
                            RYDE_1S_PARAM_R - 1,
                            RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

    rbc_53_vec_set(base_xL, base_x, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R - RYDE_1S_PARAM_K);
    rbc_53_vec_set(base_xR,
                (rbc_53_vec)&(base_x[RYDE_1S_PARAM_N - RYDE_1S_PARAM_R - RYDE_1S_PARAM_K]),
                RYDE_1S_PARAM_K);

    // Calculate base_a
    rbc_53_mat_mul_by_vec_left_transpose(tmp_nk, H, base_xR, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_K);
    rbc_53_vec_add((rbc_53_vec)&(tmp_nk[RYDE_1S_PARAM_R]),
                (rbc_53_vec)&(tmp_nk[RYDE_1S_PARAM_R]),
                base_xL,
                RYDE_1S_PARAM_N - RYDE_1S_PARAM_R - RYDE_1S_PARAM_K);
    rbc_53_mat_mul_by_vec_left(base_a, gamma, tmp_nk, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_RHO);
    rbc_53_vec_add(base_a, base_a, base.v[e], RYDE_1S_PARAM_RHO);
    rbc_53_vec_to_string(base_a_str[e], base_a, RYDE_1S_PARAM_RHO);

    // Calculate mid_x
    rbc_53_mat_fq_mul_by_vec_left(tmp_nr, (rbc_53_mat_fq)&(C[1]), base.s[e], RYDE_1S_PARAM_R - 1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_mat_mul_by_vec_left(aux_nr, (rbc_53_mat)&(base.C[e][1]), (rbc_53_vec)&s[1], RYDE_1S_PARAM_R - 1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_add(tmp_nr, aux_nr, tmp_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    rbc_53_vec_add(tmp_nr, tmp_nr, (rbc_53_vec)(base.C[e][0]), RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

    rbc_53_vec_set(mid_x, base.s[e], RYDE_1S_PARAM_R - 1);
    rbc_53_vec_set((rbc_53_vec)&mid_x[RYDE_1S_PARAM_R - 1], tmp_nr, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);

    rbc_53_vec_set(mid_xL, mid_x, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
    rbc_53_vec_set(mid_xR, (rbc_53_vec)&(mid_x[RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1]), RYDE_1S_PARAM_K);

    // Calculate mid_a
    rbc_53_mat_mul_by_vec_left_transpose(tmp_nk, H, mid_xR, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_K);
    rbc_53_vec_add(tmp_nk1, (rbc_53_vec)&(tmp_nk[1]), mid_xL, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
    rbc_53_vec_set((rbc_53_vec)&(tmp_nk[1]), tmp_nk1, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K - 1);
    rbc_53_mat_mul_by_vec_left(mid_a, gamma, tmp_nk, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_RHO);
    rbc_53_vec_add(mid_a, mid_a, acc_v[e], RYDE_1S_PARAM_RHO);
    rbc_53_vec_to_string(mid_a_str[e], mid_a, RYDE_1S_PARAM_RHO);

    rbc_53_vec_set(mid_alpha[e], mid_a, RYDE_1S_PARAM_RHO);
  }

  // -------------------------------------------------------------------------------------------------- Second challenge

  // Initialize ctx_h2
  hash_sha3_init(&ctx_h2);
  // Add m, pk, salt and h1 to ctx_h2
  domain_separator = DOMAIN_SEPARATOR_HASH2;
  hash_sha3_absorb(&ctx_h2, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_h2, m_digest, RYDE_1S_HASH_BYTES);
  hash_sha3_absorb(&ctx_h2, pk, RYDE_1S_PUBLIC_KEY_BYTES);
  hash_sha3_absorb(&ctx_h2, salt, RYDE_1S_SALT_BYTES);
  hash_sha3_absorb(&ctx_h2, h1, RYDE_1S_HASH_BYTES);
  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
    hash_sha3_absorb(&ctx_h2, base_a_str[e], RYDE_1S_VEC_RHO_BYTES);
    hash_sha3_absorb(&ctx_h2, mid_a_str[e], RYDE_1S_VEC_RHO_BYTES);
  }
  hash_sha3_finalize(h2, &ctx_h2);

  // SHAKE input (fixed prefix)
  uint8_t shake_input[RYDE_1S_HASH_BYTES + sizeof(uint64_t)] = {0};
  memcpy(&shake_input[0], h2, RYDE_1S_HASH_BYTES);

  uint64_t ctr = 0;
retry:

  // SHAKE input (suffix corresponds with the counter)
  memcpy(&shake_input[RYDE_1S_HASH_BYTES], (uint8_t *)&ctr, sizeof(uint64_t));
  ryde_1s_tcith_expand_challenge_2(i_star, v_grinding, shake_input);


  if (ryde_1s_tcith_discard_input_challenge_2(v_grinding)) {
      memset(v_grinding, 0, RYDE_1S_PARAM_W_BYTES);
      ctr += 1;
      goto retry;
  }

  // Next we map the challenges to the leaves position (GGM Tree optimization)
  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++){
      size_t i = i_star[e];
      psi_i_star[e] = ryde_1s_tcith_psi(i, e);
  }

  size_t path_length = ryde_1s_ggm_tree_get_sibling_path(path, (const ryde_1s_ggm_tree_node_t *)tree, psi_i_star);

  if (path_length > RYDE_1S_PARAM_T_OPEN) {
      ctr += 1;
      memset(path, 0, path_length * RYDE_1S_SECURITY_BYTES);
      goto retry;
  }

  // --------------------------------------------------------------------------------------------------------- Signature

  memcpy(&signature[0], salt, RYDE_1S_SALT_BYTES);
  memcpy(&signature[RYDE_1S_SALT_BYTES], &ctr, sizeof(uint64_t));
  memcpy(&signature[RYDE_1S_SALT_BYTES + sizeof(uint64_t)], h2, RYDE_1S_HASH_BYTES);
  memcpy(&signature[RYDE_1S_SALT_BYTES + RYDE_1S_HASH_BYTES + sizeof(uint64_t)], path, RYDE_1S_SECURITY_BYTES * RYDE_1S_PARAM_T_OPEN);

  for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
    // Commitment concerning the hidden seed
    size_t idx = ryde_1s_tcith_psi(i_star[e], e);
    ryde_1s_tcith_commit(commit, salt, e, i_star[e], seeds[idx]);
    memcpy(&signature[
            RYDE_1S_SALT_BYTES +
            RYDE_1S_HASH_BYTES +
            sizeof(uint64_t) +
            RYDE_1S_PARAM_T_OPEN * RYDE_1S_SECURITY_BYTES +
            e * RYDE_1S_HASH_BYTES
           ],
          commit,
          RYDE_1S_HASH_BYTES);
  }
  ryde_1s_pack_matrices_and_vectors(&signature[
                                         RYDE_1S_SALT_BYTES +
                                         RYDE_1S_HASH_BYTES +
                                         sizeof(uint64_t) +
                                         RYDE_1S_PARAM_T_OPEN * RYDE_1S_SECURITY_BYTES +
                                         RYDE_1S_PARAM_TAU * RYDE_1S_HASH_BYTES
                                         ],
                                 acc_s, acc_C, mid_alpha);

  // ------------------------------------------------------------------------------------------------------ Verbose Mode
#ifdef VERBOSE
    printf("\n\n### SIGN ###\n");

    printf("\nsk: "); for(int i = 0 ; i < RYDE_1S_SECRET_KEY_BYTES ; ++i) printf("%02X", sk[i]);
    printf("\npk: "); for(int i = 0 ; i < RYDE_1S_PUBLIC_KEY_BYTES ; ++i) printf("%02X", pk[i]);

    printf("\nx: (s | sC)");
    uint8_t s_string[RYDE_1S_VEC_R_BYTES];
    rbc_53_vec_to_string(s_string, s, RYDE_1S_PARAM_R);
    printf("\n    - s      : "); for(size_t i = 0 ; i < RYDE_1S_VEC_R_BYTES ; i++) { printf("%02X", s_string[i]); }
    memset(s_string, 0, RYDE_1S_VEC_R_BYTES);
    uint8_t C_string[RYDE_1S_MAT_FQ_BYTES] = {0};
    rbc_53_mat_fq_to_string(C_string, C, RYDE_1S_PARAM_R, RYDE_1S_PARAM_N - RYDE_1S_PARAM_R);
    printf("\n    - C      : "); for(size_t i = 0 ; i < RYDE_1S_MAT_FQ_BYTES ; i++) { printf("%02X", C_string[i]); }
    memset(C_string, 0, RYDE_1S_MAT_FQ_BYTES);
    printf("\n\nm_digest: "); for(size_t i = 0 ; i < RYDE_1S_HASH_BYTES ; i++) { printf("%02X", m_digest[i]); }

    size_t length = ((RYDE_1S_PARAM_N - RYDE_1S_PARAM_K) * RYDE_1S_PARAM_K * RYDE_1S_PARAM_M + 7 ) / 8;
    uint8_t H_string[length];
    rbc_53_mat_to_string(H_string, H, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_K);
    printf("\nH: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", H_string[i]); }
    memset(H_string, 0, length);

    length = ((RYDE_1S_PARAM_N - RYDE_1S_PARAM_K) * RYDE_1S_PARAM_M + 7 ) / 8;
    uint8_t y_string[length];
    rbc_53_vec_to_string(y_string, y, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K);
    printf("\ny: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", y_string[i]); }
    memset(y_string, 0, length);

    printf("\n\ntree: ");
    printf("\n    - root   : ");
    for(size_t i = 0 ; i < RYDE_1S_SECURITY_BYTES ; i++) {
      printf("%02X", salt_and_rseed[i + RYDE_1S_SALT_BYTES]);
    }

    printf("\n\nsalt: "); for(size_t i = 0 ; i < RYDE_1S_SALT_BYTES ; i++) { printf("%02X", salt[i]); }
    printf("\n\nh1: "); for(size_t i = 0 ; i < RYDE_1S_HASH_BYTES ; i++) { printf("%02X", h1[i]); }
    printf("\nh2: "); for(size_t i = 0 ; i < RYDE_1S_HASH_BYTES ; i++) { printf("%02X", h2[i]); }
    printf("\n\nchallenges:");
    printf("\n    - i_star     :"); for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) { printf(" %05zu", i_star[e]); }
    printf("\n    - psi_i_star :"); for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) { printf(" %05zu", psi_i_star[e]); }
    printf("\nsibling path:"); ryde_1s_ggm_tree_print_sibling_path(path);
    printf("\n\nsigma: "); for(size_t i = 0; i < RYDE_1S_SIGNATURE_BYTES; i++) { printf("%02X", signature[i]); }
    printf("\n\nGamma:\n"); rbc_53_mat_print(gamma, RYDE_1S_PARAM_N - RYDE_1S_PARAM_K, RYDE_1S_PARAM_RHO);
    printf("\n\nctr: %lu\n", ctr);

    printf("\nbase_alpha:");
    for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
        printf("\n    - "); for (size_t i = 0; i < RYDE_1S_VEC_RHO_BYTES; i++) { printf("%02X", base_a_str[e][i]); }
    }
    printf("\n\nmid_alpha:");
    for(size_t e = 0; e < RYDE_1S_PARAM_TAU; e++) {
        printf("\n    - "); for (size_t i = 0; i < RYDE_1S_VEC_RHO_BYTES; i++) { printf("%02X", mid_a_str[e][i]); }
    }

    printf("\n");
#endif

  // -------------------------------------------------------------------------------------------------------- Clear Data
  memset(salt, 0, RYDE_1S_SALT_BYTES);
  memset(salt_and_rseed, 0, RYDE_1S_SALT_BYTES + RYDE_1S_SECURITY_BYTES);

  rbc_53_vec_clear(sC);

  rbc_53_vec_clear(aux_nr);
  rbc_53_vec_clear(tmp_nr);
  rbc_53_vec_clear(tmp_nk1);
  rbc_53_vec_clear(tmp_nk);
  rbc_53_vec_clear(mid_a);
  rbc_53_vec_clear(mid_xL);
  rbc_53_vec_clear(mid_xR);
  rbc_53_vec_clear(mid_x);
  rbc_53_vec_clear(base_a);
  rbc_53_vec_clear(base_xL);
  rbc_53_vec_clear(base_xR);
  rbc_53_vec_clear(base_x);

  rbc_53_mat_clear(gamma);
  ryde_1s_tcith_shares_clear(&base);
  rbc_53_vec_clear(overline_s_);
  rbc_53_mat_clear(overline_D);
  rbc_53_mat_fq_clear(overline_C);
  rbc_53_vec_clear(overline_v);
  for(size_t i = 0; i < RYDE_1S_PARAM_TAU; i++ ) {
    rbc_53_vec_clear(mid_alpha[i]);
    rbc_53_vec_clear(acc_s[i]);
    rbc_53_mat_fq_clear(acc_C[i]);
    rbc_53_vec_clear(acc_v[i]);
  }

  rbc_53_mat_fq_clear(C);
  rbc_53_vec_clear(s);
  rbc_53_vec_clear(y);
  rbc_53_mat_clear(H);

  // ------------------------------------------------------------------------------------------------------ Profile Mode


  return EXIT_SUCCESS;
}
