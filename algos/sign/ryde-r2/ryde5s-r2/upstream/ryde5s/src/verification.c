/** 
 * \file ryde_5s_verify.c
 * \brief Implementation of verify.h
 */

#include "string.h"
#include "hash_fips202.h"
#include "parameters.h"
#include "parsing.h"
#include "tcith.h"
#include "ggm_tree.h"
#include "verification.h"


/**
 * \fn int ryde_5s_verify(const uint8_t* message, size_t message_size, const uint8_t* signature, size_t signature_size, const uint8_t* pk)
 * \brief Verify of the RYDE scheme
 *
 * The public key is composed of the vector <b>y</b> as well as the seed used to generate matrix <b>H</b>.
 *
 * \param[in] signature String containing the signature
 * \param[in] signature_size Integer determining the signed message byte-length
 * \param[in] message String containing the message to be signed
 * \param[in] message_size Integer determining the message byte-length
 * \param[in] pk String containing the public key
 * \return EXIT_SUCCESS if verify is successful. Otherwise, it returns EXIT_FAILURE
 */
int ryde_5s_verify(const uint8_t* signature, size_t signature_size, const uint8_t* message, size_t message_size, const uint8_t* pk) {



  // ---------------------------------------------------------------------------------------------------- Initialization

  rbc_67_field_init();

  if(signature == NULL || message == NULL || pk == NULL) { return EXIT_FAILURE; }
  if(signature_size != RYDE_5S_SIGNATURE_BYTES) { return EXIT_FAILURE; }

  // Setup variables related to randomness, salt, hash and challenges
  ryde_5s_tcith_commit_t commit = {0};

  uint8_t salt[RYDE_5S_SALT_BYTES] = {0};
  uint64_t ctr = 0;

  uint8_t domain_separator;
  uint8_t h1[RYDE_5S_HASH_BYTES] = {0};
  uint8_t h2[RYDE_5S_HASH_BYTES] = {0};
  uint8_t h2_[RYDE_5S_HASH_BYTES] = {0};
  uint8_t v_grinding[RYDE_5S_PARAM_W_BYTES] = {0};
  hash_sha3_ctx ctx_m, ctx_h1, ctx_h2;
  hash_sha3_init(&ctx_m);
  hash_sha3_init(&ctx_h1);

  uint8_t m_digest[RYDE_5S_HASH_BYTES] = {0};

  ryde_5s_tcith_challenge_t i_star = {0}, psi_i_star = {0};
  ryde_5s_tcith_share_s_t aux_s_str[RYDE_5S_PARAM_TAU] = {0};
  ryde_5s_tcith_share_C_t aux_C_str[RYDE_5S_PARAM_TAU] = {0};

  ryde_5s_tcith_seed_t seed = {0};
  ryde_5s_ggm_tree_leaves_t seeds = {0};
  ryde_5s_ggm_tree_t tree = {0};
  ryde_5s_ggm_tree_node_t path[RYDE_5S_PARAM_MAX_OPEN] = {0};

  // Setup variables related to shares
  rbc_67_vec overline_v;
  rbc_67_vec overline_s_;
  rbc_67_mat_fq overline_C;
  rbc_67_mat overline_D;
  ryde_5s_tcith_shares_t shares;
  rbc_67_mat gamma;
  rbc_67_vec share_x, share_xL, share_xR, mid_a, share_a, tmp_nk, tmp_nk1, aux_nk, aux_nr, tmp_nr, tmp_r1, base_a;
  ryde_5s_tcith_alpha_t base_a_str[RYDE_5S_PARAM_TAU] = {0};
  ryde_5s_tcith_alpha_t mid_a_str[RYDE_5S_PARAM_TAU] = {0};

  // Setup variables related to pk
  rbc_67_mat H;
  rbc_67_vec y;

  rbc_67_mat_init(&H, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_K);
  rbc_67_vec_init(&y, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);

  // Initialize variables related to shares
  rbc_67_vec_init(&overline_s_, RYDE_5S_PARAM_R - 1);
  rbc_67_mat_fq_init(&overline_C, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
  rbc_67_mat_init(&overline_D, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
  rbc_67_vec_init(&overline_v, RYDE_5S_PARAM_RHO);

  ryde_5s_tcith_shares_init(&shares);
  rbc_67_mat_init(&gamma, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_RHO);
  rbc_67_vec_init(&share_x, RYDE_5S_PARAM_N - 1);
  rbc_67_vec_init(&share_xL, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
  rbc_67_vec_init(&share_xR, RYDE_5S_PARAM_K);
  rbc_67_vec_init(&mid_a, RYDE_5S_PARAM_RHO);
  rbc_67_vec_init(&base_a, RYDE_5S_PARAM_RHO);
  rbc_67_vec_init(&share_a, RYDE_5S_PARAM_RHO);
  rbc_67_vec_init(&aux_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
  rbc_67_vec_init(&aux_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
  rbc_67_vec_init(&tmp_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
  rbc_67_vec_init(&tmp_nk1, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
  rbc_67_vec_init(&tmp_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
  rbc_67_vec_init(&tmp_r1, RYDE_5S_PARAM_R - 1);


  rbc_67_vec aux_s[RYDE_5S_PARAM_TAU], mid_alpha[RYDE_5S_PARAM_TAU];
  rbc_67_mat_fq aux_C[RYDE_5S_PARAM_TAU];
  for(size_t i = 0; i < RYDE_5S_PARAM_TAU; i++ ) {
    rbc_67_vec_init(&(aux_s[i]), RYDE_5S_PARAM_R - 1);
    rbc_67_mat_fq_init(&(aux_C[i]), RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_init(&(mid_alpha[i]), RYDE_5S_PARAM_RHO);
  }
  ryde_5s_unpack_matrices_and_vectors(aux_s, aux_C, mid_alpha,
                                   &signature[
                                           RYDE_5S_SALT_BYTES +
                                           RYDE_5S_HASH_BYTES +
                                           sizeof(uint64_t) +
                                           RYDE_5S_PARAM_T_OPEN * RYDE_5S_SECURITY_BYTES +
                                           RYDE_5S_PARAM_TAU * RYDE_5S_HASH_BYTES
                                           ]);

  // Parse public key
  ryde_5s_public_key_from_string(H, y, pk);

  // Hash message
  domain_separator = DOMAIN_SEPARATOR_MESSAGE;
  hash_sha3_absorb(&ctx_m, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_m, message, message_size);
  hash_sha3_finalize(m_digest, &ctx_m);

  // Parse signature data
  memcpy(salt, &signature[0], RYDE_5S_SALT_BYTES);
  memcpy(&ctr, &signature[RYDE_5S_SALT_BYTES], sizeof(uint64_t));
  memcpy(h2,   &signature[RYDE_5S_SALT_BYTES + sizeof(uint64_t)], RYDE_5S_HASH_BYTES);
  memcpy(path, &signature[RYDE_5S_SALT_BYTES + RYDE_5S_HASH_BYTES + sizeof(uint64_t)], RYDE_5S_SECURITY_BYTES * RYDE_5S_PARAM_T_OPEN);

  // SHAKE input
  uint8_t shake_input[RYDE_5S_HASH_BYTES + sizeof(uint64_t)] = {0};
  memcpy(&shake_input[0], h2, RYDE_5S_HASH_BYTES);
  memcpy(&shake_input[RYDE_5S_HASH_BYTES], (uint8_t *)&ctr, sizeof(uint64_t));
  ryde_5s_tcith_expand_challenge_2(i_star, v_grinding, shake_input);

  // Next we map the challenges to the leaves position (GGM Tree optimization)
  for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++){
    size_t i = i_star[e];
    psi_i_star[e] = ryde_5s_tcith_psi(i, e);
  }

  // Get sibling path length: starts
  size_t path_length = 0;
  for(size_t i = 0; i < RYDE_5S_PARAM_T_OPEN; i++) {
      uint8_t zero[RYDE_5S_SECURITY_BYTES] = {0};
      if (memcmp(zero, &path[i], RYDE_5S_SECURITY_BYTES) == 0) { continue; }
      path_length += 1;
  }
  // Get sibling path length: ends

  // Add salt to ctx_h1
  domain_separator = DOMAIN_SEPARATOR_HASH1;
  hash_sha3_absorb(&ctx_h1, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_h1, salt, RYDE_5S_SALT_BYTES);

  // ---------------------------------------------------------------------------------- Recompute shares and commitments

  int wrong_sibling_path = ryde_5s_ggm_tree_partial_expand(tree, salt, (const ryde_5s_ggm_tree_node_t*)path, path_length, psi_i_star);
  ryde_5s_ggm_tree_get_leaves(seeds, tree);


  for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
    // Set to zero the accumulator vector and matrix
    rbc_67_vec_set_zero(shares.s[e], RYDE_5S_PARAM_R - 1);
    rbc_67_mat_set_zero(shares.C[e], RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_set_zero(shares.v[e], RYDE_5S_PARAM_RHO);

    rbc_67_elt phi_i_star;
    ryde_5s_tcith_phi(phi_i_star, i_star[e]);

    size_t N = e < RYDE_5S_PARAM_TAU_1? RYDE_5S_PARAM_N_1 : RYDE_5S_PARAM_N_2;
    for(size_t i = 0; i < N; i++) {
      size_t idx = ryde_5s_tcith_psi(i, e);
      memcpy(seed, &seeds[idx], RYDE_5S_SECURITY_BYTES);

      // Set to zero the accumulator vector and matrix
      rbc_67_vec_set_zero(overline_s_, RYDE_5S_PARAM_R - 1);
      rbc_67_mat_fq_set_zero(overline_C, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
      rbc_67_mat_set_zero(overline_D, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
      rbc_67_vec_set_zero(overline_v, RYDE_5S_PARAM_RHO);

      if (i == (size_t)i_star[e]) {
        memcpy(commit,
               &signature[
                  RYDE_5S_SALT_BYTES + RYDE_5S_HASH_BYTES + sizeof(uint64_t) + RYDE_5S_PARAM_T_OPEN * RYDE_5S_SECURITY_BYTES +
                  e * RYDE_5S_HASH_BYTES
               ],
               RYDE_5S_HASH_BYTES);
        hash_sha3_absorb(&ctx_h1, commit, RYDE_5S_HASH_BYTES);
      }
      else {
        // Compute commit and add it to ctx_h1
        ryde_5s_tcith_commit(commit, salt, e, i, seed);

        hash_sha3_absorb(&ctx_h1, commit, RYDE_5S_HASH_BYTES);

        ryde_5s_tcith_expand_share(overline_s_, overline_C, overline_v, seed, salt);

        // Compute shares
        rbc_67_elt scalar;
        ryde_5s_tcith_phi(scalar, i);
        rbc_67_elt_add(scalar, phi_i_star, scalar);

        rbc_67_vec_scalar_mul(overline_s_, overline_s_, scalar, RYDE_5S_PARAM_R - 1);
        rbc_67_mat_fq_mul_by_constant(overline_D, overline_C, scalar, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
        rbc_67_vec_scalar_mul(overline_v, overline_v, scalar, RYDE_5S_PARAM_RHO);

        rbc_67_vec_add(shares.s[e], shares.s[e], overline_s_, RYDE_5S_PARAM_R - 1);
        rbc_67_mat_add(shares.C[e], shares.C[e], overline_D, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
        rbc_67_vec_add(shares.v[e], shares.v[e], overline_v, RYDE_5S_PARAM_RHO);
      }
    }


    // Operations concerning vector se
    rbc_67_vec_to_string(aux_s_str[e], aux_s[e], RYDE_5S_PARAM_R - 1);
    rbc_67_vec_scalar_mul(overline_s_, aux_s[e], phi_i_star, RYDE_5S_PARAM_R - 1);

    // Operations concerning matrix Ce
    rbc_67_mat_fq_to_string(aux_C_str[e], aux_C[e], RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_mat_fq_mul_by_constant(overline_D, aux_C[e], phi_i_star, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);


    rbc_67_vec_add(shares.s[e], shares.s[e], overline_s_, RYDE_5S_PARAM_R - 1);
    rbc_67_mat_add(shares.C[e], shares.C[e], overline_D, RYDE_5S_PARAM_R, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
  }

  for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
    hash_sha3_absorb(&ctx_h1, aux_s_str[e], RYDE_5S_VEC_R_MINUS_ONE_BYTES);
    hash_sha3_absorb(&ctx_h1, aux_C_str[e], RYDE_5S_MAT_FQ_BYTES);
  }

  // --------------------------------------------------------------------------------------------------- First Challenge

  // Generate h1 and gamma
  hash_sha3_finalize(h1, &ctx_h1);
  ryde_5s_tcith_expand_challenge_1(gamma, h1, salt);

  // ---------------------------------------------------------------------------------------------------- MPC simulation

  // We next Recompute the Polynomial Proof
  for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
    rbc_67_vec_set_zero(tmp_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
    rbc_67_vec_set_zero(tmp_nk1, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
    rbc_67_vec_set_zero(tmp_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_set_zero(tmp_r1, RYDE_5S_PARAM_R - 1);
    rbc_67_vec_set_zero(aux_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
    rbc_67_vec_set_zero(aux_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_set_zero(share_a, RYDE_5S_PARAM_RHO);
    rbc_67_vec_set_zero(mid_a, RYDE_5S_PARAM_RHO);

    rbc_67_elt phi_i_star, phi_i_star_squared;
    ryde_5s_tcith_phi(phi_i_star, i_star[e]);
    rbc_67_elt_sqr(phi_i_star_squared, phi_i_star);

    // Calculate share_x = (share_xL | share_xR)
    rbc_67_vec_scalar_mul(tmp_r1, shares.s[e], phi_i_star, RYDE_5S_PARAM_R - 1);
    rbc_67_mat_mul_by_vec_left(tmp_nr,
                            (rbc_67_mat)&(shares.C[e][1]),
                            shares.s[e],
                            RYDE_5S_PARAM_R - 1,
                            RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_scalar_mul(aux_nr, (rbc_67_vec)shares.C[e][0], phi_i_star, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);
    rbc_67_vec_add(tmp_nr, aux_nr, tmp_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);

    rbc_67_vec_set(share_x, tmp_r1, RYDE_5S_PARAM_R - 1);
    rbc_67_vec_set((rbc_67_vec)&share_x[RYDE_5S_PARAM_R - 1], tmp_nr, RYDE_5S_PARAM_N - RYDE_5S_PARAM_R);

    rbc_67_vec_set(share_xL, share_x, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
    rbc_67_vec_set(share_xR, (rbc_67_vec)&(share_x[RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1]), RYDE_5S_PARAM_K);

    // Calculate share_a
    rbc_67_mat_mul_by_vec_left_transpose(tmp_nk, H, share_xR, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_K);
    rbc_67_elt_add(tmp_nk[0], tmp_nk[0], phi_i_star_squared);
    rbc_67_vec_add(tmp_nk1, (rbc_67_vec)&(tmp_nk[1]), share_xL, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
    rbc_67_vec_set((rbc_67_vec)&(tmp_nk[1]), tmp_nk1, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K - 1);
    rbc_67_vec_scalar_mul(aux_nk, y, phi_i_star_squared, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
    rbc_67_vec_add(tmp_nk, tmp_nk, aux_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
    rbc_67_mat_mul_by_vec_left(share_a, gamma, tmp_nk, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_RHO);
    rbc_67_vec_add(share_a, share_a, shares.v[e], RYDE_5S_PARAM_RHO);

    // Calculate base_a
    rbc_67_vec_to_string(mid_a_str[e], mid_alpha[e], RYDE_5S_PARAM_RHO);
    rbc_67_vec_scalar_mul(mid_a, mid_alpha[e], phi_i_star, RYDE_5S_PARAM_RHO);
    rbc_67_vec_add(base_a, share_a, mid_a, RYDE_5S_PARAM_RHO);
    rbc_67_vec_to_string(base_a_str[e], base_a, RYDE_5S_PARAM_RHO);
  }

  // ------------------------------------------------------------------------------------------------------ Verification

  // Initialize ctx_h2
  hash_sha3_init(&ctx_h2);
  // Add m, pk, salt and h1 to ctx_h2
  domain_separator = DOMAIN_SEPARATOR_HASH2;
  hash_sha3_absorb(&ctx_h2, &domain_separator, sizeof(uint8_t));
  hash_sha3_absorb(&ctx_h2, m_digest, RYDE_5S_HASH_BYTES);
  hash_sha3_absorb(&ctx_h2, pk, RYDE_5S_PUBLIC_KEY_BYTES);
  hash_sha3_absorb(&ctx_h2, salt, RYDE_5S_SALT_BYTES);
  hash_sha3_absorb(&ctx_h2, h1, RYDE_5S_HASH_BYTES);
  for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
    hash_sha3_absorb(&ctx_h2, base_a_str[e], RYDE_5S_VEC_RHO_BYTES);
    hash_sha3_absorb(&ctx_h2, mid_a_str[e], RYDE_5S_VEC_RHO_BYTES);
  }
  hash_sha3_finalize(h2_, &ctx_h2);

  // ------------------------------------------------------------------------------------------------------ Verbose Mode
  #ifdef VERBOSE
    printf("\n### VERIFY ###\n");

    printf("\npk: "); for(int i = 0 ; i < RYDE_5S_PUBLIC_KEY_BYTES ; ++i) printf("%02X", pk[i]);

    size_t length = ((RYDE_5S_PARAM_N - RYDE_5S_PARAM_K) * RYDE_5S_PARAM_K * RYDE_5S_PARAM_M + 7 ) / 8;
    uint8_t H_string[length];
    rbc_67_mat_to_string(H_string, H, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_K);
    printf("\nH: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", H_string[i]); }
    memset(H_string, 0, length);

    length = ((RYDE_5S_PARAM_N - RYDE_5S_PARAM_K) * RYDE_5S_PARAM_M + 7 ) / 8;
    uint8_t y_string[length];
    rbc_67_vec_to_string(y_string, y, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K);
    printf("\ny: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", y_string[i]); }
    memset(y_string, 0, length);

    printf("\n\nm_digest: "); for(size_t i = 0 ; i < RYDE_5S_HASH_BYTES ; i++) { printf("%02X", m_digest[i]); }

    printf("\n\nsigma: "); for(size_t i = 0; i < RYDE_5S_SIGNATURE_BYTES; i++) { printf("%02X", signature[i]); } printf("\n");

    printf("\n\nsalt: "); for(size_t i = 0 ; i < RYDE_5S_SALT_BYTES ; i++) { printf("%02X", salt[i]); }
    printf("\n\nh1: "); for(size_t i = 0 ; i < RYDE_5S_HASH_BYTES ; i++) { printf("%02X", h1[i]); }
    printf("\nh2: "); for(size_t i = 0 ; i < RYDE_5S_HASH_BYTES ; i++) { printf("%02X", h2[i]); }
    printf("\n\nchallenges:");
    printf("\n    - i_star     :"); for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) { printf(" %05zu", i_star[e]); }
    printf("\n    - psi_i_star :"); for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) { printf(" %05zu", psi_i_star[e]); }
    printf("\nsibling path:"); ryde_5s_ggm_tree_print_sibling_path(path);
    printf("\n\nGamma:\n"); rbc_67_mat_print(gamma, RYDE_5S_PARAM_N - RYDE_5S_PARAM_K, RYDE_5S_PARAM_RHO);
    printf("\n\nctr: %lu\n", ctr);

    printf("\nbase_alpha:");
    for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
      printf("\n    - "); for (size_t i = 0; i < RYDE_5S_VEC_RHO_BYTES; i++) { printf("%02X", base_a_str[e][i]); }
    }
    printf("\n\nmid_alpha:");
    for(size_t e = 0; e < RYDE_5S_PARAM_TAU; e++) {
      printf("\n    - "); for (size_t i = 0; i < RYDE_5S_VEC_RHO_BYTES; i++) { printf("%02X", mid_a_str[e][i]); }
    }

    printf("\n\nh2\': "); for(size_t i = 0 ; i < RYDE_5S_HASH_BYTES ; i++) { printf("%02X", h2_[i]); }
    printf("\n");
  #endif

  // -------------------------------------------------------------------------------------------------------- Clear Data
  for(size_t i = 0; i < RYDE_5S_PARAM_TAU; i++ ) {
    rbc_67_vec_clear(mid_alpha[i]);
    rbc_67_vec_clear(aux_s[i]);
    rbc_67_mat_fq_clear(aux_C[i]);
  }

  rbc_67_vec_clear(tmp_r1);
  rbc_67_vec_clear(tmp_nr);
  rbc_67_vec_clear(aux_nr);
  rbc_67_vec_clear(aux_nk);
  rbc_67_vec_clear(tmp_nk1);
  rbc_67_vec_clear(tmp_nk);
  rbc_67_vec_clear(share_xR);
  rbc_67_vec_clear(share_xL);
  rbc_67_vec_clear(share_x);
  rbc_67_vec_clear(mid_a);
  rbc_67_vec_clear(share_a);
  rbc_67_vec_clear(base_a);
  rbc_67_mat_clear(gamma);
  ryde_5s_tcith_shares_clear(&shares);
  rbc_67_vec_clear(overline_s_);
  rbc_67_mat_clear(overline_D);
  rbc_67_mat_fq_clear(overline_C);
  rbc_67_vec_clear(overline_v);
  rbc_67_mat_clear(H);
  rbc_67_vec_clear(y);

  // ------------------------------------------------------------------------------------------------------ Profile Mode


  // ------------------------------------------------------------------------------------------------------ Verification
  if ((memcmp(h2, h2_, RYDE_5S_HASH_BYTES) != 0) || wrong_sibling_path || ryde_5s_tcith_discard_input_challenge_2(v_grinding)) {
    memset(h1, 0, RYDE_5S_HASH_BYTES);
    memset(h2, 0, RYDE_5S_HASH_BYTES);;
    memset(h2_, 0, RYDE_5S_HASH_BYTES);

    return EXIT_FAILURE;
  }
  else {
    memset(h1, 0, RYDE_5S_HASH_BYTES);
    memset(h2, 0, RYDE_5S_HASH_BYTES);
    memset(h2_, 0, RYDE_5S_HASH_BYTES);

    return EXIT_SUCCESS;
  }
}
