/** 
 * @file ryde_1f_keygen.c
 * @brief Implementation of keypair.h
 */

#include "string.h"
#include "randombytes.h"
#include "seedexpander_shake.h"
#include "rbc_53_vspace.h"
#include "rbc_53_mat_fq.h"
#include "parameters.h"
#include "parsing.h"
#include "keypair.h"



/**
 * \fn int ryde_1f_keygen(uint8_t* pk, uint8_t* sk)
 * \brief Keygen of the RQC_KEM IND-CCA2 scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used to generate vectors <b>g</b> and <b>h</b>.
 *
 * The secret key is composed of the seed used to generate the vectors <b>x</b> and <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect the NIST API.
 *
 * \param[out] pk String containing the public key
 * \param[out] sk String containing the secret key
 * \return EXIT_SUCCESS if verify is successful. Otherwise, it returns EXIT_FAILURE
 */
int ryde_1f_keygen(uint8_t* pk, uint8_t* sk) {

  rbc_53_field_init();

  uint8_t sk_seed[RYDE_1F_SECURITY_BYTES] = {0};
  uint8_t pk_seed[RYDE_1F_SECURITY_BYTES] = {0};

  seedexpander_shake_t sk_seedexpander;
  seedexpander_shake_t pk_seedexpander;

  rbc_53_vspace support;
  rbc_53_mat H;
  rbc_53_vec s, c, x1, x2, x, y;
  rbc_53_mat_fq C;

  rbc_53_vspace_init(&support, RYDE_1F_PARAM_R);
  rbc_53_mat_init(&H, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K, RYDE_1F_PARAM_K);
  rbc_53_vec_init(&s, RYDE_1F_PARAM_R);
  rbc_53_vec_init(&c, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
  rbc_53_vec_init(&x1, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K);
  rbc_53_vec_init(&x2, RYDE_1F_PARAM_K);
  rbc_53_vec_init(&x, RYDE_1F_PARAM_N);
  rbc_53_vec_init(&y, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K);
  rbc_53_mat_fq_init(&C, RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);

  // Create seed expanders for public key and secret key
  if (randombytes(sk_seed, RYDE_1F_SECURITY_BYTES) != EXIT_SUCCESS) {
    memset(sk_seed, 0, RYDE_1F_SECURITY_BYTES);
    return EXIT_FAILURE;
  }
  if (randombytes(pk_seed, RYDE_1F_SECURITY_BYTES) != EXIT_SUCCESS) {
    memset(sk_seed, 0, RYDE_1F_SECURITY_BYTES);
    memset(pk_seed, 0, RYDE_1F_SECURITY_BYTES);
    return EXIT_FAILURE;
  }
  seedexpander_shake_init(&sk_seedexpander, sk_seed, RYDE_1F_SECURITY_BYTES, NULL, 0);
  seedexpander_shake_init(&pk_seedexpander, pk_seed, RYDE_1F_SECURITY_BYTES, NULL, 0);

  // Compute secret key
  // Compute first part vector s of the secret key
  rbc_53_vspace_set_random_full_rank_with_one(&sk_seedexpander, support, RYDE_1F_PARAM_R);
  rbc_53_mat_fq_set_random(&sk_seedexpander, C, RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
  // Calculate last part vector c of the secret key as sC
  for(size_t i = 1; i < RYDE_1F_PARAM_R; i++) {
    rbc_53_elt_set(s[i], support[i - 1]);
  }
  rbc_53_elt_set(s[0], support[RYDE_1F_PARAM_R - 1]);
  rbc_53_mat_fq_mul_by_vec_left(c, C, s, RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
  // Set x as (s | c)
  for(size_t i = 0; i < RYDE_1F_PARAM_R; i++) {
    rbc_53_elt_set(x[i], s[i]);
  }
  for(size_t i = RYDE_1F_PARAM_R; i < RYDE_1F_PARAM_N; i++) {
    rbc_53_elt_set(x[i], c[i - RYDE_1F_PARAM_R]);
  }
  // Split x as (x1 | x2)
  for(size_t i = 0; i < RYDE_1F_PARAM_N - RYDE_1F_PARAM_K; i++) {
    rbc_53_elt_set(x1[i], x[i]);
  }
  for(size_t i = 0; i < RYDE_1F_PARAM_K; i++) {
    rbc_53_elt_set(x2[i], x[i + RYDE_1F_PARAM_N - RYDE_1F_PARAM_K]);
  }
  // Compute public key
  rbc_53_mat_set_random(&pk_seedexpander, H, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K, RYDE_1F_PARAM_K);
  rbc_53_mat_mul_by_vec_right(y, H, x2, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K, RYDE_1F_PARAM_K);
  rbc_53_vec_add(y, y, x1, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K);

  // Parse keys to string
  ryde_1f_public_key_to_string(pk, pk_seed, y);
  ryde_1f_secret_key_to_string(sk, sk_seed, pk_seed);

  #ifdef VERBOSE
    printf("\n\n\n### KEYGEN ###");

    printf("\n\nsk_seed: "); for(int i = 0 ; i < RYDE_1F_SECURITY_BYTES ; ++i) printf("%02X", sk_seed[i]);
    printf("\npk_seed: ");   for(int i = 0 ; i < RYDE_1F_SECURITY_BYTES ; ++i) printf("%02X", pk_seed[i]);
    printf("\nsk: "); for(int i = 0 ; i < RYDE_1F_SECRET_KEY_BYTES ; ++i) printf("%02X", sk[i]);
    printf("\npk: "); for(int i = 0 ; i < RYDE_1F_PUBLIC_KEY_BYTES ; ++i) printf("%02X", pk[i]);

    printf("\nx: (s | sC)");
    uint8_t s_string[RYDE_1F_VEC_R_BYTES];
    rbc_53_vec_to_string(s_string, s, RYDE_1F_PARAM_R);
    printf("\n    - s   : "); for(size_t i = 0 ; i < RYDE_1F_VEC_R_BYTES ; i++) { printf("%02X", s_string[i]); }
    memset(s_string, 0, RYDE_1F_VEC_R_BYTES);
    uint8_t C_string[RYDE_1F_MAT_FQ_BYTES] = {0};
    rbc_53_mat_fq_to_string(C_string, C, RYDE_1F_PARAM_R, RYDE_1F_PARAM_N - RYDE_1F_PARAM_R);
    printf("\n    - C   : "); for(size_t i = 0 ; i < RYDE_1F_MAT_FQ_BYTES ; i++) { printf("%02X", C_string[i]); }
    memset(C_string, 0, RYDE_1F_MAT_FQ_BYTES);

    size_t length = ((RYDE_1F_PARAM_N - RYDE_1F_PARAM_K) * RYDE_1F_PARAM_K * RYDE_1F_PARAM_M + 7 ) / 8;
    uint8_t H_string[length];
    rbc_53_mat_to_string(H_string, H, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K, RYDE_1F_PARAM_K);
    printf("\nH: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", H_string[i]); }
    memset(H_string, 0, length);

    length = ((RYDE_1F_PARAM_N - RYDE_1F_PARAM_K) * RYDE_1F_PARAM_M + 7 ) / 8;
    uint8_t y_string[length];
    rbc_53_vec_to_string(y_string, y, RYDE_1F_PARAM_N - RYDE_1F_PARAM_K);
    printf("\ny: "); for(size_t i = 0 ; i < length ; i++) { printf("%02X", y_string[i]); }
    memset(y_string, 0, length);
    printf("\n");
  #endif

  rbc_53_vspace_clear(support);
  rbc_53_mat_fq_clear(C);
  rbc_53_mat_clear(H);
  rbc_53_vec_clear(s);
  rbc_53_vec_clear(c);
  rbc_53_vec_clear(x1);
  rbc_53_vec_clear(x2);
  rbc_53_vec_clear(x);
  rbc_53_vec_clear(y);

  return EXIT_SUCCESS;
}
