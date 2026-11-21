/** 
 * @file ryde_5f_parsing.c
 * @brief Implementation of parsing.h
 */

#include "string.h"
#include "rbc_67_vspace.h"
#include "seedexpander_shake.h"
#include "parameters.h"
#include "parsing.h"



/**
 * \fn void ryde_5f_public_key_to_string(uint8_t* pk, const uint8_t* pk_seed, const rbc_67_vec y)
 * \brief This function parses a public key into a string
 *
 * The public key is composed of the vector <b>y</b> as well as the seed used to generate matrix <b>H</b>.
 *
 * \param[out] pk String containing the public key
 * \param[in] pk_seed Seed used to generate the public key
 * \param[in] y rbc_67_vec representation of vector y
 */
void ryde_5f_public_key_to_string(uint8_t* pk, const uint8_t* pk_seed, const rbc_67_vec y) {
  memcpy(pk, pk_seed, RYDE_5F_SECURITY_BYTES);
  rbc_67_vec_to_string(&pk[RYDE_5F_SECURITY_BYTES], y, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K);
}



/**
 * \fn void ryde_5f_public_key_from_string(rbc_67_mat H, rbc_67_vec y, const uint8_t* pk)
 * \brief This function parses a public key from a string
 *
 * The public key is composed of the vector <b>y</b> as well as the seed used to generate matrix <b>H</b>.
 *
 * \param[out] H rbc_67_mat representation of vector H
 * \param[out] y rbc_67_vec representation of vector y
 * \param[in] pk String containing the public key
 */
void ryde_5f_public_key_from_string(rbc_67_mat H, rbc_67_vec y, const uint8_t* pk) {
  uint8_t pk_seed[RYDE_5F_SECURITY_BYTES] = {0};
  seedexpander_shake_t pk_seedexpander;

  rbc_67_vspace support;
  rbc_67_vspace_init(&support, RYDE_5F_PARAM_R);

  // Compute parity-check matrix
  memcpy(pk_seed, pk, RYDE_5F_SECURITY_BYTES);
  seedexpander_shake_init(&pk_seedexpander, pk_seed, RYDE_5F_SECURITY_BYTES, NULL, 0);

  rbc_67_mat_set_random(&pk_seedexpander, H, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K, RYDE_5F_PARAM_K);

  // Compute syndrome
  rbc_67_vec_from_string(y, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K, &pk[RYDE_5F_SECURITY_BYTES]);

  rbc_67_vspace_clear(support);
}



/**
 * \fn void ryde_5f_secret_key_to_string(uint8_t* sk, const uint8_t* seed, const uint8_t* pk)
 * \brief This function parses a secret key into a string
 *
 * The secret key is composed of the seed used to generate vectors <b>x = (x1,x2)</b> and <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect the NIST API.
 *
 * \param[out] sk String containing the secret key
 * \param[in] seed Seed used to generate the vectors x and y
 * \param[in] pk String containing the public key
 */
void ryde_5f_secret_key_to_string(uint8_t* sk, const uint8_t* sk_seed, const uint8_t* pk) {
  memcpy(sk, sk_seed, RYDE_5F_SECURITY_BYTES);
  memcpy(&sk[RYDE_5F_SECURITY_BYTES], pk, RYDE_5F_SECURITY_BYTES);
}



/**
* \fn void ryde_5f_secret_key_from_string(rbc_67_vec y, rbc_67_mat H, rbc_67_vec s, rbc_67_mat_fq C, const uint8_t* sk)
* \brief This function parses a secret key from a string
*
* The secret key is composed of the seed used to generate vectors <b>x = (x1,x2)</b> and <b>y</b>.
* Additionally, it calculates the public matrix <b>H</b> and the annihilator polynomial <b>A</b>.
*
* As a technicality, the public key is appended to the secret key in order to respect the NIST API.
*
* \param[out] y rbc_67_vec representation of vector y
* \param[out] H rbc_67_mat representation of matrix H
* \param[out] s rbc_67_vec representation of vector s
* \param[out] C rbc_67_mat_fq representation of matrix C
* \param[in] sk String containing the secret key
*/
void ryde_5f_secret_key_from_string(rbc_67_vec y, rbc_67_mat H, rbc_67_vec s, rbc_67_mat_fq C, const uint8_t* sk) {

  uint8_t sk_seed[RYDE_5F_SECURITY_BYTES] = {0};
  uint8_t pk_seed[RYDE_5F_SECURITY_BYTES] = {0};

  seedexpander_shake_t sk_seedexpander;
  seedexpander_shake_t pk_seedexpander;

  memcpy(sk_seed, sk, RYDE_5F_SECURITY_BYTES);
  seedexpander_shake_init(&sk_seedexpander, sk_seed, RYDE_5F_SECURITY_BYTES, NULL, 0);

  rbc_67_vspace support;
  rbc_67_vspace_init(&support, RYDE_5F_PARAM_R);

  rbc_67_vec x1, x2, x, c;
  rbc_67_vec_init(&x1, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K);
  rbc_67_vec_init(&x2, RYDE_5F_PARAM_K);
  rbc_67_vec_init(&x, RYDE_5F_PARAM_N);
  rbc_67_vec_init(&c, RYDE_5F_PARAM_N - RYDE_5F_PARAM_R);

  // Compute secret key
  // Compute first part vector s of the secret key
  rbc_67_vspace_set_random_full_rank_with_one(&sk_seedexpander, support, RYDE_5F_PARAM_R);
  rbc_67_mat_fq_set_random(&sk_seedexpander, C, RYDE_5F_PARAM_R, RYDE_5F_PARAM_N - RYDE_5F_PARAM_R);
  // Calculate last part vector c of the secret key as sC
  for(size_t i = 1; i < RYDE_5F_PARAM_R; i++) {
    rbc_67_elt_set(s[i], support[i - 1]);
  }
  rbc_67_elt_set(s[0], support[RYDE_5F_PARAM_R - 1]);
  rbc_67_mat_fq_mul_by_vec_left(c, C, s, RYDE_5F_PARAM_R, RYDE_5F_PARAM_N - RYDE_5F_PARAM_R);
  // Set x as (s | c)
  for(size_t i = 0; i < RYDE_5F_PARAM_R; i++) {
    rbc_67_elt_set(x[i], s[i]);
  }
  for(size_t i = RYDE_5F_PARAM_R; i < RYDE_5F_PARAM_N; i++) {
    rbc_67_elt_set(x[i], c[i - RYDE_5F_PARAM_R]);
  }
  // Split x as (x1 | x2)
  for(size_t i = 0; i < RYDE_5F_PARAM_N - RYDE_5F_PARAM_K; i++) {
    rbc_67_elt_set(x1[i], x[i]);
  }
  for(size_t i = 0; i < RYDE_5F_PARAM_K; i++) {
    rbc_67_elt_set(x2[i], x[i + RYDE_5F_PARAM_N - RYDE_5F_PARAM_K]);
  }

  // Compute public key
  memcpy(pk_seed, &sk[RYDE_5F_SECURITY_BYTES], RYDE_5F_SECURITY_BYTES);
  seedexpander_shake_init(&pk_seedexpander, pk_seed, RYDE_5F_SECURITY_BYTES, NULL, 0);

  rbc_67_mat_set_random(&pk_seedexpander, H, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K, RYDE_5F_PARAM_K);
  rbc_67_mat_mul_by_vec_right(y, H, x2, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K, RYDE_5F_PARAM_K);
  rbc_67_vec_add(y, y, x1, RYDE_5F_PARAM_N - RYDE_5F_PARAM_K);

  rbc_67_vspace_clear(support);
  rbc_67_vec_clear(c);
  rbc_67_vec_clear(x);
  rbc_67_vec_clear(x1);
  rbc_67_vec_clear(x2);
}

