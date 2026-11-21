/** 
 * @file ryde_1f_parsing.h
 * @brief Functions to parse secret key, public key, commitment, and response of the SIGN-RSD_MPC_ONE scheme
 */

#ifndef RYDE_1F_PARSING_H
#define RYDE_1F_PARSING_H

#include "rbc_53_vec.h"
#include "rbc_53_mat.h"
#include "rbc_53_mat_fq.h"

void ryde_1f_public_key_to_string(uint8_t* pk, const uint8_t* pk_seed, const rbc_53_vec y);
void ryde_1f_public_key_from_string(rbc_53_mat H, rbc_53_vec y, const uint8_t* pk);

void ryde_1f_secret_key_to_string(uint8_t* sk, const uint8_t* sk_seed, const uint8_t* pk_seed);
void ryde_1f_secret_key_from_string(rbc_53_vec y, rbc_53_mat H, rbc_53_vec s, rbc_53_mat_fq C, const uint8_t* sk);

#endif

