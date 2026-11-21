/** 
 * @file ryde_5f_parsing.h
 * @brief Functions to parse secret key, public key, commitment, and response of the SIGN-RSD_MPC_ONE scheme
 */

#ifndef RYDE_5F_PARSING_H
#define RYDE_5F_PARSING_H

#include "rbc_67_vec.h"
#include "rbc_67_mat.h"
#include "rbc_67_mat_fq.h"

void ryde_5f_public_key_to_string(uint8_t* pk, const uint8_t* pk_seed, const rbc_67_vec y);
void ryde_5f_public_key_from_string(rbc_67_mat H, rbc_67_vec y, const uint8_t* pk);

void ryde_5f_secret_key_to_string(uint8_t* sk, const uint8_t* sk_seed, const uint8_t* pk_seed);
void ryde_5f_secret_key_from_string(rbc_67_vec y, rbc_67_mat H, rbc_67_vec s, rbc_67_mat_fq C, const uint8_t* sk);

#endif

