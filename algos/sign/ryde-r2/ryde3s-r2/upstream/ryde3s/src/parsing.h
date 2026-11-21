/** 
 * @file ryde_3s_parsing.h
 * @brief Functions to parse secret key, public key, commitment, and response of the SIGN-RSD_MPC_ONE scheme
 */

#ifndef RYDE_3S_PARSING_H
#define RYDE_3S_PARSING_H

#include "rbc_61_vec.h"
#include "rbc_61_mat.h"
#include "rbc_61_mat_fq.h"

void ryde_3s_public_key_to_string(uint8_t* pk, const uint8_t* pk_seed, const rbc_61_vec y);
void ryde_3s_public_key_from_string(rbc_61_mat H, rbc_61_vec y, const uint8_t* pk);

void ryde_3s_secret_key_to_string(uint8_t* sk, const uint8_t* sk_seed, const uint8_t* pk_seed);
void ryde_3s_secret_key_from_string(rbc_61_vec y, rbc_61_mat H, rbc_61_vec s, rbc_61_mat_fq C, const uint8_t* sk);

#endif

