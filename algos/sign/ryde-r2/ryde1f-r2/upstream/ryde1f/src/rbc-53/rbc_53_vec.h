/**
 * \file rbc_53_vec.h
 * \brief Interface for vectors of finite field elements
 */

#ifndef RBC_53_VEC_H
#define RBC_53_VEC_H

#include "rbc_53.h"
#include "rbc_53_elt.h"

#include "seedexpander_shake.h"

void rbc_53_vec_init(rbc_53_vec* v, uint32_t size);

void rbc_53_vec_clear(rbc_53_vec v);

void rbc_53_vec_set_zero(rbc_53_vec v, uint32_t size);

void rbc_53_vec_set(rbc_53_vec o, const rbc_53_vec v, uint32_t size);

void rbc_53_vec_set_random(seedexpander_shake_t* ctx, rbc_53_vec o, uint32_t size);

void rbc_53_vec_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_53_vec o, uint32_t size);

void rbc_53_vec_set_random_from_support(seedexpander_shake_t* ctx, rbc_53_vec o, uint32_t size, const rbc_53_vec support, uint32_t support_size, uint8_t copy_flag);
uint32_t rbc_53_vec_gauss(rbc_53_vec v, uint32_t size, uint8_t reduced_flag, rbc_53_vec *other_matrices, uint32_t nMatrices);

uint32_t rbc_53_vec_get_rank(const rbc_53_vec v, uint32_t size);

void rbc_53_vec_add(rbc_53_vec o, const rbc_53_vec v1, const rbc_53_vec v2, uint32_t size);

void rbc_53_vec_inner_product(rbc_53_elt o, const rbc_53_vec v1, const rbc_53_vec v2, uint32_t size);

void rbc_53_vec_scalar_mul(rbc_53_vec o, const rbc_53_vec v, const rbc_53_elt e, uint32_t size);

void rbc_53_vec_to_string(uint8_t* str, const rbc_53_vec v, uint32_t size);

void rbc_53_vec_from_string(rbc_53_vec v, uint32_t size, const uint8_t* str);

void rbc_53_vec_from_bytes(rbc_53_vec o, uint32_t size, uint8_t *random);

void rbc_53_vec_to_bytes( uint8_t *o, const rbc_53_vec v, uint32_t size);

void rbc_53_vec_print(const rbc_53_vec v, uint32_t size);

#endif

