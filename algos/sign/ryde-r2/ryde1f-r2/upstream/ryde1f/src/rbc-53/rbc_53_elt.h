/**
 * \file rbc_53_vec.h
 * \brief Interface for finite field elements
 */

#ifndef RBC_53_ELT_H
#define RBC_53_ELT_H

#include "rbc_53.h"


void rbc_53_field_init(void);
void rbc_53_elt_set_zero(rbc_53_elt o);

void rbc_53_elt_set_one(rbc_53_elt o);

void rbc_53_elt_set(rbc_53_elt o, const rbc_53_elt e);

void rbc_53_elt_set_mask1(rbc_53_elt o, const rbc_53_elt e1, const rbc_53_elt e2, uint32_t mask);

void rbc_53_elt_set_from_uint64(rbc_53_elt o, const uint64_t* e);

uint8_t rbc_53_elt_is_zero(const rbc_53_elt e);

uint8_t rbc_53_elt_is_equal_to(const rbc_53_elt e1, const rbc_53_elt e2);

int32_t rbc_53_elt_get_degree(const rbc_53_elt e);

uint8_t rbc_53_elt_get_coefficient(const rbc_53_elt e, uint32_t index);

void rbc_53_elt_set_coefficient_vartime(rbc_53_elt o, uint32_t index, uint8_t bit);

void rbc_53_elt_add(rbc_53_elt o, const rbc_53_elt e1, const rbc_53_elt e2);

void rbc_53_elt_mul(rbc_53_elt o, const rbc_53_elt e1, const rbc_53_elt e2);

void rbc_53_elt_sqr(rbc_53_elt o, const rbc_53_elt e);

void rbc_53_elt_reduce(rbc_53_elt o, const rbc_53_elt_ur e);

void rbc_53_elt_print(const rbc_53_elt e);

void rbc_53_elt_ur_set(rbc_53_elt_ur o, const rbc_53_elt_ur e);

void rbc_53_elt_ur_set_zero(rbc_53_elt_ur o);

void rbc_53_elt_ur_mul(rbc_53_elt_ur o, const rbc_53_elt e1, const rbc_53_elt e2);

void rbc_53_elt_ur_sqr(rbc_53_elt_ur o, const rbc_53_elt e);

void rbc_53_elt_to_string(uint8_t* str, const rbc_53_elt e);

#endif

