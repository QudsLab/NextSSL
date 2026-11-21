/**
 * \file rbc_61_vec.h
 * \brief Interface for finite field elements
 */

#ifndef RBC_61_ELT_H
#define RBC_61_ELT_H

#include "rbc_61.h"


void rbc_61_field_init(void);
void rbc_61_elt_set_zero(rbc_61_elt o);

void rbc_61_elt_set_one(rbc_61_elt o);

void rbc_61_elt_set(rbc_61_elt o, const rbc_61_elt e);

void rbc_61_elt_set_mask1(rbc_61_elt o, const rbc_61_elt e1, const rbc_61_elt e2, uint32_t mask);

void rbc_61_elt_set_from_uint64(rbc_61_elt o, const uint64_t* e);

uint8_t rbc_61_elt_is_zero(const rbc_61_elt e);

uint8_t rbc_61_elt_is_equal_to(const rbc_61_elt e1, const rbc_61_elt e2);

int32_t rbc_61_elt_get_degree(const rbc_61_elt e);

uint8_t rbc_61_elt_get_coefficient(const rbc_61_elt e, uint32_t index);

void rbc_61_elt_set_coefficient_vartime(rbc_61_elt o, uint32_t index, uint8_t bit);

void rbc_61_elt_add(rbc_61_elt o, const rbc_61_elt e1, const rbc_61_elt e2);

void rbc_61_elt_mul(rbc_61_elt o, const rbc_61_elt e1, const rbc_61_elt e2);

void rbc_61_elt_sqr(rbc_61_elt o, const rbc_61_elt e);

void rbc_61_elt_reduce(rbc_61_elt o, const rbc_61_elt_ur e);

void rbc_61_elt_print(const rbc_61_elt e);

void rbc_61_elt_ur_set(rbc_61_elt_ur o, const rbc_61_elt_ur e);

void rbc_61_elt_ur_set_zero(rbc_61_elt_ur o);

void rbc_61_elt_ur_mul(rbc_61_elt_ur o, const rbc_61_elt e1, const rbc_61_elt e2);

void rbc_61_elt_ur_sqr(rbc_61_elt_ur o, const rbc_61_elt e);

void rbc_61_elt_to_string(uint8_t* str, const rbc_61_elt e);

#endif

