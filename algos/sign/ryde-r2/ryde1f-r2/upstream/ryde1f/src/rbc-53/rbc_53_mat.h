/**
 * \file rbc_53_mat.h
 * \brief Interface for matrices over Fq^m
 */

#ifndef RBC_53_MAT_H
#define RBC_53_MAT_H

#include "rbc_53.h"
#include "rbc_53_elt.h"
#include "rbc_53_vec.h"

#include "seedexpander_shake.h"

void rbc_53_mat_init(rbc_53_mat* m, uint32_t rows, uint32_t columns);
void rbc_53_mat_clear(rbc_53_mat m);
void rbc_53_mat_set(rbc_53_mat o, const rbc_53_mat m, uint32_t rows, uint32_t columns);
void rbc_53_mat_set_zero(rbc_53_mat m, uint32_t rows, uint32_t columns);
void rbc_53_mat_set_random(seedexpander_shake_t* ctx, rbc_53_mat o, uint32_t rows, uint32_t columns);
void rbc_53_mat_add(rbc_53_mat o, const rbc_53_mat m1, const rbc_53_mat m2, uint32_t rows, uint32_t columns);
void rbc_53_mat_mul(rbc_53_mat o, const rbc_53_mat m1, const rbc_53_mat m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2);
void rbc_53_mat_mul_by_vec_right(rbc_53_vec o, const rbc_53_mat m, const rbc_53_vec v, uint32_t rows, uint32_t columns);
void rbc_53_mat_mul_by_vec_left(rbc_53_vec o, const rbc_53_mat m, const rbc_53_vec v, uint32_t rows, uint32_t columns);
void rbc_53_mat_mul_by_vec_left_transpose(rbc_53_vec o, const rbc_53_mat m, const rbc_53_vec v, uint32_t rows, uint32_t columns);
void rbc_53_mat_to_string(uint8_t* str, const rbc_53_mat m, uint32_t rows, uint32_t columns);
void rbc_53_mat_from_string(rbc_53_mat m, uint32_t rows, uint32_t columns, const uint8_t* str);
void rbc_53_mat_print(const rbc_53_mat m, uint32_t rows, uint32_t columns);
#endif

