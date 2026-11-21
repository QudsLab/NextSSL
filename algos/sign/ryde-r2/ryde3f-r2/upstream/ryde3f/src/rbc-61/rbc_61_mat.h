/**
 * \file rbc_61_mat.h
 * \brief Interface for matrices over Fq^m
 */

#ifndef RBC_61_MAT_H
#define RBC_61_MAT_H

#include "rbc_61.h"
#include "rbc_61_elt.h"
#include "rbc_61_vec.h"

#include "seedexpander_shake.h"

void rbc_61_mat_init(rbc_61_mat* m, uint32_t rows, uint32_t columns);
void rbc_61_mat_clear(rbc_61_mat m);
void rbc_61_mat_set(rbc_61_mat o, const rbc_61_mat m, uint32_t rows, uint32_t columns);
void rbc_61_mat_set_zero(rbc_61_mat m, uint32_t rows, uint32_t columns);
void rbc_61_mat_set_random(seedexpander_shake_t* ctx, rbc_61_mat o, uint32_t rows, uint32_t columns);
void rbc_61_mat_add(rbc_61_mat o, const rbc_61_mat m1, const rbc_61_mat m2, uint32_t rows, uint32_t columns);
void rbc_61_mat_mul(rbc_61_mat o, const rbc_61_mat m1, const rbc_61_mat m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2);
void rbc_61_mat_mul_by_vec_right(rbc_61_vec o, const rbc_61_mat m, const rbc_61_vec v, uint32_t rows, uint32_t columns);
void rbc_61_mat_mul_by_vec_left(rbc_61_vec o, const rbc_61_mat m, const rbc_61_vec v, uint32_t rows, uint32_t columns);
void rbc_61_mat_mul_by_vec_left_transpose(rbc_61_vec o, const rbc_61_mat m, const rbc_61_vec v, uint32_t rows, uint32_t columns);
void rbc_61_mat_to_string(uint8_t* str, const rbc_61_mat m, uint32_t rows, uint32_t columns);
void rbc_61_mat_from_string(rbc_61_mat m, uint32_t rows, uint32_t columns, const uint8_t* str);
void rbc_61_mat_print(const rbc_61_mat m, uint32_t rows, uint32_t columns);
#endif

