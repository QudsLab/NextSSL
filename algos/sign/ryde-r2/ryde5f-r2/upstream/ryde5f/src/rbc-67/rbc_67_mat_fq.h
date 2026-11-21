/**
 * \file rbc_67_mat_fq.h
 * \brief Interface for matrices over Fq
 */

#ifndef RBC_67_MAT_FQ_H
#define RBC_67_MAT_FQ_H

#include "rbc_67.h"
#include "rbc_67_elt.h"
#include "rbc_67_vec.h"
#include "seedexpander_shake.h"

void rbc_67_mat_fq_init(rbc_67_mat_fq* m, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_clear(rbc_67_mat_fq m);
void rbc_67_mat_fq_set(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_set_zero(rbc_67_mat_fq m, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_set_identity(rbc_67_mat_fq m, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_set_transpose(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_from_string(rbc_67_mat_fq m, uint32_t rows, uint32_t cols, const uint8_t* str);
void rbc_67_mat_fq_set_random(seedexpander_shake_t* ctx, rbc_67_mat_fq o, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_to_string(uint8_t* str, const rbc_67_mat_fq m, uint32_t rows, uint32_t cols);
void rbc_67_mat_fq_add(rbc_67_mat_fq o, const rbc_67_mat_fq a, const rbc_67_mat_fq b, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_mul(rbc_67_mat_fq o, const rbc_67_mat_fq m1, const rbc_67_mat_fq m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2);
void rbc_67_mat_fq_mul_by_vec_left(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_mul_by_vec_right(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_mul_by_constant(rbc_67_mat o, const rbc_67_mat_fq m, const rbc_67_elt c, uint32_t rows, uint32_t columns);
void rbc_67_mat_fq_minmax(rbc_67_mat_fq c1, uint64_t* x, rbc_67_mat_fq c2, uint64_t* y, uint32_t size);
void rbc_67_mat_fq_set_inverse(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t size);
void rbc_67_mat_fq_print(const rbc_67_mat_fq m, uint32_t rows, uint32_t columns);
#endif

