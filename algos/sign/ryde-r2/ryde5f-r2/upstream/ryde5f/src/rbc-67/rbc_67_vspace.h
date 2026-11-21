/**
 * \file rbc_67_vspace.h
 * \brief Interface for subspaces of Fq^m
 */

#ifndef RBC_67_VSPACE_H
#define RBC_67_VSPACE_H

#include "rbc_67.h"

#include "seedexpander_shake.h"

void rbc_67_vspace_init(rbc_67_vspace* vs, uint32_t size);

void rbc_67_vspace_clear(rbc_67_vspace vs);

void rbc_67_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_67_vspace o, uint32_t size);

#endif

