/**
 * \file rbc_61_vspace.h
 * \brief Interface for subspaces of Fq^m
 */

#ifndef RBC_61_VSPACE_H
#define RBC_61_VSPACE_H

#include "rbc_61.h"

#include "seedexpander_shake.h"

void rbc_61_vspace_init(rbc_61_vspace* vs, uint32_t size);

void rbc_61_vspace_clear(rbc_61_vspace vs);

void rbc_61_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_61_vspace o, uint32_t size);

#endif

