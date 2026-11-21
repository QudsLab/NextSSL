/**
 * \file rbc_53_vspace.h
 * \brief Interface for subspaces of Fq^m
 */

#ifndef RBC_53_VSPACE_H
#define RBC_53_VSPACE_H

#include "rbc_53.h"

#include "seedexpander_shake.h"

void rbc_53_vspace_init(rbc_53_vspace* vs, uint32_t size);

void rbc_53_vspace_clear(rbc_53_vspace vs);

void rbc_53_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_53_vspace o, uint32_t size);

#endif

