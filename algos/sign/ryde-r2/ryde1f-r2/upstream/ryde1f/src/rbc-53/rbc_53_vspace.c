/**
 * \file rbc_53_vspace.c
 * \brief Implementation of rbc_53_vspace.h
 */

#include "rbc_53.h"
#include "rbc_53_vspace.h"
#include "rbc_53_vec.h"




/**
 * \fn void rbc_53_vspace_init(rbc_53_vspace* vs, uint32_t size)
 * \brief This function allocates the memory for a rbc_53_vspace.
 *
 * \param[out] vs Pointer to the allocated rbc_53_vspace
 * \param[in] size Size of the rbc_53_vspace
 */
void rbc_53_vspace_init(rbc_53_vspace* vs, uint32_t size) {
  rbc_53_vec_init(vs, size);
}




/**
 * \fn void rbc_53_vspace_clear(rbc_53_vspace vs)
 * \brief This functions clears the memory allocated to a rbc_53_vspace.
 *
 * \param[in] v rbc_53_vspace
 * \param[in] size Size of the rbc_53_vspace
 */
void rbc_53_vspace_clear(rbc_53_vspace vs) {
  rbc_53_vec_clear(vs);
}




/**
 * \fn void rbc_53_vspace_set_random_full_rank_with_one(seedexpander_shake* ctx, rbc_53_vspace o, uint32_t size) {
 * \brief This function sets a rbc_53_vspace with random values using a seed expander. The rbc_53_vspace returned by this function has full rank and contains one.
 *
 * \param[out] ctx Seed expander
 * \param[out] o rbc_53_vspace
 * \param[in] size Size of rbc_53_vspace
 */
void rbc_53_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_53_vspace o, uint32_t size) {
  rbc_53_vec_set_random_full_rank_with_one(ctx, o, size);
}

