/**
 * \file rbc_61_vspace.c
 * \brief Implementation of rbc_61_vspace.h
 */

#include "rbc_61.h"
#include "rbc_61_vspace.h"
#include "rbc_61_vec.h"




/**
 * \fn void rbc_61_vspace_init(rbc_61_vspace* vs, uint32_t size)
 * \brief This function allocates the memory for a rbc_61_vspace.
 *
 * \param[out] vs Pointer to the allocated rbc_61_vspace
 * \param[in] size Size of the rbc_61_vspace
 */
void rbc_61_vspace_init(rbc_61_vspace* vs, uint32_t size) {
  rbc_61_vec_init(vs, size);
}




/**
 * \fn void rbc_61_vspace_clear(rbc_61_vspace vs)
 * \brief This functions clears the memory allocated to a rbc_61_vspace.
 *
 * \param[in] v rbc_61_vspace
 * \param[in] size Size of the rbc_61_vspace
 */
void rbc_61_vspace_clear(rbc_61_vspace vs) {
  rbc_61_vec_clear(vs);
}




/**
 * \fn void rbc_61_vspace_set_random_full_rank_with_one(seedexpander_shake* ctx, rbc_61_vspace o, uint32_t size) {
 * \brief This function sets a rbc_61_vspace with random values using a seed expander. The rbc_61_vspace returned by this function has full rank and contains one.
 *
 * \param[out] ctx Seed expander
 * \param[out] o rbc_61_vspace
 * \param[in] size Size of rbc_61_vspace
 */
void rbc_61_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_61_vspace o, uint32_t size) {
  rbc_61_vec_set_random_full_rank_with_one(ctx, o, size);
}

