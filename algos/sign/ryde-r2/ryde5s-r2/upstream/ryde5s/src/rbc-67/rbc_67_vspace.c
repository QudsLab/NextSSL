/**
 * \file rbc_67_vspace.c
 * \brief Implementation of rbc_67_vspace.h
 */

#include "rbc_67.h"
#include "rbc_67_vspace.h"
#include "rbc_67_vec.h"




/**
 * \fn void rbc_67_vspace_init(rbc_67_vspace* vs, uint32_t size)
 * \brief This function allocates the memory for a rbc_67_vspace.
 *
 * \param[out] vs Pointer to the allocated rbc_67_vspace
 * \param[in] size Size of the rbc_67_vspace
 */
void rbc_67_vspace_init(rbc_67_vspace* vs, uint32_t size) {
  rbc_67_vec_init(vs, size);
}




/**
 * \fn void rbc_67_vspace_clear(rbc_67_vspace vs)
 * \brief This functions clears the memory allocated to a rbc_67_vspace.
 *
 * \param[in] v rbc_67_vspace
 * \param[in] size Size of the rbc_67_vspace
 */
void rbc_67_vspace_clear(rbc_67_vspace vs) {
  rbc_67_vec_clear(vs);
}




/**
 * \fn void rbc_67_vspace_set_random_full_rank_with_one(seedexpander_shake* ctx, rbc_67_vspace o, uint32_t size) {
 * \brief This function sets a rbc_67_vspace with random values using a seed expander. The rbc_67_vspace returned by this function has full rank and contains one.
 *
 * \param[out] ctx Seed expander
 * \param[out] o rbc_67_vspace
 * \param[in] size Size of rbc_67_vspace
 */
void rbc_67_vspace_set_random_full_rank_with_one(seedexpander_shake_t* ctx, rbc_67_vspace o, uint32_t size) {
  rbc_67_vec_set_random_full_rank_with_one(ctx, o, size);
}

