#ifndef MIRATH_TCITH_H
#define MIRATH_TCITH_H

#include <stdint.h>
#include <stdlib.h>
#include "mirath_parameters.h"
#include "mirath_ggm_tree.h"
#include "arith//mirath_arith.h"

#define MIRATH_BLOCK_LENGTH ((MIRATH_VAR_FF_S_BYTES + MIRATH_VAR_FF_C_BYTES + (MIRATH_PARAM_RHO * sizeof(ff_mu_t)) + (MIRATH_SECURITY_BYTES - 1)) / MIRATH_SECURITY_BYTES)

typedef uint8_t mirath_tcith_commit_t[2 * MIRATH_SECURITY_BYTES];
typedef mirath_tcith_commit_t mirath_tcith_commit_1_t[MIRATH_PARAM_TAU_1][MIRATH_PARAM_N_1];
typedef mirath_tcith_commit_t mirath_tcith_commit_2_t[MIRATH_PARAM_TAU_2][MIRATH_PARAM_N_2];

typedef uint32_t mirath_tcith_view_challenge_t[MIRATH_PARAM_TAU];

void mirath_tcith_internal_steps_pk(ff_t y[MIRATH_VAR_FF_Y_BYTES],
                                    const ff_t S[MIRATH_VAR_FF_S_BYTES], const ff_t C[MIRATH_VAR_FF_C_BYTES],
                                    const ff_t H[MIRATH_VAR_FF_H_BYTES]);


void mirath_tcith_commit_set_as_a_grid_list(mirath_tcith_commit_t *seeds[MIRATH_PARAM_TAU],
                                            mirath_tcith_commit_1_t *input_1,
                                            mirath_tcith_commit_2_t *input_2);

void mirath_tcith_commit(mirath_tcith_commit_t commit, const uint8_t *salt, uint16_t e, uint32_t i, const uint8_t *seed);
size_t mirath_tcith_psi(size_t i, size_t e);

void commit_parallel_sharings(ff_mu_t S_base[MIRATH_PARAM_TAU][MIRATH_VAR_S],
                            ff_mu_t C_base[MIRATH_PARAM_TAU][MIRATH_VAR_C],
                            ff_mu_t v_base[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO],
                            ff_mu_t v[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO],
                            hash_t hash_sh,
                            mirath_ggm_tree_t tree,
                            mirath_tcith_commit_t *commits[MIRATH_PARAM_TAU],
                            ff_t aux[MIRATH_PARAM_TAU][MIRATH_VAR_FF_AUX_BYTES],
                            const uint8_t salt[MIRATH_PARAM_SALT_BYTES],
                            const seed_t rseed,
                            const ff_t S[MIRATH_VAR_FF_S_BYTES],
                            const ff_t C[MIRATH_VAR_FF_C_BYTES]);

void compute_share(ff_mu_t S_share[MIRATH_VAR_S],
                   ff_mu_t C_share[MIRATH_VAR_C],
                   ff_mu_t v_share[MIRATH_PARAM_RHO],
                   uint32_t i_star, const mirath_ggm_tree_leaves_t seeds, uint32_t e,
                   const ff_t aux[MIRATH_VAR_FF_AUX_BYTES],
                   const uint8_t salt[MIRATH_PARAM_SALT_BYTES]);

void split_codeword_ff_mu(ff_mu_t e_A[MIRATH_VAR_E_A], ff_mu_t e_B[MIRATH_PARAM_K],
                          const ff_mu_t in_X[MIRATH_VAR_S],
                          const ff_mu_t in_Y[MIRATH_VAR_BASE_MID]);

void emulateMPC_mu(ff_mu_t base_alpha[MIRATH_PARAM_RHO], ff_mu_t mid_alpha[MIRATH_PARAM_RHO],
                   const ff_t S[MIRATH_VAR_FF_S_BYTES], const ff_mu_t S_rnd[MIRATH_VAR_S],
                   const ff_t C[MIRATH_VAR_FF_C_BYTES], const ff_mu_t C_rnd[MIRATH_VAR_C],
                   const ff_mu_t v[MIRATH_PARAM_RHO], ff_mu_t rnd_v[MIRATH_PARAM_RHO],
                   const ff_mu_t gamma[MIRATH_VAR_GAMMA], const ff_t H[MIRATH_VAR_FF_H_BYTES]);

void emulateparty_mu(ff_mu_t base_alpha[MIRATH_PARAM_RHO], ff_mu_t p,
                     const ff_mu_t S_share[MIRATH_VAR_S], const ff_mu_t C_share[MIRATH_VAR_C],
                     const ff_mu_t v_share[MIRATH_PARAM_RHO], const ff_mu_t gamma[MIRATH_VAR_GAMMA],
                     const ff_t H[MIRATH_VAR_FF_H_BYTES], const ff_t y[MIRATH_VAR_FF_Y_BYTES],
                     const ff_mu_t mid_alpha[MIRATH_PARAM_RHO]);

void mirath_tcith_expand_mpc_challenge(ff_mu_t Gamma[MIRATH_VAR_GAMMA], const hash_t h_sh);

void mirath_tcith_hash_mpc(hash_t h_mpc,
                        const uint8_t pk[MIRATH_PUBLIC_KEY_BYTES],
                        const uint8_t salt[MIRATH_PARAM_SALT_BYTES],
                        const uint8_t *msg, size_t msg_len,
                        const hash_t h_sh,
                        const ff_mu_t alpha_mid[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO],
                        const ff_mu_t alpha_base[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO]);

void mirath_tcith_hash_sh(hash_t h_sh,
                            const uint8_t salt[MIRATH_PARAM_SALT_BYTES],
                            const hash_t h_com,
                            const ff_t aux[MIRATH_PARAM_TAU][MIRATH_VAR_FF_AUX_BYTES]);

void mirath_tcith_expand_view_challenge(mirath_tcith_view_challenge_t challenge, uint8_t *v_grinding, const uint8_t *string_input);

uint8_t mirath_tcith_discard_input_challenge_2(const uint8_t *seed_input);

int64_t mirath_tcith_open_random_share(mirath_ggm_tree_node_t path[MIRATH_PARAM_MAX_OPEN],
                                        mirath_tcith_commit_t commits_i_star[MIRATH_PARAM_TAU],
                                        const mirath_ggm_tree_t tree,
                                        const mirath_tcith_commit_t *commits[MIRATH_PARAM_TAU],
                                        const hash_t binding);


int mirath_tcith_compute_parallel_shares(ff_mu_t S_share[MIRATH_PARAM_TAU][MIRATH_VAR_S],
                                       ff_mu_t C_share[MIRATH_PARAM_TAU][MIRATH_VAR_C],
                                       ff_mu_t v_share[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO],
                                       mirath_tcith_view_challenge_t i_star,
                                       hash_t h_sh,
                                       const uint64_t ctr,
                                       const mirath_ggm_tree_node_t path[MIRATH_PARAM_MAX_OPEN],
                                       const mirath_tcith_commit_t commits_i_star[MIRATH_PARAM_TAU],
                                       const ff_t aux[MIRATH_PARAM_TAU][MIRATH_VAR_FF_AUX_BYTES],
                                       const uint8_t salt[MIRATH_PARAM_SALT_BYTES],
                                       const hash_t binding);

#define mirath_tcith_shift_to_right(shiftOut, highIn, lowIn, shift, DigitSize)  \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << ((DigitSize) - (shift)));

#endif //MIRATH_TCITH_H
