#include <stdint.h>
#include <string.h>

#include "prng.h"
#include "random.h"
#include "mirath_matrix_ff.h"
#include "mirath_parsing.h"
#include "mirath_tcith.h"

int mirath_verify(uint8_t *msg, size_t *msg_len, uint8_t *sig_msg, uint8_t *pk) {
    uint8_t salt[MIRATH_PARAM_SALT_BYTES];
    hash_t h_sh;
    hash_t h_mpc_prime = {0};
    hash_t h_mpc = {0};
    uint64_t ctr;
    mirath_tcith_view_challenge_t i_star;
    ff_t H[MIRATH_VAR_FF_H_BYTES];
    ff_t y[MIRATH_VAR_FF_Y_BYTES];
    mirath_tcith_commit_t commits_i_star[MIRATH_PARAM_TAU];
    mirath_ggm_tree_node_t path[MIRATH_PARAM_MAX_OPEN] = {0};
    ff_mu_t S_share[MIRATH_PARAM_TAU][MIRATH_VAR_S];
    ff_mu_t C_share[MIRATH_PARAM_TAU][MIRATH_VAR_C];
    ff_mu_t v_share[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];
    ff_mu_t Gamma[MIRATH_VAR_GAMMA];
    ff_t aux[MIRATH_PARAM_TAU][MIRATH_VAR_FF_AUX_BYTES] = {0};
    ff_mu_t alpha_mid[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO] = {0};
    ff_mu_t alpha_base[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];

    int ret = 0;

    // Phase 0: Initialization (parsing and expansion)
    // step 1
    ret = parse_signature(salt, &ctr, h_mpc, path, commits_i_star, aux, alpha_mid, sig_msg);
    if (ret != 0) {
        return 1;
    }

    // step 2
    mirath_matrix_decompress_pk(H, y, pk);

    // Phase 1: Recomputing shares.
    // step 3
    ret = mirath_tcith_compute_parallel_shares(S_share, C_share, v_share,i_star, h_sh,  ctr,  path, commits_i_star, aux, salt, h_mpc);

    // Phase 2: MPC simulation.
    // step 4
    mirath_tcith_expand_mpc_challenge(Gamma, h_sh);

    // steps 5 and 6
    for (uint32_t e = 0; e < MIRATH_PARAM_TAU; e++) {
        emulateparty_mu(alpha_base[e], i_star[e], S_share[e], C_share[e], v_share[e], Gamma, H, y, alpha_mid[e]);
    }

    // Phase 3: Verification
    // step 7
    mirath_tcith_hash_mpc(h_mpc_prime, pk, salt, msg, *msg_len, h_sh, alpha_mid, alpha_base);

    // step 8
    if (!hash_equal(h_mpc, h_mpc_prime)) {
        ret = 1;
    }

    return ret;
}
