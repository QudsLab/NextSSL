#include <stdint.h>
#include <string.h>
#include <printf.h>

#include "prng.h"
#include "random.h"
#include "mirath_matrix_ff.h"
#include "mirath_parsing.h"
#include "mirath_ggm_tree.h"
#include "mirath_tcith.h"


int mirath_sign(uint8_t *sig_msg, uint8_t *msg, size_t msg_len, uint8_t *sk) {
    uint8_t salt[MIRATH_PARAM_SALT_BYTES] = {0};
    seed_t rseed = {0};
    uint64_t ctr;
    mirath_ggm_tree_node_t path[MIRATH_PARAM_MAX_OPEN] = {0};
    hash_t h_mpc;

    ff_t S[MIRATH_VAR_FF_S_BYTES];
    ff_t C[MIRATH_VAR_FF_C_BYTES];
    ff_t H[MIRATH_VAR_FF_H_BYTES];

    uint8_t pk[MIRATH_PUBLIC_KEY_BYTES] = {0};

    ff_mu_t S_base[MIRATH_PARAM_TAU][MIRATH_VAR_S];
    ff_mu_t C_base[MIRATH_PARAM_TAU][MIRATH_VAR_C];
    ff_mu_t v_base[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];
    ff_mu_t v[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];
    ff_t aux[MIRATH_PARAM_TAU][MIRATH_VAR_FF_AUX_BYTES];
    hash_t h_sh;
    mirath_tcith_commit_t commits_i_star[MIRATH_PARAM_TAU];
    mirath_ggm_tree_t tree = {0};
    mirath_tcith_commit_t *commits[MIRATH_PARAM_TAU];
    mirath_tcith_commit_1_t commits_1 = {0};
    mirath_tcith_commit_2_t commits_2;
    mirath_tcith_commit_set_as_a_grid_list(commits, &commits_1, &commits_2);

    ff_mu_t Gamma[MIRATH_VAR_GAMMA];

    ff_mu_t alpha_mid[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];
    ff_mu_t alpha_base[MIRATH_PARAM_TAU][MIRATH_PARAM_RHO];

    // Phase 0: Initialization
    // step 1
    mirath_matrix_decompress_secret_key(S, C, H, pk, (const uint8_t *)sk);
    // step 2
    randombytes(salt, MIRATH_PARAM_SALT_BYTES);

    // step 3
    randombytes(rseed, MIRATH_SECURITY_BYTES);

    // Phase 1:  Build and Commit Parallel Witness Shares
    // step 4
    commit_parallel_sharings(S_base, C_base, v_base, v, h_sh, tree, commits, aux, salt, rseed, S, C);

    // step 5
    mirath_tcith_expand_mpc_challenge(Gamma, h_sh);

    // Phase 2: MPC simulation
    // steps 6, 7 and 8
    for (uint32_t e = 0; e < MIRATH_PARAM_TAU; e++) {
        emulateMPC_mu(alpha_base[e], alpha_mid[e], S, S_base[e], C, C_base[e], v[e], v_base[e], Gamma, H);
    }

    // step 9
    mirath_tcith_hash_mpc(h_mpc, pk, salt, msg, msg_len, h_sh, alpha_mid, alpha_base);

    // Phase 3: Sharing Opening.
    // step 10
    ctr = mirath_tcith_open_random_share(path, commits_i_star, tree,
                                         (mirath_tcith_commit_t const **) (mirath_tcith_commit_t (*)[MIRATH_PARAM_TAU]) commits, h_mpc);

    // step 11
    unparse_signature(sig_msg, salt, ctr, h_mpc, path, commits_i_star, aux, alpha_mid);

    return 0;
}
