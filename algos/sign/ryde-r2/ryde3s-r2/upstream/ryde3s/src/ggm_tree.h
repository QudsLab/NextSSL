/**
 * @file ryde_3s_ggm_tree.h
 * @brief Header file for ryde_3s_ggm_tree.c
 */

#ifndef RYDE_3S_GGM_TREE_H
#define RYDE_3S_GGM_TREE_H

#include <stdio.h>
#include <stdint.h>
#include "parameters.h"

#define RYDE_3S_LEAVES_SEEDS_OFFSET (RYDE_3S_PARAM_TREE_LEAVES - 1)

// No control on the path length for random instances, but experiments suggest 2 * RYDE_3S_PARAM_T_OPEN as upper bound
#define RYDE_3S_PARAM_MAX_OPEN (2 * RYDE_3S_PARAM_T_OPEN)

#if (RYDE_3S_PARAM_TREE_LEAVES > 0xFFFFFFFF)
#error RYDE_3S_PARAM_TREE_LEAVES must fit in uint32_t
#endif


typedef uint8_t ryde_3s_ggm_tree_node_t[RYDE_3S_SECURITY_BYTES];
typedef ryde_3s_ggm_tree_node_t ryde_3s_ggm_tree_t[2 * RYDE_3S_PARAM_TREE_LEAVES - 1] __attribute__((aligned(16)));
typedef ryde_3s_ggm_tree_node_t ryde_3s_ggm_tree_leaves_t[RYDE_3S_PARAM_TREE_LEAVES];

void ryde_3s_ggm_tree_expand(ryde_3s_ggm_tree_t ggm_tree, const uint8_t salt[RYDE_3S_SALT_BYTES]);

int ryde_3s_ggm_tree_partial_expand(ryde_3s_ggm_tree_t partial_ggm_tree,
                                 const uint8_t salt[RYDE_3S_SALT_BYTES],
                                 const ryde_3s_ggm_tree_node_t path_seeds[RYDE_3S_PARAM_MAX_OPEN],
                                 size_t path_length,
                                 const size_t hidden_leaves[RYDE_3S_PARAM_TAU]);

int ryde_3s_ggm_tree_get_sibling_path(ryde_3s_ggm_tree_node_t path_seeds[RYDE_3S_PARAM_MAX_OPEN],
                                   const ryde_3s_ggm_tree_t ggm_tree,
                                   const size_t hidden_leaves[RYDE_3S_PARAM_TAU]);

void ryde_3s_ggm_tree_get_leaves(ryde_3s_ggm_tree_leaves_t output, ryde_3s_ggm_tree_t tree);

void ryde_3s_ggm_tree_print_sibling_path(const ryde_3s_ggm_tree_node_t path[RYDE_3S_PARAM_T_OPEN]);

#endif //RYDE_3S_GGM_TREE_H
