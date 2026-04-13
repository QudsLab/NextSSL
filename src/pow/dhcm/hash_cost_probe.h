/* hash_cost_probe.h — Adapter-based cost model probe (Plan 40005)
 *
 * Takes a pre-configured hash_adapter_t and runs it as a real benchmark.
 * Produces two sets of measurements side-by-side:
 *
 *   - formula   : hash_cost_compute() output (exact formula, all 8 dimensions)
 *   - measured  : actual wall-clock timing from n_trials live adapter runs
 *
 * Design rules:
 *   - The adapter is treated as a BLACK BOX — the probe never inspects impl.
 *   - For DF (memory-hard) algos: cost_params MUST be provided so the formula
 *     side can be computed. Without params the probe returns PROBE_ERR_DF_NEEDS_PARAMS.
 *   - For fast hashes: cost_params may be NULL — probe substitutes default
 *     (input_bytes = 64).
 *   - The adapter must already be fully configured before calling probe.
 *     A DF adapter that was never config()'d will use library defaults, which
 *     may not match the cost_params you provide. That mismatch is YOUR problem.
 *   - No heap allocation inside the probe. All timing arrays are on the stack.
 *   - n_trials is capped at HASH_COST_PROBE_MAX_TRIALS.
 */
#ifndef HASH_COST_PROBE_H
#define HASH_COST_PROBE_H

#include "hash_cost.h"
#include "../../hash/adapters/hash_adapter.h"

/* Maximum number of timing trials (stack-allocated). */
#define HASH_COST_PROBE_MAX_TRIALS  64

/* Recommended trial counts:
 *   Fast hash   — at least 100 (very fast; single run is too noisy)
 *   Memory-hard — at least 3   (each run is expensive) */
#define HASH_COST_PROBE_TRIALS_FAST   100
#define HASH_COST_PROBE_TRIALS_DF       3

/* -----------------------------------------------------------------------
 * hash_cost_probe_result_t — combined formula + measured output
 * ----------------------------------------------------------------------- */
typedef struct hash_cost_probe_result_s {
    /* ---- Input classification ---------------------------------------- */
    const char *algo_name;          /* pointer to the name passed in       */
    int         is_df;              /* 1 = memory-hard DF algo             */
    int         adapter_ok;         /* 1 = adapter->hash_fn returned 0     */

    /* ---- Timing measurements from n_trials live runs ----------------- */
    uint32_t    n_trials;           /* actual number of trials run         */
    uint64_t    ns_min;             /* fastest single eval (nanoseconds)   */
    uint64_t    ns_max;             /* slowest single eval                 */
    uint64_t    ns_median;          /* median single eval (noise-robust)   */
    uint64_t    ns_total;           /* sum of all n_trials                 */

    /* ---- Formula output from hash_cost_compute ----------------------- */
    int         formula_valid;      /* 1 = compute succeeded; 0 = no params*/
    hash_cost_t formula;            /* all 8 cost dimensions (zero if invalid) */

    /* ---- Cross-check: ns per primitive call -------------------------- */
    /*   ns_per_primitive = ns_median / formula.primitive_calls
     *   Compare to dhcm_cycles_per_prim / CPU_GHz to validate calibration.
     *   Zero if formula_valid == 0 or primitive_calls == 0.               */
    uint64_t    ns_per_primitive;
} hash_cost_probe_result_t;

/* -----------------------------------------------------------------------
 * Error codes returned by hash_cost_probe()
 * ----------------------------------------------------------------------- */
#define PROBE_OK                  0
#define PROBE_ERR_NULL           -1  /* adapter, algo_name, or result is NULL    */
#define PROBE_ERR_UNKNOWN_ALGO   -2  /* algo_name not found in DHCM registry     */
#define PROBE_ERR_DF_NEEDS_PARAMS -3 /* DF algo given but cost_params == NULL    */
#define PROBE_ERR_ADAPTER_FAILED -4  /* adapter->hash_fn returned non-zero       */

/* -----------------------------------------------------------------------
 * hash_cost_probe — run the adapter as a benchmark + formula check
 *
 * adapter        — pre-configured hash_adapter_t. Must not be NULL.
 * algo_name      — canonical name (e.g. "argon2id", "sha256"). Must not be NULL.
 * cost_params    — pointer to the correct hash_cost_params_* struct.
 *                  Required for DFs (PROBE_ERR_DF_NEEDS_PARAMS if missing).
 *                  May be NULL for fast hashes (uses default 64-byte input).
 * cost_params_size — sizeof(*cost_params). Ignored if cost_params == NULL.
 * n_trials       — how many adapter evaluations to time.
 *                  Capped at HASH_COST_PROBE_MAX_TRIALS.
 *                  Minimum enforced at 1.
 * result         — filled on return. Must not be NULL.
 *
 * Returns PROBE_OK (0) on success, or one of the PROBE_ERR_* codes.
 * On PROBE_ERR_ADAPTER_FAILED the timing fields are zero; formula is still
 * computed if params were provided.
 * ----------------------------------------------------------------------- */
int hash_cost_probe(hash_adapter_t           *adapter,
                    const char               *algo_name,
                    const void               *cost_params,
                    size_t                    cost_params_size,
                    uint32_t                  n_trials,
                    hash_cost_probe_result_t *result);

/* -----------------------------------------------------------------------
 * hash_cost_probe_print — print a human-readable summary to stdout.
 * Prints both formula and measured fields side-by-side.
 * ----------------------------------------------------------------------- */
void hash_cost_probe_print(const hash_cost_probe_result_t *result);

#endif /* HASH_COST_PROBE_H */
