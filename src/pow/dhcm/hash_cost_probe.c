/* hash_cost_probe.c — Adapter-based cost model probe (Plan 40005)
 *
 * Runs a pre-configured hash_adapter_t as a real benchmark, then compares
 * the measured timing to the formula output from hash_cost_compute().
 *
 * No heap allocation. All timing samples are on the stack.
 * Platform-portable nanosecond timer via POSIX clock_gettime or Win32 QPC.
 */
#include "hash_cost_probe.h"
#include "hash_cost.h"
#include "dhcm_types.h"
#include "dhcm_core.h"
#include "../../hash/adapters/hash_adapter.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Platform-portable nanosecond timer
 * ----------------------------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

static uint64_t probe_ns(void) {
    LARGE_INTEGER now, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    /* Multiply first to reduce integer truncation error */
    return (uint64_t)(now.QuadPart / freq.QuadPart) * 1000000000ULL
         + (uint64_t)(now.QuadPart % freq.QuadPart) * 1000000000ULL / (uint64_t)freq.QuadPart;
}

#elif defined(__EMSCRIPTEN__)
/* WASM: emscripten_get_now() returns ms as double */
#  include <emscripten.h>

static uint64_t probe_ns(void) {
    return (uint64_t)(emscripten_get_now() * 1e6);
}

#else
/* POSIX: clock_gettime(CLOCK_MONOTONIC) */
#  include <time.h>

static uint64_t probe_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

/* -----------------------------------------------------------------------
 * Simple insertion sort for timing samples (n <= HASH_COST_PROBE_MAX_TRIALS)
 * ----------------------------------------------------------------------- */
static void sort_u64(uint64_t *arr, uint32_t n) {
    for (uint32_t i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/* -----------------------------------------------------------------------
 * is_df_algo — true if algo is a memory-hard DF (group 0x05xx in DHCM)
 * ----------------------------------------------------------------------- */
static int is_df_algo(const char *name) {
    DHCMAlgorithm id = dhcm_algo_from_name(name);
    /* All memory-hard algorithms span DHCM_ARGON2ID (0x0500) to DHCM_MAKWA (0x050A) */
    return (id >= DHCM_ARGON2ID && id <= DHCM_MAKWA);
}

/* -----------------------------------------------------------------------
 * hash_cost_probe — implementation
 * ----------------------------------------------------------------------- */
int hash_cost_probe(hash_adapter_t           *adapter,
                    const char               *algo_name,
                    const void               *cost_params,
                    size_t                    cost_params_size,
                    uint32_t                  n_trials,
                    hash_cost_probe_result_t *result)
{
    if (!adapter || !algo_name || !result) return PROBE_ERR_NULL;

    /* Zero-initialise result */
    memset(result, 0, sizeof(*result));
    result->algo_name = algo_name;

    /* ---- Classify algorithm ------------------------------------------ */
    DHCMAlgorithm dhcm_id = dhcm_algo_from_name(algo_name);
    if (dhcm_id == DHCM_ALGO_UNKNOWN) return PROBE_ERR_UNKNOWN_ALGO;
    result->is_df = is_df_algo(algo_name);

    /* DF algo without cost_params → cannot compute formula; fail explicitly */
    if (result->is_df && !cost_params) return PROBE_ERR_DF_NEEDS_PARAMS;

    /* ---- Clamp n_trials ---------------------------------------------- */
    if (n_trials == 0) n_trials = 1;
    if (n_trials > HASH_COST_PROBE_MAX_TRIALS) n_trials = HASH_COST_PROBE_MAX_TRIALS;
    result->n_trials = n_trials;

    /* ---- Formula side: hash_cost_compute ----------------------------- */
    if (cost_params && cost_params_size > 0) {
        int fc = hash_cost_compute(algo_name, cost_params, cost_params_size,
                                   &result->formula);
        result->formula_valid = (fc == 0) ? 1 : 0;
    } else {
        /* Fast hash without params: default 64-byte input */
        hash_cost_params_fast_t fp = { .input_bytes = 64 };
        int fc = hash_cost_compute(algo_name, &fp, sizeof fp, &result->formula);
        result->formula_valid = (fc == 0) ? 1 : 0;
    }

    /* ---- Benchmark: run adapter n_trials times ----------------------- */
    /* Fixed 64-byte dummy input — content doesn't affect cost, only length */
    static const uint8_t dummy_input[64] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x44, 0x48, 0x43, 0x4d, 0x20, 0x70,
        0x72, 0x6f, 0x62, 0x65, 0x20, 0x74, 0x65, 0x73,
        0x74, 0x20, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x2e,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t out_buf[64];
    size_t  out_len = adapter->digest_size > 0 ? adapter->digest_size : 32;
    if (out_len > sizeof(out_buf)) out_len = sizeof(out_buf);

    /* Warm-up: one untimed run to avoid cold-cache on first trial */
    int warm = adapter->hash_fn(adapter->impl, dummy_input, sizeof dummy_input,
                                out_buf, out_len);
    if (warm != 0) {
        result->adapter_ok = 0;
        return PROBE_ERR_ADAPTER_FAILED;
    }
    result->adapter_ok = 1;

    /* Timed trials */
    uint64_t samples[HASH_COST_PROBE_MAX_TRIALS];
    uint64_t total_ns = 0;

    for (uint32_t i = 0; i < n_trials; i++) {
        uint64_t t0 = probe_ns();
        adapter->hash_fn(adapter->impl, dummy_input, sizeof dummy_input,
                         out_buf, out_len);
        uint64_t t1 = probe_ns();
        samples[i] = t1 > t0 ? t1 - t0 : 0;
        total_ns  += samples[i];
    }

    /* Sort for min/median/max */
    sort_u64(samples, n_trials);

    result->ns_total  = total_ns;
    result->ns_min    = samples[0];
    result->ns_max    = samples[n_trials - 1];
    result->ns_median = samples[n_trials / 2];

    /* ---- Cross-check: ns per primitive call -------------------------- */
    if (result->formula_valid && result->formula.primitive_calls > 0) {
        result->ns_per_primitive =
            result->ns_median / result->formula.primitive_calls;
    }

    return PROBE_OK;
}

/* -----------------------------------------------------------------------
 * hash_cost_probe_print — human-readable summary
 * ----------------------------------------------------------------------- */
void hash_cost_probe_print(const hash_cost_probe_result_t *r) {
    if (!r) return;

    static const char *tier_names[] = {
        "STACK", "L1", "L2", "L3", "DRAM", "?"
    };
    static const char *access_names[] = {
        "?", "SEQUENTIAL", "RANDOM", "MIXED"
    };

    printf("=== hash_cost_probe: %s ===\n", r->algo_name ? r->algo_name : "?");
    printf("  type            : %s\n", r->is_df ? "memory-hard DF" : "fast hash");
    printf("  adapter_ok      : %s\n", r->adapter_ok ? "yes" : "NO — failed");
    printf("\n");

    /* ---- Measured timing -------------------------------------------- */
    printf("  [measured — %u trials]\n", r->n_trials);
    printf("  ns_min          : %llu ns\n",    (unsigned long long)r->ns_min);
    printf("  ns_median       : %llu ns\n",    (unsigned long long)r->ns_median);
    printf("  ns_max          : %llu ns\n",    (unsigned long long)r->ns_max);
    if (r->ns_median >= 1000000ULL)
        printf("  ms_per_eval     : %.3f ms\n",
               (double)r->ns_median / 1e6);
    printf("\n");

    /* ---- Formula ------------------------------------------------------- */
    if (r->formula_valid) {
        const hash_cost_t *f = &r->formula;
        uint8_t tier  = f->memory_tier < 5 ? f->memory_tier : 5;
        uint8_t acc   = (f->access_pattern >= 1 && f->access_pattern <= 3)
                        ? f->access_pattern : 0;

        printf("  [formula — hash_cost_compute]\n");
        printf("  peak_bytes      : %llu  (%llu KiB)\n",
               (unsigned long long)f->peak_bytes,
               (unsigned long long)(f->peak_bytes >> 10));
        printf("  bandwidth_bytes : %llu  (%llu MiB)\n",
               (unsigned long long)f->bandwidth_bytes,
               (unsigned long long)(f->bandwidth_bytes >> 20));
        printf("  primitive_calls : %llu\n",
               (unsigned long long)f->primitive_calls);
        printf("  primitive_id    : 0x%02X\n", f->primitive_id);
        printf("  parallel_limit  : %u\n",     f->parallel_limit);
        printf("  dep_depth       : %llu\n",   (unsigned long long)f->dependency_depth);
        printf("  access_pattern  : %s\n",     access_names[acc]);
        printf("  memory_tier     : %s\n",     tier_names[tier]);
        printf("  reread_factor   : %u\n",     f->memory_reread_factor);
        printf("  bit_ops         : %llu\n",   (unsigned long long)f->bit_ops);
        printf("  flags           : 0x%08X%s%s%s%s%s\n",
               f->flags,
               (f->flags & HASH_COST_MEMORY_HARD) ? " MEMORY_HARD" : "",
               (f->flags & HASH_COST_SEQ_HARD)    ? " SEQ_HARD"    : "",
               (f->flags & HASH_COST_EXACT)        ? " EXACT"       : "",
               (f->flags & HASH_COST_APPROX)       ? " APPROX"      : "",
               (f->flags & HASH_COST_ZERO_MEM)     ? " ZERO_MEM"    : "");
        printf("\n");

        /* Cross-check */
        if (r->ns_per_primitive > 0) {
            printf("  [cross-check]\n");
            printf("  ns/primitive    : %llu ns  (ns_median / primitive_calls)\n",
                   (unsigned long long)r->ns_per_primitive);
        }
    } else {
        printf("  [formula]       : not computed (no cost_params provided)\n\n");
    }
    printf("=====================================\n");
}
