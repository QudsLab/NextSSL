# DHCM — Difficulty/Hash Cost Model

The DHCM subsystem calculates the work and memory cost of a given hash
algorithm under a given difficulty model.  It is a standalone computation
layer — it does not perform any hashing itself.

Header: `src/DHCM/utils/dhcm_api.h`

---

## Structs

### `DHCMParams` — Input

| Field | Type | Description |
|---|---|---|
| `algorithm` | `DHCMAlgorithm` | Algorithm identifier (see table below) |
| `difficulty_model` | `DHCMDifficultyModel` | None / target-based / iteration-based |
| `target_leading_zeros` | `uint32_t` | Leading zero bits required (target-based PoW) |
| `iterations` | `uint32_t` | Time cost / t_cost (Argon2) |
| `memory_kb` | `uint32_t` | Memory cost in KiB / m_cost (Argon2) |
| `parallelism` | `uint32_t` | Thread count / p (Argon2) |
| `input_size` | `size_t` | Input data size in bytes |
| `output_size` | `size_t` | Output hash size in bytes |

### `DHCMResult` — Output

| Field | Type | Description |
|---|---|---|
| `work_units_per_eval` | `uint64_t` | Work units for a single hash evaluation |
| `memory_units_per_eval` | `uint64_t` | Memory units (KB) for a single evaluation |
| `expected_trials` | `double` | E\[N\] = expected trials to solve (target-based) |
| `total_work_units` | `uint64_t` | WU × E\[N\] |
| `total_memory_units` | `uint64_t` | MU × parallelism (where applicable) |
| `verification_work_units` | `uint64_t` | Work units to verify a solution |
| `algorithm_name` | `const char*` | Human-readable algorithm name |
| `cost_model_version` | `const char*` | Version of the cost model used |

---

## Entry Points

```c
// Calculate work and memory cost
int nextssl_dhcm_calculate(const DHCMParams *params, DHCMResult *result);

// Get algorithm metadata
int nextssl_dhcm_get_algorithm_info(DHCMAlgorithm algo,
                                    const char **name,
                                    uint64_t *base_wu,
                                    size_t *block_size);

// Expected trial count for a given difficulty and model
double nextssl_dhcm_expected_trials(DHCMDifficultyModel model,
                                    uint32_t target_zeros);
```

---

## Algorithm IDs

### Group 0x01xx — Primitive Fast

| ID | Constant | Algorithm |
|---|---|---|
| 0x0100 | `DHCM_SHA256` | SHA-256 |
| 0x0101 | `DHCM_SHA512` | SHA-512 |
| 0x0102 | `DHCM_BLAKE2B` | BLAKE2b |
| 0x0103 | `DHCM_BLAKE2S` | BLAKE2s |
| 0x0104 | `DHCM_BLAKE3` | BLAKE3 |

### Group 0x02xx — Memory-Hard

| ID | Constant | Algorithm |
|---|---|---|
| 0x0200 | `DHCM_ARGON2ID` | Argon2id |
| 0x0201 | `DHCM_ARGON2I` | Argon2i |
| 0x0202 | `DHCM_ARGON2D` | Argon2d |

### Group 0x03xx — Sponge / XOF

| ID | Constant | Algorithm |
|---|---|---|
| 0x0300 | `DHCM_SHA3_256` | SHA3-256 |
| 0x0301 | `DHCM_SHA3_512` | SHA3-512 |
| 0x0302 | `DHCM_KECCAK_256` | Keccak-256 |
| 0x0303 | `DHCM_SHAKE128` | SHAKE128 |
| 0x0304 | `DHCM_SHAKE256` | SHAKE256 |

### Group 0x04xx — Legacy Alive

| ID | Constant | Algorithm |
|---|---|---|
| 0x0400 | `DHCM_MD5` | MD5 |
| 0x0401 | `DHCM_SHA1` | SHA-1 |
| 0x0402 | `DHCM_RIPEMD160` | RIPEMD-160 |
| 0x0403 | `DHCM_WHIRLPOOL` | Whirlpool |
| 0x0404 | `DHCM_NT` | NT hash |

### Group 0x05xx — Legacy Unsafe

| ID | Constant | Algorithm |
|---|---|---|
| 0x0500 | `DHCM_MD2` | MD2 |
| 0x0501 | `DHCM_MD4` | MD4 |
| 0x0502 | `DHCM_SHA0` | SHA-0 |
| 0x0503 | `DHCM_HAS160` | HAS-160 |
| 0x0504 | `DHCM_RIPEMD128` | RIPEMD-128 |
| 0x0505 | `DHCM_RIPEMD256` | RIPEMD-256 |
| 0x0506 | `DHCM_RIPEMD320` | RIPEMD-320 |

---

## Difficulty Models

| Constant | Value | Description |
|---|---|---|
| `DHCM_DIFFICULTY_NONE` | 0 | No difficulty — cost of a single hash |
| `DHCM_DIFFICULTY_TARGET_BASED` | 1 | Leading-zero PoW; uses `target_leading_zeros` |
| `DHCM_DIFFICULTY_ITERATION_BASED` | 2 | Fixed iteration count; uses `iterations`, `memory_kb`, `parallelism` |
