"""
logic/registry.py
Single source of truth: layer number string → list of script module paths.

Adding a new sublayer = add one key here. Nothing else changes.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# LAYER_REGISTRY
# key   = layer-number string matching the numbering in LAYER_SELECT_PLAN.md
# value = list of script paths (relative to script/) that belong to that key
# ---------------------------------------------------------------------------
LAYER_REGISTRY: dict[str, list[str]] = {
    # ── Layer 1 — partial ────────────────────────────────────────────────────
    "1.1":       ["gen/partial/core",       "test/partial/core"],
    "1.1.1":     ["gen/partial/core/aes_aead",       "test/partial/core/aes_aead"],
    "1.1.2":     ["gen/partial/core/aes_modes",      "test/partial/core/aes_modes"],
    "1.1.3":     ["gen/partial/core/ecc",            "test/partial/core/ecc"],
    "1.1.4":     ["gen/partial/core/macs",           "test/partial/core/macs"],
    "1.1.5":     ["gen/partial/core/stream_aead",    "test/partial/core/stream_aead"],

    "1.2":       ["gen/partial/dhcm",       "test/partial/dhcm"],
    "1.2.1":     ["gen/partial/dhcm/legacy_alive",         "test/partial/dhcm/legacy_alive"],
    "1.2.2":     ["gen/partial/dhcm/legacy_unsafe",        "test/partial/dhcm/legacy_unsafe"],
    "1.2.3":     ["gen/partial/dhcm/primitive_fast",       "test/partial/dhcm/primitive_fast"],
    "1.2.4":     ["gen/partial/dhcm/primitive_memory_hard","test/partial/dhcm/primitive_memory_hard"],
    "1.2.5":     ["gen/partial/dhcm/primitive_sponge_xof", "test/partial/dhcm/primitive_sponge_xof"],

    "1.3":       ["gen/partial/hash",       "test/partial/hash"],
    "1.3.1":     ["gen/partial/hash/legacy_alive",         "test/partial/hash/legacy_alive"],
    "1.3.2":     ["gen/partial/hash/legacy_unsafe",        "test/partial/hash/legacy_unsafe"],
    "1.3.3":     ["gen/partial/hash/primitive_fast",       "test/partial/hash/primitive_fast"],
    "1.3.4":     ["gen/partial/hash/primitive_memory_hard","test/partial/hash/primitive_memory_hard"],
    "1.3.5":     ["gen/partial/hash/primitive_sponge_xof", "test/partial/hash/primitive_sponge_xof"],

    "1.4":       ["gen/partial/pow",        "test/partial/pow"],
    "1.4.1":     ["gen/partial/pow/legacy_alive",          "test/partial/pow/legacy_alive"],
    "1.4.2":     ["gen/partial/pow/legacy_unsafe",         "test/partial/pow/legacy_unsafe"],
    "1.4.3":     ["gen/partial/pow/primitive_fast",        "test/partial/pow/primitive_fast"],
    "1.4.4":     ["gen/partial/pow/primitive_memory_hard", "test/partial/pow/primitive_memory_hard"],
    "1.4.5":     ["gen/partial/pow/primitive_sponge_xof",  "test/partial/pow/primitive_sponge_xof"],

    "1.5":       ["gen/partial/pqc",        "test/partial/pqc"],
    "1.5.1":     ["gen/partial/pqc/kem_code_based",  "test/partial/pqc/kem_code_based"],
    "1.5.2":     ["gen/partial/pqc/kem_lattice",     "test/partial/pqc/kem_lattice"],
    "1.5.3":     ["gen/partial/pqc/sign_hash_based", "test/partial/pqc/sign_hash_based"],
    "1.5.4":     ["gen/partial/pqc/sign_lattice",    "test/partial/pqc/sign_lattice"],

    # ── Layer 2 — base ───────────────────────────────────────────────────────
    "2.1":       ["gen/base/core",          "test/base/core"],
    "2.1.1":     ["gen/base/core/cipher",   "test/base/core/cipher"],
    "2.1.2":     ["gen/base/core/ecc",      "test/base/core/ecc"],
    "2.1.3":     ["gen/base/core/mac",      "test/base/core/mac"],

    "2.2":       ["gen/base/dhcm",          "test/base/dhcm"],
    "2.2.1":     ["gen/base/dhcm/legacy",   "test/base/dhcm/legacy"],
    "2.2.2":     ["gen/base/dhcm/primitive","test/base/dhcm/primitive"],

    "2.3":       ["gen/base/hash",          "test/base/hash"],
    "2.3.1":     ["gen/base/hash/legacy",   "test/base/hash/legacy"],
    "2.3.2":     ["gen/base/hash/primitive","test/base/hash/primitive"],

    "2.4":       ["gen/base/pow",           "test/base/pow"],
    "2.4.1":     ["gen/base/pow/combined",  "test/base/pow/combined"],
    "2.4.2":     ["gen/base/pow/legacy",    "test/base/pow/legacy"],
    "2.4.3":     ["gen/base/pow/primitive", "test/base/pow/primitive"],

    "2.5":       ["gen/base/pqc",           "test/base/pqc"],
    "2.5.1":     ["gen/base/pqc/kem",       "test/base/pqc/kem"],
    "2.5.2":     ["gen/base/pqc/sign",      "test/base/pqc/sign"],

    # ── Layer 3 — main ───────────────────────────────────────────────────────
    "3.1":       ["gen/main/core",          "test/main/core"],
    "3.2":       ["gen/main/dhcm",          "test/main/dhcm"],
    "3.3":       ["gen/main/hash",          "test/main/hash"],
    "3.4":       ["gen/main/pow",           "test/main/pow"],
    "3.4.1":     ["gen/main/pow/single",    "test/main/pow/single"],
    "3.4.2":     ["gen/main/pow/combined",  "test/main/pow/combined"],
    "3.5":       ["gen/main/pqc",           "test/main/pqc"],
    "3.6":       ["gen/main/system",        "test/main/system"],

    # ── Layer 4 — primary ────────────────────────────────────────────────────
    "4.1":       ["gen/primary/system",      "test/primary/system"],
    "4.2":       ["gen/primary/system_lite", "test/primary/system_lite"],
}


def expand(selector: str) -> list[str]:
    """Return all registry paths whose key starts with `selector`.

    Examples:
        expand("1")   → all partial paths
        expand("1.3") → all partial/hash paths
        expand("4.1") → ["gen/primary/system", "test/primary/system"]
    """
    results: list[str] = []
    seen: set[str] = set()
    for key, paths in LAYER_REGISTRY.items():
        if key == selector or key.startswith(selector + "."):
            for p in paths:
                if p not in seen:
                    seen.add(p)
                    results.append(p)
    return results


def all_top_layers() -> list[int]:
    """Return the four top-level layer numbers."""
    return [1, 2, 3, 4]
