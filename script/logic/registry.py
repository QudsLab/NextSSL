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
    # ── Layer 3 — main ───────────────────────────────────────────────────────
    "3.1":   ["gen/main/core",     "test/probe/main/core",     "test/main/core"],
    "3.2":   ["gen/main/hash",     "test/probe/main/hash",     "test/main/hash"],
    "3.3":   ["gen/main/pqc",      "test/probe/main/pqc",      "test/main/pqc"],
    "3.4":   ["gen/main/pow",      "test/probe/main/pow",      "test/main/pow"],
    "3.5":   [                     "test/probe/main/keygen",   "test/main/keygen"],

    # ── Layer 4 — primary ────────────────────────────────────────────────────
    "4.1":   ["gen/primary/system",      "test/probe/primary/system",      "test/primary/system"],
    "4.2":   ["gen/primary/system_lite", "test/probe/primary/system_lite", "test/primary/system_lite"],
}


def expand(selector: str) -> list[str]:
    """Return all registry paths whose key starts with `selector`.

    Examples:
        expand("3")   → all main paths
        expand("3.4") → ["gen/main/pow", "test/main/pow"]
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
    """Return the active top-level layer numbers."""
    return [3, 4]
