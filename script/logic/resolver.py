"""
logic/resolver.py
ParsedFlags → ExecutionMatrix.

Applies modifier-flag precedence chain in order:
  loc → loe → loft → lofb → lntt → lntb → -l selector filter
"""

from __future__ import annotations

from .matrix import ExecutionMatrix, ExecutionNode
from .parser import ParsedFlags
from .registry import all_top_layers


def resolve(flags: ParsedFlags) -> ExecutionMatrix:
    """Apply flags and modifier precedence to produce an ExecutionMatrix."""
    layers = all_top_layers()  # [1, 2, 3, 4]

    # Start: all layers active, build+test enabled
    nodes: dict[int, ExecutionNode] = {
        n: ExecutionNode(layer=n, active=True, do_build=True, do_test=True, reason="default")
        for n in layers
    }

    # Step 1 — --loe (exclusive): deactivate all layers NOT in the loe list
    if flags.loe:
        for n in layers:
            if n not in flags.loe:
                nodes[n].active = False
                nodes[n].reason = f"--loe {','.join(str(x) for x in flags.loe)} → only those layers run"

    # Step 2 — --loc (cancel): hard-cancel listed layers (overrides loe)
    for n in flags.loc:
        if n in nodes:
            nodes[n].active = False
            nodes[n].do_build = False
            nodes[n].do_test = False
            nodes[n].reason = f"--loc {n} → cancelled"

    # Step 3 — --loft (test-only): suppress build
    for n in flags.loft:
        if n in nodes and nodes[n].active:
            nodes[n].do_build = False
            nodes[n].reason = f"--loft {n} → test only"

    # Step 4 — --lofb (build-only): suppress test
    # Also resolves conflict: if both loft and lofb target same layer → lofb wins
    for n in flags.lofb:
        if n in nodes and nodes[n].active:
            nodes[n].do_test = False
            if not nodes[n].do_build:
                # loft had suppressed build; lofb restores it and suppresses test instead
                nodes[n].do_build = True
            nodes[n].reason = f"--lofb {n} → build only (overrides --loft if both set)"

    # Step 5 — --lntt (no test): suppress test, build still runs
    for n in flags.lntt:
        if n in nodes and nodes[n].active:
            nodes[n].do_test = False
            existing = nodes[n].reason
            nodes[n].reason = f"--lntt {n} → build runs, tests suppressed" + (
                f" (+ {existing})" if existing != "default" else ""
            )

    # Step 6 — --lntb (no build): suppress build, test still runs
    for n in flags.lntb:
        if n in nodes and nodes[n].active:
            nodes[n].do_build = False
            existing = nodes[n].reason
            nodes[n].reason = f"--lntb {n} → test runs, build suppressed" + (
                f" (+ {existing})" if existing != "default" else ""
            )

    # Step 7 — constraint: if both suppressed → deactivate
    for n in layers:
        node = nodes[n]
        if node.active and not node.do_build and not node.do_test:
            node.active = False
            node.reason += " → both suppressed, treating as --loc"

    # Step 8 — filter to -l selector
    # The layers field is a comma-separated string like "1,2,3,4" or "4"
    selected_top: set[int] = set()
    for token in flags.layers.split(","):
        token = token.strip()
        if token:
            # Only the first character matters for top-level (e.g. "4.1" → top-layer 4)
            try:
                top = int(token.split(".")[0])
                selected_top.add(top)
            except ValueError:
                pass

    for n in layers:
        if nodes[n].active and n not in selected_top:
            nodes[n].active = False
            nodes[n].reason = f"not in -l selector ({flags.layers})"

    # Build final layer_selector string (only active layers)
    active = sorted(n for n in layers if nodes[n].active)
    layer_selector = ",".join(str(n) for n in active)

    # Resolve platform list
    platforms = [p.strip() for p in flags.platforms.split(",") if p.strip()]

    return ExecutionMatrix(
        platforms=platforms,
        load_mode=flags.load_mode,
        nodes=nodes,
        layer_selector=layer_selector,
    )
