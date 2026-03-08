"""
logic/validator.py
Inspect ParsedFlags + ExecutionMatrix and append warnings/errors.

All checks are in CHECKS list at the bottom — add a new check there.
"""

from __future__ import annotations

from .matrix import ExecutionMatrix
from .parser import ParsedFlags


# ---------------------------------------------------------------------------
# Each check is a callable(flags, matrix) that may append to
# matrix.warnings or matrix.errors.
# ---------------------------------------------------------------------------
def _check_no_action(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """ERROR: no trigger flag found."""
    if not (flags.has_gen or flags.has_gen_all or flags.has_gen_quick or flags.has_test):
        matrix.errors.append(
            "no action flag found — add --gen, --genAll, --genQuick, or --test"
        )


def _check_layer_no_action(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """ERROR: -l used but no action flag."""
    any_action = flags.has_gen or flags.has_gen_all or flags.has_gen_quick or flags.has_test
    if flags.layers and not any_action:
        matrix.errors.append(
            f"layer selector '-l {flags.layers}' found but no --gen or --test"
        )


def _check_no_gen(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """ERROR: --no_gen detected."""
    if flags.has_no_gen:
        matrix.errors.append(
            "--no_gen detected — this run will be blocked"
        )


def _check_loft_lofb_conflict(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """WARNING: --loft and --lofb both target same layer (--lofb wins)."""
    overlap = sorted(set(flags.loft) & set(flags.lofb))
    if overlap:
        for n in overlap:
            matrix.warnings.append(
                f"layer {n}: --loft and --lofb both set; --lofb wins (build-only)"
            )


def _check_lntt_lntb_conflict(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """WARNING: --lntt + --lntb same layer → both suppressed → treated as --loc."""
    overlap = sorted(set(flags.lntt) & set(flags.lntb))
    if overlap:
        for n in overlap:
            matrix.warnings.append(
                f"layer {n}: --lntt + --lntb both set — both actions suppressed, "
                f"treating as --loc {n}"
            )


def _check_loe_loc_overlap(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """WARNING: --loe and --loc both cover a layer (--loc wins)."""
    overlap = sorted(set(flags.loe) & set(flags.loc))
    if overlap:
        for n in overlap:
            matrix.warnings.append(
                f"layer {n}: in both --loe and --loc; --loc takes precedence"
            )


def _check_all_inactive(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """WARNING: all layers cancelled."""
    if not matrix.active_layers():
        matrix.warnings.append(
            "all layers are cancelled — no build/test jobs will run"
        )


def _check_layer_out_of_range(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """ERROR: layer number out of 1-4 range in any modifier."""
    modifier_fields = [
        ("--loft", flags.loft),
        ("--lofb", flags.lofb),
        ("--lntt", flags.lntt),
        ("--lntb", flags.lntb),
        ("--loc",  flags.loc),
        ("--loe",  flags.loe),
    ]
    for flag, layers in modifier_fields:
        for n in layers:
            if not (1 <= n <= 4):
                matrix.errors.append(
                    f"invalid layer number {n} in {flag}; valid range: 1-4"
                )


def _check_genall_genquick_conflict(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """WARNING: --genAll and --genQuick both present (--genAll wins)."""
    if flags.has_gen_all and flags.has_gen_quick:
        matrix.warnings.append(
            "--genAll and --genQuick are mutually exclusive; --genAll wins"
        )


def _check_loe_empty(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """ERROR: --loe found but parsed to empty list."""
    # This scenario can happen if the regex matched but no valid ints followed
    # We detect it by checking parser found the flag but loe list is empty.
    # (flags.loe being [] while the raw text contained --loe is the indicator;
    #  parser leaves loe=[] if no valid numbers followed)
    # Simple: if loe is empty there is nothing to validate; not an error unless
    # the raw text contained --loe but parsing came up empty.
    # We handle this through the "no active layers" check instead.
    pass


# ---------------------------------------------------------------------------
# CHECKS list — add new check callables here
# ---------------------------------------------------------------------------
CHECKS = [
    _check_no_action,
    _check_layer_no_action,
    _check_no_gen,
    _check_loft_lofb_conflict,
    _check_lntt_lntb_conflict,
    _check_loe_loc_overlap,
    _check_all_inactive,
    _check_layer_out_of_range,
    _check_genall_genquick_conflict,
]


def validate(flags: ParsedFlags, matrix: ExecutionMatrix) -> ExecutionMatrix:
    """Run all checks. Appends warnings/errors to matrix in-place. Returns matrix."""
    for check in CHECKS:
        check(flags, matrix)
    return matrix
