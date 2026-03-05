"""
logic/reporter.py
Format and print the [REACTOR] parse report.

The report is ALWAYS printed on every run (Actions log + local dry-run)
so you can verify exactly what was parsed and what will execute.
"""

from __future__ import annotations

from .matrix import ExecutionMatrix
from .parser import ParsedFlags

_SEP_THICK = "═" * 48
_SEP_THIN  = "─" * 48
_PREFIX    = "[REACTOR] "


def _p(line: str = "") -> str:
    return _PREFIX + line


def _bool_mark(val: bool) -> str:
    return "✓" if val else "✗"


def _csv_or_empty(lst: list[int]) -> str:
    return ",".join(str(x) for x in lst) if lst else "(none)"


def _layer_name(n: int) -> str:
    names = {1: "partial", 2: "base", 3: "main", 4: "primary"}
    return names.get(n, "?")


def _node_status(node) -> str:
    if not node.active:
        return "SKIPPED"
    if node.do_build and node.do_test:
        return "BUILD + TEST"
    if node.do_build:
        return "BUILD ONLY"
    if node.do_test:
        return "TEST ONLY"
    return "INACTIVE"


def format_report(flags: ParsedFlags, matrix: ExecutionMatrix) -> str:
    """Return the full [REACTOR] report as a single string."""
    lines: list[str] = []
    a = lines.append

    a(_p(_SEP_THICK))
    a(_p(" COMMIT CONTROL PARSE REPORT"))
    a(_p(f" Event:  {flags.fields_from.get('event_name', 'push')}"))
    sources = " + ".join(flags.flags_found_in) if flags.flags_found_in else "default"
    a(_p(f" Source: {sources}"))
    a(_p(_SEP_THIN))

    # Raw input
    a(_p(" RAW TITLE:"))
    a(_p(f'   "{flags.raw_title}"'))
    a(_p(" RAW DESCRIPTION:"))
    desc = flags.raw_description.strip()
    if desc:
        for dline in desc.splitlines():
            a(_p(f"   {dline}"))
    else:
        a(_p("   (empty)"))
    a(_p(_SEP_THIN))

    # Parsed flags
    a(_p(" PARSED FLAGS:"))

    def _src(field: str) -> str:
        s = flags.fields_from.get(field, "")
        return f"  (from: {s})" if s else ""

    a(_p(f"   --gen         {_bool_mark(flags.has_gen)}{_src('has_gen')}"))
    a(_p(f"   --genAll      {_bool_mark(flags.has_gen_all)}{_src('has_gen_all')}"))
    a(_p(f"   --genQuick    {_bool_mark(flags.has_gen_quick)}{_src('has_gen_quick')}"))
    a(_p(f"   --test        {_bool_mark(flags.has_test)}{_src('has_test')}"))
    a(_p(f"   --no_gen      {_bool_mark(flags.has_no_gen)}{_src('has_no_gen')}"))
    a(_p(f"   --beta        {_bool_mark(flags.has_beta)}{_src('has_beta')}"))
    a(_p(f"   --release     {_bool_mark(flags.has_release)}{_src('has_release')}"))
    a(_p(f"   -l            {flags.layers or '(default)'}{_src('layers')}"))
    a(_p(f"   --platform    {flags.platforms or '(default)'}{_src('platforms')}"))
    a(_p(f"   --loft        {_csv_or_empty(flags.loft)}{_src('loft')}"))
    a(_p(f"   --lofb        {_csv_or_empty(flags.lofb)}{_src('lofb')}"))
    a(_p(f"   --lntt        {_csv_or_empty(flags.lntt)}{_src('lntt')}"))
    a(_p(f"   --lntb        {_csv_or_empty(flags.lntb)}{_src('lntb')}"))
    a(_p(f"   --loc         {_csv_or_empty(flags.loc)}{_src('loc')}"))
    a(_p(f"   --loe         {_csv_or_empty(flags.loe)}{_src('loe')}"))
    a(_p(f"   load_mode     {flags.load_mode}{_src('load_mode')}"))
    a(_p(_SEP_THIN))

    # Execution matrix
    a(_p(" EXECUTION MATRIX:"))
    for n in [1, 2, 3, 4]:
        node = matrix.nodes.get(n)
        if node is None:
            continue
        status = _node_status(node)
        a(_p(f"   Layer {n} ({_layer_name(n):<8})  {status:<14}  — {node.reason}"))
    a(_p(_SEP_THIN))

    a(_p(f" PLATFORMS:  {', '.join(matrix.platforms)}"))
    a(_p(f" LOAD MODE:  {matrix.load_mode}"))
    a(_p(_SEP_THIN))

    if matrix.warnings:
        for w in matrix.warnings:
            a(_p(f" WARNING: {w}"))
    else:
        a(_p(" WARNINGS:   (none)"))

    if matrix.errors:
        for e in matrix.errors:
            a(_p(f" ERROR:   {e}"))
    else:
        a(_p(" ERRORS:     (none)"))

    a(_p(_SEP_THIN))

    # GITHUB_OUTPUT preview
    a(_p(" GITHUB_OUTPUT (will write):"))
    output = matrix.github_output_dict(
        flags_loft=flags.loft,
        flags_lofb=flags.lofb,
        flags_lntt=flags.lntt,
        flags_lntb=flags.lntb,
        flags_loc=flags.loc,
        flags_loe=flags.loe,
    )
    for key, val in output.items():
        a(_p(f"   {key}={val if val else '(empty)'}"))

    a(_p(_SEP_THICK))
    return "\n".join(lines)


def print_report(flags: ParsedFlags, matrix: ExecutionMatrix) -> None:
    """Print the [REACTOR] report to stdout."""
    print(format_report(flags, matrix), flush=True)
