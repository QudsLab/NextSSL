"""
script/reactor.py
Entry point called by the `parse_layers` GitHub Actions job.

Reads environment variables, runs the full parse → resolve → validate →
report pipeline, writes GITHUB_OUTPUT, and exits.

──────────────────────────────────────────────────
HOW TO CONFIGURE
──────────────────────────────────────────────────
All tuneable settings are in the CONFIG block below
(labeled "easy to modify").  You should NEVER need
to touch the code below the ── PIPELINE ── divider.

To add a new flag:
  1. Add regex entry to FLAG_PATTERNS in script/logic/parser.py
  2. Add field to ParsedFlags in the same file
  3. Add entry to RUNNER_FLAG_MAP below (if it maps to a runner.py arg)

──────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import sys
import argparse
import pathlib

# Make sure the workspace root is on sys.path when called directly
_HERE = pathlib.Path(__file__).resolve()
_ROOT = _HERE.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from script.logic.parser   import RawContext, parse
from script.logic.resolver import resolve
from script.logic.validator import validate
from script.logic.reporter  import print_report
from script.logic.matrix    import ExecutionMatrix


# ═══════════════════════════════════════════════════════════════════════════════
# EASY-TO-CONFIGURE SECTION
# Edit the dicts/lists below to change behaviour.
# Never edit below the "PIPELINE" divider.
# ═══════════════════════════════════════════════════════════════════════════════

# ── Guard flags ─────────────────────────────────────────────────────────────
# If ANY of these are present in the commit message the run is blocked.
GUARD_FLAGS: list[str] = [
    "--no_gen",
]

# ── Trigger flags ────────────────────────────────────────────────────────────
# At least one of these must be present for a run to proceed.
TRIGGER_FLAGS: list[str] = [
    "--gen",
    "--genAll",
    "--genQuick",
    "--test",
]

# ── Layer names (layer number → tier name used in runner.py calls) ───────────
LAYER_NAMES: dict[int, str] = {
    1: "partial",
    2: "base",
    3: "main",
    4: "system",   # called "system" in the YAML tier arg, layer 4
}

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_LAYERS:    str = "1,2,3,4"
DEFAULT_PLATFORMS: str = "web,linux,mac,windows"
DEFAULT_LOAD_MODE: str = "gen"

# ── Runner flag map ──────────────────────────────────────────────────────────
# Maps a commit flag name → the runner.py CLI arg it controls.
# Informational only (not used by reactor logic — used by developers
# who need to know what runner.py arguments correspond to each flag).
RUNNER_FLAG_MAP: dict[str, str] = {
    "--gen":        "--build ... --test ...",
    "--genAll":     "--load-mode genAll",
    "--genQuick":   "--load-mode genQuick",
    "--test":       "--test ...",
    "--platform":   "--platform ...",
    "-l":           "(selects which jobs run)",
    "--loft":       "(skips --build for layer N)",
    "--lofb":       "(skips --test for layer N)",
    "--lntt":       "(skips --test for layer N)",
    "--lntb":       "(skips --build for layer N)",
    "--loc":        "(cancels layer N entirely)",
    "--loe":        "(runs only layer N, cancels others)",
}

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE (do not edit below this line unless you know what you're doing)
# ═══════════════════════════════════════════════════════════════════════════════


def _split_commit_message(raw: str) -> tuple[str, str]:
    """Split a commit message into (title, description).
    Title = first line.  Description = everything after the first blank line.
    """
    lines = raw.splitlines()
    if not lines:
        return ("", "")
    title = lines[0].strip()
    desc_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if not in_body and line.strip() == "":
            in_body = True
            continue
        if in_body:
            desc_lines.append(line)
    return title, "\n".join(desc_lines)


def _contains_guard(title: str, description: str) -> str | None:
    """Return the first guard flag found in title+description, or None."""
    text = title + "\n" + description
    for flag in GUARD_FLAGS:
        if flag in text:
            return flag
    return None


def _write_github_output(path: str, data: dict[str, str]) -> None:
    """Append key=value pairs to the GITHUB_OUTPUT file."""
    with open(path, "a", encoding="utf-8") as fh:
        for key, val in data.items():
            fh.write(f"{key}={val}\n")


def main(dry_run: bool = False) -> int:
    """
    Full pipeline.  Returns exit code (0 = success, 1 = error / blocked).
    """
    # ── Read environment ─────────────────────────────────────────────────────
    event_name   = os.environ.get("REACTOR_EVENT_NAME",   "push")
    raw_msg      = os.environ.get("REACTOR_MSG",          "")
    wd_layers    = os.environ.get("REACTOR_WD_LAYERS",    "")
    wd_platforms = os.environ.get("REACTOR_WD_PLATFORMS", "")
    wd_load_mode = os.environ.get("REACTOR_WD_LOAD_MODE", "")
    gh_output    = os.environ.get("GITHUB_OUTPUT",        "")

    title, description = _split_commit_message(raw_msg)

    # ── Guard check (reactor does this itself per design) ────────────────────
    blocked_by = _contains_guard(title, description)

    # ── Build RawContext ─────────────────────────────────────────────────────
    ctx = RawContext(
        title        = title,
        description  = description,
        event_name   = event_name,
        wd_layers    = wd_layers,
        wd_platforms = wd_platforms,
        wd_load_mode = wd_load_mode,
    )

    # ── Parse → Resolve → Validate ───────────────────────────────────────────
    flags  = parse(ctx)
    matrix = resolve(flags)
    matrix = validate(flags, matrix)

    # If guard tripped, inject an error into the matrix report
    if blocked_by:
        matrix.errors.insert(
            0, f"BLOCKED: guard flag '{blocked_by}' found in commit message"
        )

    # ── Report (ALWAYS printed) ──────────────────────────────────────────────
    print_report(flags, matrix)

    # ── Determine exit code ──────────────────────────────────────────────────
    has_errors = bool(matrix.errors)

    # ── Write GITHUB_OUTPUT (unless dry-run or no output path) ──────────────
    if not dry_run:
        if gh_output:
            output_data = matrix.github_output_dict(
                flags_loft=flags.loft,
                flags_lofb=flags.lofb,
                flags_lntt=flags.lntt,
                flags_lntb=flags.lntb,
                flags_loc=flags.loc,
                flags_loe=flags.loe,
            )
            _write_github_output(gh_output, output_data)
        else:
            # Not in a GitHub Actions runner — print what would be written
            print("[REACTOR] (no GITHUB_OUTPUT path set; would write:)")
            output_data = matrix.github_output_dict(
                flags_loft=flags.loft,
                flags_lofb=flags.lofb,
                flags_lntt=flags.lntt,
                flags_lntb=flags.lntb,
                flags_loc=flags.loc,
                flags_loe=flags.loe,
            )
            for k, v in output_data.items():
                print(f"[REACTOR]   {k}={v if v else '(empty)'}")
    else:
        print("[REACTOR] --dry-run: GITHUB_OUTPUT NOT written.")

    return 1 if has_errors else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Reactor: parse commit message and emit GITHUB_OUTPUT."
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and report but do not write to GITHUB_OUTPUT.",
    )
    args = ap.parse_args()
    sys.exit(main(dry_run=args.dry_run))
