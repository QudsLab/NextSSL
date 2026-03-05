"""
logic/parser.py
Pure text → ParsedFlags.  No side effects, no I/O, no subprocess calls.

All flag patterns are defined in FLAG_PATTERNS at the top — add a new one
there and it is automatically picked up in both title and description.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# FLAG_PATTERNS
# Defines every commit-message flag and how to extract its value.
#
# Format per entry:
#   "flag_name": {
#       "pattern":  compiled regex with optional named group 'val'
#       "has_val":  True if the flag carries a value (e.g. "-l 4"), False if bare word
#       "field":    which ParsedFlags field this populates
#       "val_type": "str" | "int_list" (how to coerce the matched value)
#   }
#
# To add a new flag: add one entry here + a field to ParsedFlags below.
# ---------------------------------------------------------------------------
FLAG_PATTERNS: dict[str, dict] = {
    # ── Trigger flags ────────────────────────────────────────────────────────
    "--genAll": {
        "pattern":  re.compile(r"--genAll\b"),
        "has_val":  False,
        "field":    "has_gen_all",
        "val_type": "bool",
        "description": "Build + exhaustive tests",
    },
    "--genQuick": {
        "pattern":  re.compile(r"--genQuick\b"),
        "has_val":  False,
        "field":    "has_gen_quick",
        "val_type": "bool",
        "description": "Build + fast smoke test only",
    },
    "--gen": {
        # checked AFTER --genAll/--genQuick to avoid prefix clash
        "pattern":  re.compile(r"--gen\b"),
        "has_val":  False,
        "field":    "has_gen",
        "val_type": "bool",
        "description": "Generate (build) binaries",
    },
    "--test": {
        "pattern":  re.compile(r"--test\b"),
        "has_val":  False,
        "field":    "has_test",
        "val_type": "bool",
        "description": "Run tests only (no rebuild)",
    },
    "--no_gen": {
        "pattern":  re.compile(r"--no_gen\b"),
        "has_val":  False,
        "field":    "has_no_gen",
        "val_type": "bool",
        "description": "Guard abort flag",
    },
    "--beta": {
        "pattern":  re.compile(r"--beta\b"),
        "has_val":  False,
        "field":    "has_beta",
        "val_type": "bool",
        "description": "Mark as beta release",
    },
    "--release": {
        "pattern":  re.compile(r"--release\b"),
        "has_val":  False,
        "field":    "has_release",
        "val_type": "bool",
        "description": "Mark as stable release",
    },
    "--v": {
        "pattern":  re.compile(r"--v\s+\S+"),
        "has_val":  True,
        "field":    "has_version",
        "val_type": "bool",   # presence-only; value not stored in ParsedFlags
        "description": "Version bump push",
    },

    # ── Layer selector ───────────────────────────────────────────────────────
    "-l": {
        "pattern":  re.compile(r"-l\s+([\d,\.]+)"),
        "has_val":  True,
        "field":    "layers",
        "val_type": "str",
        "description": "Layer/sublayer selector",
    },

    # ── Platform selector ────────────────────────────────────────────────────
    "--platform": {
        "pattern":  re.compile(r"--platform\s+([\w,]+)"),
        "has_val":  True,
        "field":    "platforms",
        "val_type": "str",
        "description": "Platform override",
    },

    # ── Layer execution modifiers ─────────────────────────────────────────────
    "--loft": {
        "pattern":  re.compile(r"--loft\s+([\d,]+)"),
        "has_val":  True,
        "field":    "loft",
        "val_type": "int_list",
        "description": "Layer Only For Test",
    },
    "--lofb": {
        "pattern":  re.compile(r"--lofb\s+([\d,]+)"),
        "has_val":  True,
        "field":    "lofb",
        "val_type": "int_list",
        "description": "Layer Only For Build",
    },
    "--lntt": {
        "pattern":  re.compile(r"--lntt\s+([\d,]+)"),
        "has_val":  True,
        "field":    "lntt",
        "val_type": "int_list",
        "description": "Layer Not To Test",
    },
    "--lntb": {
        "pattern":  re.compile(r"--lntb\s+([\d,]+)"),
        "has_val":  True,
        "field":    "lntb",
        "val_type": "int_list",
        "description": "Layer Not To Build",
    },
    "--loc": {
        "pattern":  re.compile(r"--loc\s+([\d,]+)"),
        "has_val":  True,
        "field":    "loc",
        "val_type": "int_list",
        "description": "Layer Only Cancel",
    },
    "--loe": {
        "pattern":  re.compile(r"--loe\s+([\d,]+)"),
        "has_val":  True,
        "field":    "loe",
        "val_type": "int_list",
        "description": "Layer Only Execute",
    },
}


# ---------------------------------------------------------------------------
# ParsedFlags — result dataclass
# ---------------------------------------------------------------------------
@dataclass
class ParsedFlags:
    # Trigger
    has_gen:       bool = False
    has_gen_all:   bool = False
    has_gen_quick: bool = False
    has_test:      bool = False
    has_no_gen:    bool = False
    has_version:   bool = False
    has_beta:      bool = False
    has_release:   bool = False

    # Selection (defaults filled after text parse)
    layers:    str = ""   # e.g. "1,2,3,4" — empty means use default
    platforms: str = ""   # e.g. "web,linux,mac,windows"

    # Modifiers (top-level layer numbers only, 1-4)
    loft: list[int] = field(default_factory=list)
    lofb: list[int] = field(default_factory=list)
    lntt: list[int] = field(default_factory=list)
    lntb: list[int] = field(default_factory=list)
    loc:  list[int] = field(default_factory=list)
    loe:  list[int] = field(default_factory=list)

    # Load mode (resolved from trigger flag combinations)
    load_mode: str = "gen"

    # Source tracking (for parse report)
    flags_found_in:  list[str] = field(default_factory=list)  # ["title","description"]
    fields_from:     dict[str, str] = field(default_factory=dict)  # field → source
    raw_title:       str = ""
    raw_description: str = ""


# ---------------------------------------------------------------------------
# RawContext — what reactor.py feeds to parse()
# ---------------------------------------------------------------------------
@dataclass
class RawContext:
    title:        str   # first line of commit message
    description:  str   # text after first blank line
    event_name:   str   # "push" | "workflow_dispatch"
    wd_layers:    str   # workflow_dispatch input (empty string if push)
    wd_platforms: str   # workflow_dispatch input (empty string if push)
    wd_load_mode: str   # workflow_dispatch input (empty string if push)


# ---------------------------------------------------------------------------
# parse() — main entry point
# ---------------------------------------------------------------------------
_DEFAULTS = {
    "layers":    "1,2,3,4",
    "platforms": "web,linux,mac,windows",
    "load_mode": "gen",
}


def _coerce(raw: str, val_type: str) -> bool | str | list[int]:
    if val_type == "bool":
        return True
    if val_type == "str":
        return raw.strip()
    if val_type == "int_list":
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                pass  # invalid numbers silently ignored; validator catches them
        return result
    return raw


def _scan(text: str, source_label: str, flags: ParsedFlags) -> None:
    """Scan `text` for all FLAG_PATTERNS. Populate `flags` in-place.
    Title values already set are NOT overwritten (title wins)."""
    contributed = False
    for flag_name, cfg in FLAG_PATTERNS.items():
        field_name = cfg["field"]
        current = getattr(flags, field_name)
        # Skip if already populated by a higher-priority source (title)
        if cfg["val_type"] == "bool" and current:
            continue
        if cfg["val_type"] == "str" and current:
            continue
        if cfg["val_type"] == "int_list" and current:
            continue

        m = cfg["pattern"].search(text)
        if m is None:
            continue

        if cfg["has_val"]:
            raw_val = m.group(1) if m.lastindex else m.group(0)
        else:
            raw_val = ""

        coerced = _coerce(raw_val, cfg["val_type"])
        setattr(flags, field_name, coerced)
        flags.fields_from[field_name] = source_label
        contributed = True

    if contributed and source_label not in flags.flags_found_in:
        flags.flags_found_in.append(source_label)


def parse(ctx: RawContext) -> ParsedFlags:
    """Parse a RawContext and return a fully populated ParsedFlags."""
    flags = ParsedFlags(
        raw_title=ctx.title,
        raw_description=ctx.description,
    )

    # 1. Scan title first (highest priority)
    _scan(ctx.title, "title", flags)

    # 2. Scan description — extract FLAGS STARTED/FLAGS ENDED block first,
    #    then remaining description text.  Priority: title > block > rest.
    if ctx.description.strip():
        block_match = re.search(
            r"FLAGS\s+STARTED\s*(.*?)\s*FLAGS\s+ENDED",
            ctx.description,
            re.DOTALL | re.IGNORECASE,
        )
        if block_match:
            block_text = block_match.group(1).strip()
            desc_rest = (
                ctx.description[: block_match.start()]
                + ctx.description[block_match.end() :]
            ).strip()
            if block_text:
                _scan(block_text, "flags_block", flags)
            if desc_rest:
                _scan(desc_rest, "description", flags)
        else:
            _scan(ctx.description, "description", flags)

    # 3. workflow_dispatch overrides for layers / platforms / load_mode
    if ctx.event_name == "workflow_dispatch":
        if ctx.wd_layers.strip():
            flags.layers = ctx.wd_layers.strip()
            flags.fields_from["layers"] = "workflow_dispatch"
            if "workflow_dispatch" not in flags.flags_found_in:
                flags.flags_found_in.append("workflow_dispatch")
        if ctx.wd_platforms.strip():
            flags.platforms = ctx.wd_platforms.strip()
            flags.fields_from["platforms"] = "workflow_dispatch"
        if ctx.wd_load_mode.strip():
            flags.load_mode = ctx.wd_load_mode.strip()
            flags.fields_from["load_mode"] = "workflow_dispatch"

    # 4. Apply defaults for any fields still empty
    if not flags.layers:
        flags.layers = _DEFAULTS["layers"]
        flags.fields_from.setdefault("layers", "default")
    if not flags.platforms:
        flags.platforms = _DEFAULTS["platforms"]
        flags.fields_from.setdefault("platforms", "default")

    # 5. Resolve load_mode from trigger flags (text parse wins over wd default)
    if ctx.event_name != "workflow_dispatch" or not ctx.wd_load_mode.strip():
        if flags.has_gen_all:
            flags.load_mode = "genAll"
            flags.fields_from["load_mode"] = "title" if "title" in flags.flags_found_in else "description"
        elif flags.has_gen_quick:
            flags.load_mode = "genQuick"
            flags.fields_from["load_mode"] = "title" if "title" in flags.flags_found_in else "description"
        else:
            flags.load_mode = "gen"
            flags.fields_from.setdefault("load_mode", "default")

    return flags
