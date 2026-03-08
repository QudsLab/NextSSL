"""
logic/matrix.py
Pure dataclasses — no logic, no I/O.
ExecutionNode and ExecutionMatrix are the shared data contract between
resolver, validator, reporter, and reactor.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ExecutionNode:
    """Describes what should happen for one layer."""
    layer:    int   # 1, 2, 3 or 4
    active:   bool  # False = skip this layer's jobs entirely
    do_build: bool  # run --gen step for this layer
    do_test:  bool  # run --test step for this layer
    reason:   str   # human-readable explanation (e.g. "--loft 4 → test only")


@dataclass
class ExecutionMatrix:
    """The fully resolved execution plan for one run."""
    platforms:      list[str]
    load_mode:      str                      # "gen" | "genAll" | "genQuick"
    nodes:          dict[int, ExecutionNode] # key = layer number 1-4
    layer_selector: str                      # final -l value (active layers only)
    warnings:       list[str] = field(default_factory=list)
    errors:         list[str] = field(default_factory=list)

    # ── Convenience helpers ─────────────────────────────────────────────────

    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def active_layers(self) -> list[int]:
        return sorted(n.layer for n in self.nodes.values() if n.active)

    def github_output_dict(
        self,
        flags_loft: list[int] | None = None,
        flags_lofb: list[int] | None = None,
        flags_lntt: list[int] | None = None,
        flags_lntb: list[int] | None = None,
        flags_loc:  list[int] | None = None,
        flags_loe:  list[int] | None = None,
    ) -> dict[str, str]:
        """Return all key=value pairs to write to GITHUB_OUTPUT."""
        def _csv(lst: list[int] | None) -> str:
            return ",".join(str(x) for x in (lst or []))

        return {
            "layers":    ",".join(str(n) for n in self.active_layers()),
            "platforms": ",".join(self.platforms),
            "load_mode": self.load_mode,
            "loft":  _csv(flags_loft),
            "lofb":  _csv(flags_lofb),
            "lntt":  _csv(flags_lntt),
            "lntb":  _csv(flags_lntb),
            "loc":   _csv(flags_loc),
            "loe":   _csv(flags_loe),
        }
