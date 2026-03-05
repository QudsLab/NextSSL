"""
script/logic — modular execution-control library for reactor.py.

Public API re-exported here so callers only need:
    from script.logic import parse, resolve, validate, print_report, ...
"""

from .registry  import LAYER_REGISTRY, expand, all_top_layers
from .parser    import RawContext, ParsedFlags, parse
from .matrix    import ExecutionNode, ExecutionMatrix
from .resolver  import resolve
from .validator import validate
from .reporter  import print_report, format_report

__all__ = [
    "LAYER_REGISTRY", "expand", "all_top_layers",
    "RawContext", "ParsedFlags", "parse",
    "ExecutionNode", "ExecutionMatrix",
    "resolve",
    "validate",
    "print_report", "format_report",
]
