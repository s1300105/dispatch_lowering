"""Static analysis: collection propagation, the two-layer taint engine, pruning."""

from __future__ import annotations

from .collections import Env, aggregate_read, insert_element, reducer_merge
from .dispatch_resolution import resolve_dispatch
from .taint_engine import Analyzer, analyze_source

__all__ = [
    "Env",
    "aggregate_read",
    "insert_element",
    "reducer_merge",
    "Analyzer",
    "analyze_source",
    "resolve_dispatch",
]
