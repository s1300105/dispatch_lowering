"""Binding-based callee resolution (§4.3 / §6.4 limitation fix).

The engine matches callees by the *name written at the call site*.  Real agent
code routinely binds a modelled callable to another name first, so the call
site's spelling differs from the model's pattern:

    completion = client.chat.completions.create   # bind
    response   = completion(messages=messages)     # call — spelled "completion"

    import subprocess as sp
    sp.run(cmd)                                    # call — receiver "sp"

A purely syntactic matcher misses both (the proposal's §6.4 alias limitation).
This module is the *principled* fix the proposal calls for: instead of matching
the surface syntax, we first resolve a name (or attribute chain) to the
**canonical fully-qualified callable(s)** it refers to, then match on that.

Resolution is *binding-based*, not full type inference (which the Pysa port
provides): we follow ``import`` / ``from ... import`` (incl. ``as`` aliases) and
simple ``name = <dotted-callable>`` assignments.  A name may have more than one
binding (e.g. assigned in both arms of an ``if``); we keep the **union** and let
a match succeed if *any* candidate matches — the recall-preserving,
over-approximate choice consistent with the rest of the analysis.

What is intentionally *not* resolved (correctly left dynamic): bindings whose
RHS is a call or subscript (``f = get_function(name)``, ``f = registry[name]``)
— those are runtime-chosen and handled by the dynamic-dispatch path.
"""

from __future__ import annotations

import ast
from typing import Dict, FrozenSet, List, Optional, Set


def _chain_segments(node: ast.AST) -> Optional[List[str]]:
    """Segments of a pure Name/Attribute chain, head first.

    ``client.chat.completions.create`` -> ``["client", "chat", "completions",
    "create"]``.  Returns ``None`` if the expression is not a pure name/attribute
    chain (e.g. it contains a call or subscript), so such callees stay dynamic.
    """
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


class AliasResolver:
    """A name -> {canonical dotted callable} map for one module."""

    def __init__(self) -> None:
        self.map: Dict[str, Set[str]] = {}

    # ---- building -------------------------------------------------------- #
    def _resolve_chain(self, segs: List[str]) -> Set[str]:
        """Resolve a chain by substituting its head through the current map."""
        head, rest = segs[0], segs[1:]
        bases = self.map.get(head, {head})
        suffix = ("." + ".".join(rest)) if rest else ""
        return {b + suffix for b in bases}

    def _add_import(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:                       # import a.b.c as x  -> x : a.b.c
                    self.map.setdefault(a.asname, set()).add(a.name)
                else:                              # import a.b.c       -> a : a (head usable)
                    top = a.name.split(".")[0]
                    self.map.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:                # relative import without module — skip
                return
            for a in node.names:
                if a.name == "*":
                    continue
                local = a.asname or a.name         # from a.b import f [as g] -> g : a.b.f
                self.map.setdefault(local, set()).add(f"{node.module}.{a.name}")

    def _add_assign(self, name: str, value: ast.AST) -> None:
        segs = _chain_segments(value)              # only pure name/attribute RHS
        if segs is None:                           # call/subscript RHS stays dynamic
            return
        self.map.setdefault(name, set()).update(self._resolve_chain(segs))

    @classmethod
    def from_module(cls, tree: ast.AST, passes: int = 2) -> "AliasResolver":
        """Build a module-wide union resolver.

        Imports and simple assignments are collected from *anywhere* in the
        module (a union over-approximation — recall-preserving).  A couple of
        passes let transitive aliases settle (``c = client.x; f = c.create``).
        """
        r = cls()
        imports: List[ast.AST] = []
        assigns: List[tuple] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(node)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        assigns.append((tgt.id, node.value))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                    and node.value is not None:
                assigns.append((node.target.id, node.value))
        for node in imports:
            r._add_import(node)
        for _ in range(max(1, passes)):
            for name, value in assigns:
                r._add_assign(name, value)
        return r

    # ---- querying -------------------------------------------------------- #
    def resolve_callee(self, func: ast.AST) -> FrozenSet[str]:
        """Canonical dotted callable(s) a call's ``func`` expression refers to.

        A bare unknown name resolves to itself (so ``eval(...)`` -> ``{"eval"}``);
        an unresolvable callee (call/subscript receiver) yields ``frozenset()``.
        """
        if isinstance(func, ast.Name):
            return frozenset(self.map.get(func.id, {func.id}))
        segs = _chain_segments(func)
        if segs is None:
            return frozenset()
        return frozenset(self._resolve_chain(segs))
