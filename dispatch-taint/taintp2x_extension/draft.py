"""draft — turn the engine's view of cond_A into a reviewable lowering plan.

This is the step between "Pysa analysed the un-lowered tree" and "a human
decides what to lower". It joins:

  * ``engine_walls.scan``         where the unmodified engine loses taint (rows)
  * a derived recovery spec       which candidate-recovery keys the tree calls
                                  for (each key with its ``_provenance``)
  * a dry run of the pipeline     ``pipeline.run_spec(write=False)`` — the
                                  fan-out every accepted wall would get
                                  (lowered / filtered / unreasonable / phantom)

and writes one ``plan.json`` plus the review bundle (``walls.md``,
``spec.draft.json``, ``wall_files.txt``, ``candidates.draft.json``,
``links.draft.json``, ``env_report.json``, ``report.md``) and a read-only
``plan.draft.json`` — the untouched original the review edits are diffed
against (review C7; ``plan.json`` is the file the reviewer edits in place).
Every plan records ``tool_version`` (sha256 of the code and catalogue that
produced it, ``toolver.py``). Nothing under ``cond_A`` is modified.

The plan is what ``pipeline.run_plan`` consumes: one *group* per wall file,
each with a spec whose ``wall_positions`` pin the walls (``accept`` flags are
the review). The reviewer flips flags, prunes spec keys, adds analyst-pinned
``stages`` (a second hop) and re-runs.

Exit codes: 0 ok, 2 no surface (no wall rows), 4 no sources declared,
5 walls but none pre-accepted, 1 error.

    python3 draft.py <cond_A> [--src DIR] [--out DIR] [--catalog spec.presets.json]
                     [--preset NAME] [--include-proposed] [--no-dry-run]
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import json
import os
import re
import sys
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import anchoring as AN           # noqa: E402
import catalog as CAT            # noqa: E402
import dispatch_lowering as dl   # noqa: E402
import engine_walls as EW        # noqa: E402
import links as L                # noqa: E402
import pipeline                  # noqa: E402
import toolver                   # noqa: E402

# 2 (review C7 / M7 / draft minors): ``tool_version``; ``counts`` recomputed
# from the plan's groups after the dry run (engine values under
# ``engine_walls`` / ``engine_accepted``; ``accepted_by_tier`` added);
# ``dispatch_impl_map`` always written (possibly empty). Version-1 plans are
# still accepted by ``load_plan`` (upgraded in memory).
PLAN_VERSION = 2
PLAN_VERSIONS_READABLE = (1, 2)
EXIT = {"ok": 0, "no_surface": 2, "catalog_stale": 3, "no_sources": 4, "no_walls": 5}


def load_plan(path: str) -> dict:
    """Read a plan.json of any readable version. A version-1 plan gets the
    version-2 keys it lacks (``tool_version`` None, ``counts`` recomputed from
    its groups) so consumers need one code path."""
    plan = json.load(open(path))
    v = int(plan.get("version") or 1)
    if v not in PLAN_VERSIONS_READABLE:
        raise ValueError(f"{path}: plan version {v} not readable (known: {PLAN_VERSIONS_READABLE})")
    if v < 2:
        plan.setdefault("tool_version", None)
        c = dict(plan.get("counts") or {})
        if "engine_walls" not in c:
            c["engine_walls"], c["engine_accepted"] = c.get("walls"), c.get("accepted")
        plan["counts"] = c
        _recount(plan)
        plan["version_read"] = v
    return plan


def _recount(plan: dict) -> None:
    """``plan["counts"]`` from the groups as they stand (after anchoring joins,
    the dry run and fan-out demotion) — walls.md's header and the table must
    agree (review, draft minors). Engine-only values stay under
    ``engine_walls`` / ``engine_accepted``; ``accepted_by_tier`` is the tier
    distribution of the accepted walls (review M7: tiers are reported, never a
    gate — ``none`` includes anchor rows and walls behind another wall)."""
    rows = [r for g in plan.get("groups", []) for r in g.get("walls", [])]
    acc = [r for r in rows if r.get("accept")]
    c = plan.setdefault("counts", {})
    c["walls"] = len(rows)
    c["accepted"] = len(acc)
    c["by_status"] = dict(collections.Counter((r.get("engine_status") or "").split(":")[0] for r in rows))
    c["by_idiom"] = dict(collections.Counter(r.get("idiom", "") for r in rows))
    c["by_tier"] = dict(collections.Counter(r.get("engine_tier", "") for r in rows))
    c["by_origin"] = dict(collections.Counter((r.get("origin") or "").split(":")[0] for r in rows))
    c["accepted_by_tier"] = dict(collections.Counter(r.get("engine_tier", "") for r in acc))
    c["accepted_by_origin"] = dict(collections.Counter((r.get("origin") or "").split(":")[0] for r in acc))
    for g in plan.get("groups", []):
        g["accepted"] = sum(1 for r in g.get("walls", []) if r.get("accept"))

# decorator names that mark a registered tool / command / function in the
# frameworks seen so far; other in-repo decorators are listed for the reviewer
_TOOL_DECORATOR_RE = re.compile(r"(tool|command|function|register|action|skill|plugin|kernel_function|operation)s?$", re.I)
_NOT_TOOL_DECORATORS = {
    "property", "staticmethod", "classmethod", "abstractmethod", "overload", "cached_property",
    "override", "wraps", "dataclass", "field_validator", "model_validator", "root_validator",
    "validator", "contextmanager", "asynccontextmanager", "lru_cache", "cache", "retry",
    "deprecated", "experimental", "beta", "shielded", "message_handler", "fixture",
}


# --------------------------------------------------------------------------- #
# spec derivation
# --------------------------------------------------------------------------- #
# preset keys a draft may take from a preset, in the order they are looked up.
# review (draft minors): ``registry_vars`` and ``tool_decorators`` were
# missing, so the only preset carrying registry_vars (register_runtime) could
# not deliver them through --preset
_PRESET_KEYS = ("tool_decorators", "tool_base_classes", "tool_impl_methods", "register_methods",
                "tool_list_names", "tool_wrappers", "registry_vars", "wrapper_func_kwargs",
                "scan_all_callables", "candidate_module_root")


def derive_spec(res: EW.ScanResult, rows: List[EW.EngineWall], catalog: List[dict],
                preset: Optional[dict] = None, detected_preset: Optional[dict] = None,
                detected_frameworks: Optional[List[str]] = None) -> dict:
    """The candidate-recovery keys the accepted rows and the environment call
    for. Every key carries a ``_provenance`` line so the reviewer can prune
    with reason. Wall detection is never left to heuristics: ``wall_positions``
    pin the walls and every ``detect_*`` is false.

    Supplier order per key (review, draft minors): the tree's own evidence
    (decorator counts, accepted walls, catalogue hits), then the explicit
    ``--preset``, then the preset ``catalog.detect`` chose — an explicit
    preset always beats the detected one, and ``_provenance`` names which
    supplied each key. ``dispatch_impl_map`` (review M10 / K7) is built from
    the catalogue rows of the ACTIVE frameworks only — the imported ones plus
    the explicit / detected preset — and is written even when empty, so the
    lowering never falls back to ``DEFAULT_IMPL_MAP`` for a plan."""
    spec: dict = {"detect_subscript": False, "detect_getattr": False,
                  "detect_higher_order": False, "detect_boolop": False}
    prov: Dict[str, str] = {"detect_*": "false — walls are pinned by wall_positions (draft never lets detection run)"}
    env = res.env

    decs, decs_other = [], []
    for d in env.get("decorators_in_repo", []):
        last = d["decorator"].rsplit(".", 1)[-1]
        if last in _NOT_TOOL_DECORATORS or last.startswith(("trace_", "_")):
            decs_other.append(d)
        elif _TOOL_DECORATOR_RE.search(last):
            decs.append((last, d))
        else:
            decs_other.append(d)
    dec_src = "decorator-counts.json (in-repo)"
    for p, how in ((preset, "--preset"), (detected_preset, "detected by catalog.detect")):
        if p and p.get("tool_decorators"):
            for name in p["tool_decorators"]:
                if name not in [n for n, _ in decs]:
                    decs.append((name, {"decorator": f"preset:{name}", "count": 0}))
                    dec_src += f" + preset {p.get('_name', '')} ({how})"
    if decs:
        spec["tool_decorators"] = sorted({n for n, _ in decs})
        prov["tool_decorators"] = dec_src + ": " + ", ".join(
            f"{d['decorator']} x{d['count']}" for _, d in decs)

    regs, method_names, attr_names, hints = set(), set(), set(), set()
    for w in rows:
        if not w.accept:
            continue
        if w.idiom == "subscript" and w.resolver and re.match(r"^[A-Za-z_]\w*$", w.resolver):
            regs.add(w.resolver)
        if w.idiom == "method_call" and w.callee and "." in w.callee:
            method_names.add(w.callee.rsplit(".", 1)[-1])
        if w.idiom == "attr_call" and w.key_expr:
            attr_names.add(w.key_expr)
        if w.idiom == "higher_order" and w.resolver:
            hints.add(w.resolver.rsplit(".", 1)[-1])
    if regs:
        spec["registry_vars"] = sorted(regs)
        prov["registry_vars"] = "bare-name registries read by accepted subscript walls (also narrows when the dict literal is trusted)"
    if method_names:
        spec["wall_method_names"] = sorted(method_names)
        prov["wall_method_names"] = "method names of accepted method_call walls (informational under wall_positions)"
    if attr_names:
        spec["wall_attr_names"] = sorted(attr_names)
        prov["wall_attr_names"] = "attribute names of accepted attr_call walls (informational under wall_positions)"
    if hints:
        prov["resolver_hints"] = "NOT set (positions are pinned); resolvers seen: " + ", ".join(sorted(hints))

    bases, impls = set(), set()
    for api in (env.get("catalog_hits") or {}):
        row = next((r for r in catalog if r["api"] == api), None)
        if not row:
            continue
        # the candidate base class is the row's ``base`` (ToolCollection.execute
        # dispatches to BaseTool subclasses), else the API's own class
        bases.add(row.get("base") or api.rsplit(".", 1)[0].rsplit(".", 1)[-1])
        impls.update(row.get("impl") or [])
    if bases and impls:
        spec["tool_base_classes"] = sorted(bases)
        spec["tool_impl_methods"] = sorted(impls)
        prov["tool_base_classes"] = "catalogue rows hit: " + ", ".join(sorted(env.get("catalog_hits") or {}))
        prov["tool_impl_methods"] = prov["tool_base_classes"]
    # presets supply the recovery keys the tree did not reveal by itself
    # (base classes, register methods, wrappers, registry names): the explicit
    # --preset first, the detected preset only for keys still unset
    for p, how in ((preset, "--preset"), (detected_preset, "detected by catalog.detect")):
        if not p:
            continue
        for key in _PRESET_KEYS:
            if key in p and key not in spec:
                v = p[key]
                spec[key] = list(v) if isinstance(v, (list, tuple)) else v
                prov[key] = f"preset {p.get('_name', '')} ({how})"
    # dispatch_impl_map (review M10 / K7): rows of the ACTIVE frameworks only —
    # a merged map would let OpenManus's ``__call__ -> execute`` licence
    # candidates in a SuperAGI tree. Active = frameworks the tree imports +
    # the explicit / detected preset. No active framework -> an empty map,
    # written explicitly so the lowering does not fall back to its built-in one.
    fws = {r.get("framework") for r in catalog}
    active = set(detected_frameworks or []) & fws
    for p in (preset, detected_preset):
        if p and p.get("_name") in fws:
            active.add(p["_name"])
    # review M10 (repair): ONE fold, shared with catalog.impl_map_stale — the
    # aggregate's offline check that a published plan carries this map and
    # not a pre-fix (merged / missing) one
    spec["dispatch_impl_map"] = CAT.impl_map_for(catalog, active)
    prov["dispatch_impl_map"] = ("catalogue dispatch rows of " + ", ".join(sorted(active)) +
                                 ": a `x.m(..)` wall accepts class-method candidates named m or its impl methods only"
                                 if active else
                                 "empty — no framework detected / preset given, so no catalogue row applies "
                                 "(a `x.m(..)` wall accepts class-method candidates named m only)")
    spec["_provenance"] = prov
    spec["_decorators_not_used"] = [d["decorator"] for d in decs_other]
    return spec


# --------------------------------------------------------------------------- #
# plan construction
# --------------------------------------------------------------------------- #
FANOUT_MAX = 16     # more lowered targets than this without narrowing -> the row is demoted to proposed
                    # (level-2 candidates are the registered tool set: bounded; 13 tools in
                    # LangChain is the honest fan-out, 48 @kernel_function is not)


# S2 receiver evidence read off call-graph.json (review C5 / K3): engine_walls
# fills them, the draft only carries them through (never depended on here)
_S2_FIELDS = ("receiver_class", "target_form", "s2_reason")


def _s2(w: EW.EngineWall) -> dict:
    return {k: getattr(w, k, "") or "" for k in _S2_FIELDS}


def _unlowerable(w: EW.EngineWall) -> bool:
    """Review C5 policy: an S2 wall the engine resolved to an ABSTRACT stub
    (``@abstractmethod`` / raises NotImplementedError) with no in-tree
    implementation reachable from the receiver's static type — a wall whose
    candidate set is empty BY CONSTRUCTION (``resolved_stub``, no dispatch
    target, ``s2_reason == receiver_subclass_no_overrides``).

    Review C5 policy (repair) — the rule's boundary: a ``resolved_stub`` row
    with no dispatch target but ``s2_reason == receiver_unknown`` (a
    ``typing.Protocol`` / untyped receiver: the engine has no override row for
    it by construction) is NOT unlowerable — its candidates come from the
    draft's recovery (decorators / anchors), as for an S1 wall, so it stays
    pre-accepted; when the recovery finds nothing the row gets the
    ``no_candidates`` hint and, left in cond_B, counts in
    ``residual_confirmed`` (sk_real ``self.definition.deserialize``;
    test_receiver_unknown_stub_policy)."""
    return (w.engine_status == "resolved_stub" and not w.dispatch_targets
            and (getattr(w, "s2_reason", "") or "") == "receiver_subclass_no_overrides")


def _entry(w: EW.EngineWall, anchored: Optional[tuple] = None) -> dict:
    e = {"at": f"{w.file}:{w.line}:{w.col}", "end": f"{w.end_line}:{w.end_col}",
         "callee": w.callee, "accept": bool(w.accept), "origin": w.origin,
         "engine_status": w.engine_status, "engine_reason": w.engine_reason,
         "engine_tier": w.engine_tier, "confidence": w.confidence, "id": w.id, **_s2(w)}
    if w.idiom == "boolop" and w.members:
        # the BoolOp names its own destination set (explicit-Intent case): keep
        # the level-1 member candidates only; the reviewer raises the cap when
        # the open alternative (a parameter / a call) matters
        e["match_level"] = 1
    if anchored:
        a, r = anchored
        closed = bool(getattr(r, "anchor_closed", a.closed))   # review C6: per-read closedness
        e["anchor"] = a.name
        e["anchor_members"] = list(r.candidates)
        e["anchor_closed"] = closed
        e["anchor_binding"] = getattr(r, "binding", "exact")
        if closed and r.candidates:
            e["match_level"] = 1
    elif w.engine_status == "resolved_stub" and w.dispatch_targets:
        # overrides of the stub method from Pysa's override-graph.json: the
        # engine's own destination set (closed by construction)
        members = []
        for q in w.dispatch_targets:
            mod_cls, meth = q.rsplit(".", 1)
            if "." not in mod_cls:
                continue
            mod, cls = mod_cls.rsplit(".", 1)
            members.append({"cls": cls, "name": meth, "module": mod, "origin": "anchor", "match_level": 1,
                            "evidence": f"override of {w.engine_targets[0] if w.engine_targets else meth} (override-graph.json)"})
        if members:
            e["anchor"] = f"overrides:{w.engine_targets[0] if w.engine_targets else ''}"
            e["anchor_members"] = members
            e["anchor_closed"] = True
            e["match_level"] = 1
    return e


def _row(w: EW.EngineWall) -> dict:
    return {"id": w.id, "position": w.position, "file": w.file, "line": w.line, "col": w.col,
            "callee": w.callee, "idiom": w.idiom, "resolver": w.resolver, "key_expr": w.key_expr,
            "receiver_binding": w.receiver_binding, "members": w.members, "members_open": w.members_open,
            "engine_status": w.engine_status, "engine_reason": w.engine_reason,
            "engine_targets": w.engine_targets, "dispatch_targets": w.dispatch_targets,
            "engine_tier": w.engine_tier, "origin": w.origin, "confidence": w.confidence,
            "accept": bool(w.accept), "note": w.note, "callable": w.callable,
            "stmt_kind": w.stmt_kind, "in_async": w.in_async, "taint_args": w.taint_args, **_s2(w)}


def build_plan(cond_dir: str, src_root: str = "", catalog_path: str = "", preset: Optional[dict] = None,
               include_proposed: bool = False, dry_run: bool = True, use_anchoring: bool = True,
               reject_anchors=(), disable=()) -> dict:
    """``disable``: leave-one-out axes — any of S1, S2, S3 (engine classes) and
    ``anchoring``; recorded in the plan so a row.json can name the ablation."""
    disable = [d for d in disable if d]
    if "anchoring" in disable:
        use_anchoring = False
    res = EW.scan(cond_dir, src_root=src_root, catalog_path=catalog_path,
                  disable=[d for d in disable if d.upper() in ("S1", "S2", "S3")])
    # catalogue: which frameworks the tree uses, and whether their dispatch APIs exist
    presets = CAT.load(catalog_path or CAT.DEFAULT_PATH)
    # the presets file is the one source of dispatch rows (K7); the engine's
    # built-in rows only when there is no presets file at all
    catalog = CAT.dispatch_rows(presets) or EW.load_catalog(catalog_path)
    run_src = res.env["src_root"]
    rows = list(res.walls)
    if include_proposed:
        for w in rows:
            if w.confidence == "proposed" and w.aligned:
                w.accept = True
    anch = AN.anchoring(run_src, engine=res, reject=reject_anchors) if use_anchoring else None
    anchor_of: Dict[str, tuple] = {}
    if anch is not None:
        rows = _apply_anchors(rows, anch, anchor_of)
    # review C5 policy: an unlowerable S2 wall (destination set empty by
    # construction — receiver_subclass_no_overrides, see _unlowerable) has
    # nothing to link — it is never accepted (``--include-proposed``
    # included), unless an anchor read supplied members for it; the note
    # names the missing implementation. A receiver_unknown S2 row with no
    # engine target is NOT forced off: its candidates come from the recovery
    for w in rows:
        a_r = anchor_of.get(w.id)
        if _unlowerable(w) and not (a_r and a_r[1].candidates):
            w.accept, w.confidence = False, "proposed"
            if "unlowerable" not in (w.note or ""):
                w.note = (w.note + "; " if w.note else "") + (w.engine_reason or "unlowerable: no in-tree implementation")
    detected = CAT.detect(run_src, presets)
    # review M4: import / discriminating base-class evidence only — a preset
    # matched by a decorator name alone never seeds the spec
    top = CAT.top_preset(detected)
    detected["top"] = top or None
    # review M4 (repair): the framework the draft is ATTRIBUTED to in tables —
    # the seeding preset only above catalog.FW_MIN_SCORE (match.min_score);
    # summary.md / row.json recompute it with the same catalog.framework_of
    detected["framework"] = CAT.framework_of(detected, presets)
    detected_preset = dict(presets[top], _name=top) if top else None
    imported = [n for n in detected["detected"] if detected["scores"][n].get("imports")]
    base_spec = derive_spec(res, rows, catalog, preset, detected_preset, imported)

    groups = []
    by_file: Dict[str, List[EW.EngineWall]] = collections.OrderedDict()
    for w in sorted(rows, key=lambda x: (x.file, x.line, x.col)):
        by_file.setdefault(w.file, []).append(w)
    for gi, (file, ws) in enumerate(by_file.items()):
        spec = {k: v for k, v in base_spec.items()}
        spec["wall_positions"] = [_entry(w, anchor_of.get(w.id)) for w in ws]
        spec["wall_files"] = [file]
        groups.append({"id": f"G{gi}", "wall_files": [file], "spec": spec,
                       "walls": [_row(w) for w in ws], "stages": None,
                       "accepted": sum(1 for w in ws if w.accept)})

    env = dict(res.env)
    # S2 receiver evidence per stub wall (review C5 / K3) for env_report.json
    s2 = [{"position": w.position, "engine_targets": list(w.engine_targets), **_s2(w)}
          for w in rows if w.engine_status in ("resolved_stub", "resolved_obscure") and any(_s2(w).values())]
    if s2:
        env["s2_receivers"] = s2
    counts = dict(res.counts)
    counts["engine_walls"], counts["engine_accepted"] = counts.get("walls"), counts.get("accepted")
    plan = {
        "version": PLAN_VERSION,
        "created": _dt.datetime.now().isoformat(timespec="seconds"),
        "tool_version": toolver.tool_version(),
        "target": {"cond_dir": res.env["cond_dir"], "src_root": run_src,
                   "pysa_version": res.env.get("pysa_version", "")},
        "outcome": res.env.get("outcome"),
        "counts": counts,
        "groups": groups,
        "env": env,
        "candidates": {},
        "anchors": (anch.to_dict() if anch is not None else {"disabled": True}),
        "catalog": detected,
        "ablation": {"disabled": list(disable)},
        "hints": [],
        "review": {"minutes": None, "notes": ""},
    }
    if dry_run:
        _dry_run(plan, run_src, res)
    _recount(plan)
    _hints(plan, res)
    # no accepted wall at all: is the catalogue stale (framework present, its
    # dispatch API names absent from the tree) or is there simply no surface?
    if plan["outcome"] in ("ok", "no_walls", "no_surface") and not any(g["accepted"] for g in plan["groups"]):
        # review M4: catalog_status = in-repo presence; the venv-inclusive view
        # lets stale() name the rows found on the analysis search path only
        stale = CAT.stale(detected, res.env.get("catalog_status") or {},
                          catalog_status_search_path=res.env.get("catalog_status_search_path") or {})
        plan["outcome"] = "catalog_stale" if stale else ("no_surface" if not plan["groups"] else "no_walls")
        if stale:
            plan["hints"].append({"kind": "catalog", "text": "catalogue stale: " + "; ".join(stale)})
    return plan


def _apply_anchors(rows: List[EW.EngineWall], anch: "AN.AnchoringResult", anchor_of: Dict[str, tuple]) -> List[EW.EngineWall]:
    """Join anchor reads with the engine rows: an anchored engine row gets the
    anchor's members as level-1 candidates (and narrowing when closed) and a
    deferred idiom (loop / param) is promoted; a read the engine did not flag
    becomes a proposed row of origin ``anchor:<name>``."""
    by_pos = {(w.file, w.line, w.col): w for w in rows}
    out = list(rows)
    next_id = len(rows)
    for (file, line, col), (a, r) in anch.by_position.items():
        w = by_pos.get((file, line, col))
        if w is not None:
            anchor_of[w.id] = (a, r)
            # review C6: an inherited read (a subclass reading a base-assigned
            # attribute) carries candidates but is never closed — narrowing and
            # promotion key on the per-read flag, not on the anchor's own state
            closed = bool(getattr(r, "anchor_closed", a.closed))
            tag = f"anchor:{a.name}({'closed' if closed else 'open'}, {len(r.candidates)} members, {getattr(r, 'binding', 'exact')})"
            w.note = (w.note + "; " if w.note else "") + tag
            if not w.accept and w.idiom in ("loop_call", "param_call", "method_call") and closed and r.candidates \
                    and (w.engine_status.startswith("unresolved:") or w.engine_status in ("resolved_stub", "resolved_obscure")):
                w.accept, w.confidence = True, "confirmed"
                w.note += "; promoted by the anchor's members"
            continue
        # a read the engine did not list (resolved by types, or no site)
        nw = EW.EngineWall(id=f"A{next_id}", file=file, line=line, col=col, end_line=r.end_line, end_col=r.end_col,
                           callable=r.callable, callee=r.callee, idiom=r.idiom, resolver=a.name, key_expr=r.key_expr,
                           engine_status=r.engine_status or "no_site", engine_reason="anchor read",
                           engine_tier="none", origin=f"anchor:{a.name}", confidence=r.confidence,
                           accept=r.accept, note=r.note, aligned=True, callable_match=True)
        next_id += 1
        anchor_of[nw.id] = (a, r)
        out.append(nw)
    return out


def _wall_file_key(file: str, src_root: str, wall_files: List[str]) -> str:
    """The wall-file identity used to join dry-run records with plan rows
    (review C1 / K1): the path relative to ``src_root`` with POSIX separators.
    An absolute path is made relative; a bare basename (a links.py that still
    reports basenames) is resolved against the group's wall files, which is
    unambiguous because a group holds exactly one wall file."""
    f = (file or "").replace("\\", "/")
    if os.path.isabs(f):
        f = os.path.relpath(f, src_root).replace(os.sep, "/")
    if "/" not in f:
        hits = [wf for wf in wall_files if os.path.basename(wf) == f]
        if len(hits) == 1:
            f = hits[0].replace("\\", "/")
    return f


def _run_group(g: dict, src_root: str) -> "pipeline.PipelineResult":
    """One group's dry run; ids are group-prefixed (``G0W0``) as in
    ``run_plan``, so ``plan["dry_run"]`` never holds two ``W0`` records."""
    spec = dict(g["spec"])
    wall_paths = [os.path.join(src_root, f) for f in g["wall_files"]]
    return pipeline.run_spec(src_root, spec, wall_paths, cand_dir=src_root, emit="redirector", write=False,
                             id_prefix=g.get("id", ""))


def _fill_rows(g: dict, r: "pipeline.PipelineResult", src_root: str, keep: Optional[set] = None) -> None:
    """``row["dry_run"]`` for every row of the group from a pipeline result.
    Rows are joined by (relative file, line, col) — two walls on one line
    (litellm weights_biases.py:72, vanna base.py:1685) are two records
    (review C1). A record without a column (an unmatched pin) still joins when
    it is the only record on that line. Rows in ``keep`` are left as they are."""
    keep = keep or set()
    by_wall = collections.defaultdict(list)
    for l in r.links:
        by_wall[l.wall_id].append(l)
    recs: Dict[tuple, L.WallRecord] = {}
    by_line: Dict[tuple, List[L.WallRecord]] = collections.defaultdict(list)
    for w in r.walls:
        key = _wall_file_key(w.file, src_root, g["wall_files"])
        recs[(key, w.line, w.col)] = w
        by_line[(key, w.line)].append(w)
    for row in g["walls"]:
        if row["id"] in keep:
            continue
        rk = _wall_file_key(row["file"], src_root, g["wall_files"])
        w = recs.get((rk, row["line"], row["col"]))
        if w is None and len(by_line.get((rk, row["line"]), [])) == 1 and not by_line[(rk, row["line"])][0].col:
            w = by_line[(rk, row["line"])][0]
        if w is None:
            row["dry_run"] = {"status": "not_detected"}
            continue
        ls = by_wall.get(w.id, [])
        cnt = collections.Counter(l.status for l in ls)
        row["dry_run"] = {
            "status": w.status, "reason": w.reason, "wall_id": w.id,
            "links": len(ls), "lowered": cnt.get("lowered", 0),
            "filtered_registry": cnt.get("filtered_registry", 0),
            "filtered_level": cnt.get("filtered_level", 0),
            "unreasonable": cnt.get("unreasonable", 0),
            "no_args": cnt.get("no_args", 0), "phantom": cnt.get("phantom", 0),
            "members": w.members,
            "targets": [{"target": f"{l.target.module}.{l.target.qualname}".strip("."),
                         "status": l.status, "level": l.match_level, "origin": l.target.origin,
                         "evidence": l.target.evidence, "args": l.args_for(w), "reason": l.reason}
                        for l in ls],
        }


def _demote_fanout(g: dict) -> set:
    """Demote rows whose fan-out is unbounded: nothing narrowed them and the
    engine could not either — accepting them unattended would flood cond_B
    with speculative edges. The reviewer flips them back. Returns the ids of
    the demoted rows."""
    demoted = set()
    impl_keys = set((g["spec"].get("dispatch_impl_map") or {}).keys())
    for row, entry in zip(g["walls"], g["spec"]["wall_positions"]):
        dr = row.get("dry_run") or {}
        if not row["accept"] or "links" not in dr:
            continue
        level1 = any(t["level"] == 1 and t["status"] == "lowered" for t in dr["targets"])
        # a method wall whose attribute is a catalogue dispatch API is
        # bounded by the method-name filter: its fan-out IS the registered
        # tool set (13 LangChain tools, 36 SuperAGI tools), not speculation
        attr = row["callee"].rsplit(".", 1)[-1] if "." in row["callee"] else ""
        bounded = row["idiom"] in ("method_call", "attr_call") and attr in impl_keys
        if dr["lowered"] > FANOUT_MAX and not level1 and not bounded:
            row["accept"] = entry["accept"] = False
            row["confidence"] = entry["confidence"] = "proposed"
            row["note"] = (row.get("note") or "") + f"; fan-out {dr['lowered']} without narrowing — off until pruned / anchored"
            dr["demoted"] = True
            demoted.add(row["id"])
    return demoted


def _dry_run(plan: dict, src_root: str, res: Optional[EW.ScanResult] = None) -> None:
    """Run the pipeline without writing: every accepted wall gets its fan-out,
    every rejected wall its ``rejected_by_review`` row. Redirector emission is
    used because it is the stricter one (a target without a module is a
    phantom there).

    A group with a FANOUT_MAX demotion is dry-run a second time with the
    demoted rows off, so ``plan["dry_run"]`` / ``links.draft.json`` and the
    stats hold only the links the plan will actually lower (review, draft
    minors: 778 lowered in the stats vs 22 on the accepted rows). The demoted
    row keeps its first-pass fan-out (``dry_run.demoted``) for the reviewer.
    ``candidates_total`` is the maximum over groups, as in ``run_plan`` — the
    same tree is scanned once per group, not once per wall file."""
    all_walls, all_links = [], []
    stats = L.LoweringStats()
    max_cands = 0
    for g in plan["groups"]:
        if not g["accepted"]:
            continue
        try:
            r = _run_group(g, src_root)
        except Exception as e:      # the draft must still be written
            g["dry_run_error"] = f"{type(e).__name__}: {e}"
            continue
        _fill_rows(g, r, src_root)
        demoted = _demote_fanout(g)
        if demoted:
            try:
                r = _run_group(g, src_root)
            except Exception as e:
                g["dry_run_error"] = f"{type(e).__name__}: {e}"
                continue
            _fill_rows(g, r, src_root, keep=demoted)
        stats = stats.merge(r.stats)
        max_cands = max(max_cands, r.stats.candidates_total)
        all_walls += r.walls
        all_links += r.links
        g["dry_run"] = {"provider": r.provider, "stats": r.stats.to_dict(), "demoted": sorted(demoted)}
        g["accepted"] = sum(1 for r in g["walls"] if r["accept"])
    stats.candidates_total = max_cands
    plan["dry_run"] = {"stats": stats.to_dict(), "walls": [L.asdict(w) for w in all_walls],
                       "links": [L.asdict(l) for l in all_links]}
    # candidate recovery diagnostics (the target-wide spec, once) — through
    # the provider's memoised scans, which the groups above already paid for
    if plan["groups"]:
        try:
            spec0 = {k: v for k, v in plan["groups"][0]["spec"].items() if k not in ("wall_positions", "wall_files")}
            prov = pipeline.AutoLinksProvider(src_root, spec0, [])
            cands = prov.candidates()
            desc = prov.describe()
            plan["candidates"] = {
                "total": len(cands),
                "by_origin": dict(collections.Counter(c.origin for c in cands)),
                "recovery": desc.get("recovery") or ({"recovery_error": desc["recovery_error"]}
                                                     if desc.get("recovery_error") else {}),
                "list": [{"qualname": c.qualname, "module": c.module, "origin": c.origin,
                          "level": c.match_level, "path": os.path.relpath(c.path, src_root) if c.path else "",
                          "line": c.lineno, "decorated": c.decorated} for c in cands],
            }
        except Exception as e:
            plan["candidates"] = {"error": f"{type(e).__name__}: {e}"}


def _hints(plan: dict, res: EW.ScanResult) -> None:
    hints = plan["hints"]
    # walls inside a lowered target = a possible second hop (never automated)
    walls_by_callable = collections.defaultdict(list)
    for w in res.walls:
        walls_by_callable[w.callable].append(w)
    for g in plan["groups"]:
        for row in g["walls"]:
            dr = row.get("dry_run") or {}
            for t in dr.get("targets", []):
                if t["status"] != "lowered":
                    continue
                inner = walls_by_callable.get(t["target"])
                if inner:
                    hints.append({"kind": "stage2", "wall": row["position"], "target": t["target"],
                                  "walls_in_target": [x.position for x in inner],
                                  "text": f"{t['target']} (lowered from {row['position']}) itself contains "
                                          f"{len(inner)} engine wall(s): a second stage may be needed"})
            if row["accept"] and dr.get("links", 0) == 0 and dr.get("status") not in ("rejected_by_review",):
                hints.append({"kind": "no_candidates", "wall": row["position"],
                              "text": f"{row['position']}: no candidate at all — add a preset / registry_vars / "
                                      f"scan_all_callables, or pin candidates explicitly"})
            if dr.get("phantom"):
                hints.append({"kind": "phantom", "wall": row["position"],
                              "text": f"{row['position']}: {dr['phantom']} phantom link(s) — target module unknown or "
                                      f"nested def; set candidate_import_module or pin the link"})
            if row["accept"] and dr.get("lowered", 0) > 8:
                hints.append({"kind": "fan_out", "wall": row["position"],
                              "text": f"{row['position']}: fans out to {dr['lowered']} targets — consider "
                                      f"registry narrowing or match_level"})
            # review C5 policy: an unlowerable abstract stub stays a proposed
            # row with no candidate — the reviewer sees why it will stay residual
            if not row["accept"] and row.get("engine_status") == "resolved_stub" and not row.get("dispatch_targets") \
                    and row.get("s2_reason") == "receiver_subclass_no_overrides":
                hints.append({"kind": "unlowerable", "wall": row["position"],
                              "text": f"{row['position']}: {row.get('note') or 'unlowerable abstract stub'} — "
                                      f"no candidate to link; stays a residual wall (residual_unlowerable)"})
    e = plan["env"]
    if e.get("env_gaps_by_reason", {}).get("CannotResolveExports"):
        hints.append({"kind": "env", "text": f"{e['env_gaps_by_reason']['CannotResolveExports']} unresolved imports "
                                             f"(CannotResolveExports): see env_report.json env_gap_rows"})
    if e.get("model_verification_errors"):
        hints.append({"kind": "env", "text": f"{e['model_verification_errors']} model verification errors "
                                             f"(taint-metadata.json)"})


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render_walls_md(plan: dict) -> str:
    out = [f"# Wall review — {os.path.basename(plan['target']['cond_dir'])}", "",
           f"outcome: **{plan['outcome']}** — {plan['counts']}", "",
           "Flip `accept` in plan.json (or edit this table and re-import is NOT supported: plan.json is the source of truth).",
           "confirmed rows are pre-accepted; proposed rows are off.", "",
           "| # | position | callee | idiom | resolver[key] | engine | tier | origin | conf | fan-out (lowered/filtered/unreasonable/phantom) | accept | note |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for g in plan["groups"]:
        for r in g["walls"]:
            rk = r["resolver"] + (f"[{r['key_expr']}]" if r["key_expr"] else "")
            if r["members"]:
                rk = " or ".join(r["members"]) + (" (open)" if r["members_open"] else "")
            dr = r.get("dry_run") or {}
            fan = "-" if not dr or "links" not in dr else (
                f"{dr['lowered']}/{dr['filtered_registry'] + dr['filtered_level']}/{dr['unreasonable']}/{dr['phantom']}")
            eng = r["engine_status"] + (" -> " + ", ".join(r["dispatch_targets"][:2]) if r["dispatch_targets"] else "")
            out.append(f"| {r['id']} | `{r['position']}` | `{r['callee']}` | {r['idiom']} | `{rk}` | {eng} | "
                       f"{r['engine_tier']} | {r['origin']} | {r['confidence']} | {fan} | "
                       f"{'x' if r['accept'] else ' '} | {r['note']} |")
    if plan["hints"]:
        out += ["", "## hints", ""] + [f"- {h['text']}" for h in plan["hints"]]
    return "\n".join(out) + "\n"


def render_report_md(plan: dict) -> str:
    e = plan["env"]
    tv = plan.get("tool_version") or {}
    c = plan["counts"]
    out = [f"# Draft report — {plan['target']['cond_dir']}", "",
           f"- outcome: **{plan['outcome']}** (exit {EXIT.get(plan['outcome'], 1)})",
           f"- plan version {plan.get('version')}, created {plan.get('created', '')}, tool_version "
           f"{(tv.get('combined') or 'n/a')[:12]} (sha256 of the code + catalogue, toolver.py)",
           f"- pysa {e.get('pysa_version', '')[:7]}; in-repo files {e.get('files_in_repo')}, callables {e.get('callables_in_repo')}, "
           f"call sites {e.get('sites_in_repo')}, unresolved {e.get('unresolved_in_repo')} {e.get('unresolved_by_reason')}",
           f"- walls {c.get('walls')} (accepted {c.get('accepted')}; engine alone {c.get('engine_walls')} / "
           f"{c.get('engine_accepted')}), accepted by tier {c.get('accepted_by_tier')}, env gaps {e.get('env_gaps')} {e.get('env_gaps_by_reason')}",
           f"- source models {e.get('source_models')} (in-repo {e.get('source_models_in_repo')}); callables carrying source taint {e.get('callables_with_source_taint_in_repo')}",
           f"- catalogue hits {e.get('catalog_hits')}", ""]
    for g in plan["groups"]:
        out.append(f"## {g['id']}  {', '.join(g['wall_files'])}  — {g['accepted']}/{len(g['walls'])} accepted")
        sp = g["spec"]
        for k, v in sp.items():
            if k.startswith("_") or k in ("wall_positions", "wall_files"):
                continue
            out.append(f"- `{k}`: `{json.dumps(v)}` — {sp.get('_provenance', {}).get(k, '')}")
        if sp.get("_provenance", {}).get("resolver_hints"):
            out.append(f"- resolver_hints: {sp['_provenance']['resolver_hints']}")
        if sp.get("_decorators_not_used"):
            out.append(f"- in-repo decorators NOT used as tool markers: {sp['_decorators_not_used'][:10]}")
        if g.get("dry_run_error"):
            out.append(f"- dry run failed: {g['dry_run_error']}")
        for r in g["walls"]:
            dr = r.get("dry_run") or {}
            if not r["accept"] and not dr:
                continue
            out.append(f"  - {r['position']} `{r['callee']}` {r['engine_status']} {r['engine_tier']} accept={r['accept']}"
                       + (f" → {dr.get('status')} lowered {dr.get('lowered', 0)}/{dr.get('links', 0)}" if dr else ""))
            for t in dr.get("targets", []):
                out.append(f"      - {t['status']:18s} L{t['level']} {t['target']}({', '.join(t['args'])})"
                           + (f" — {t['reason']}" if t['reason'] else "") + (f" [{t['evidence']}]" if t['evidence'] else ""))
        out.append("")
    an = plan.get("anchors") or {}
    if an and not an.get("disabled"):
        out.append(f"## anchors: {an['counts']}")
        for x in an.get("anchors", [])[:40]:
            if not x["reads"] and not x["closed"]:
                continue
            out.append(f"- `{x['name']}` [{x['kind']}, {'REJECTED' if x['rejected'] else 'closed' if x['closed'] else 'open'}] "
                       f"{x['file']}:{x['line']} members={len(x['members'])} reads={len(x['reads'])}"
                       + (f" — open: {x['open_reasons'][0]}" if x['open_reasons'] else ""))
        out.append("")
    cat = plan.get("catalog") or {}
    if cat:
        # review M4: catalogue presence has two views (engine_walls.scan) — rows
        # defined in an IN-REPO callable (what catalog.stale reads) and rows found
        # anywhere on the analysis search path (venv included)
        env_ = plan.get("env") or {}
        in_repo = sorted(k for k, v in (env_.get("catalog_status") or {}).items() if v == "present")
        on_path = sorted(k for k, v in (env_.get("catalog_status_search_path") or {}).items() if v == "present")
        out.append(f"## catalogue: frameworks detected {cat.get('detected')} (seeding preset: {cat.get('top') or '(none)'}; "
                   f"attributed framework: {cat.get('framework') or CAT.framework_of(cat, CAT.load())}); "
                   f"dispatch rows defined in the tree {in_repo}; on the analysis search path (venv included) {on_path}")
        out.append("")
    c = plan.get("candidates") or {}
    if c:
        out.append(f"## candidates: {c.get('total')} {c.get('by_origin')}")
        rec = c.get("recovery") or {}
        if rec.get("unresolved_refs"):
            out.append(f"- unresolved registration refs (gap in R): {rec['unresolved_refs']}")
        out.append("")
    if plan["hints"]:
        out += ["## hints"] + [f"- {h['text']}" for h in plan["hints"]] + [""]
    out += ["## next", "",
            "```bash", "# review plan.json (accept flags, spec keys), then:",
            f"PLAN_JSON={os.path.join('<draft>', 'plan.json')} ./run_ablation.sh", "```"]
    return "\n".join(out) + "\n"


def _write_readonly_json(path: str, data: dict) -> None:
    """Write ``data`` to ``path`` and leave it mode 0444. A previous read-only
    copy (a re-draft into the same directory) is replaced, not appended to."""
    if os.path.exists(path):
        os.chmod(path, 0o644)
        os.remove(path)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(path, 0o444)


def write_bundle(plan: dict, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    # review C7 / K4: the plan names the code + catalogue that produced it
    plan.setdefault("tool_version", toolver.tool_version())
    json.dump(plan, open(os.path.join(out_dir, "plan.json"), "w"), indent=2, ensure_ascii=False)
    # review C7: the untouched original, read-only. plan.json is edited in
    # place by the review, so ``review_edits`` (accept flips, spec edits) must
    # be diffed against THIS file, never against plan.json itself
    _write_readonly_json(os.path.join(out_dir, "plan.draft.json"), plan)
    open(os.path.join(out_dir, "walls.md"), "w").write(render_walls_md(plan))
    open(os.path.join(out_dir, "report.md"), "w").write(render_report_md(plan))
    json.dump(plan["env"], open(os.path.join(out_dir, "env_report.json"), "w"), indent=2)
    specs = {g["id"]: g["spec"] for g in plan["groups"]}
    json.dump(specs if len(specs) != 1 else next(iter(specs.values())),
              open(os.path.join(out_dir, "spec.draft.json"), "w"), indent=2)
    files = sorted({f for g in plan["groups"] if g["accepted"] for f in g["wall_files"]})
    open(os.path.join(out_dir, "wall_files.txt"), "w").write("\n".join(files) + ("\n" if files else ""))
    json.dump(plan.get("candidates") or {}, open(os.path.join(out_dir, "candidates.draft.json"), "w"), indent=2)
    json.dump(plan.get("anchors") or {}, open(os.path.join(out_dir, "anchors.json"), "w"), indent=2, ensure_ascii=False)
    dr = plan.get("dry_run") or {}
    json.dump({"walls": dr.get("walls", []), "links": dr.get("links", []), "stats": dr.get("stats", {})},
              open(os.path.join(out_dir, "links.draft.json"), "w"), indent=2, ensure_ascii=False)


def load_preset(catalog_path: str, name: str) -> Optional[dict]:
    if not (catalog_path and name and os.path.exists(catalog_path)):
        return None
    presets = json.load(open(catalog_path))
    p = presets.get(name)
    if isinstance(p, dict):
        p = dict(p)
        p["_name"] = name
    return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cond")
    ap.add_argument("--src", default="")
    ap.add_argument("--out", default="", help="review bundle dir (default: <cond>/../draft)")
    ap.add_argument("--catalog", default=os.path.join(_HERE, "spec.presets.json"))
    ap.add_argument("--preset", default="", help="preset name whose recovery keys seed the spec")
    ap.add_argument("--include-proposed", action="store_true", help="pre-accept aligned proposed rows too")
    ap.add_argument("--no-dry-run", action="store_true")
    ap.add_argument("--no-anchoring", action="store_true", help="ablation axis: engine rows only")
    ap.add_argument("--reject-anchor", nargs="*", default=[],
                    help="anchor names to ignore (provider maps, callbacks): module-qualified as printed in "
                         "anchors.json (pkg.mod.NAME / pkg.mod.Cls.attr); the short form (NAME / Cls.attr) is still accepted")
    ap.add_argument("--disable", default="", help="leave-one-out: comma list of S1,S2,S3,anchoring")
    a = ap.parse_args(argv)
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.cond)), "draft")
    plan = build_plan(a.cond, src_root=a.src, catalog_path=a.catalog,
                      preset=load_preset(a.catalog, a.preset), include_proposed=a.include_proposed,
                      dry_run=not a.no_dry_run, use_anchoring=not a.no_anchoring, reject_anchors=a.reject_anchor,
                      disable=[x.strip() for x in a.disable.split(",") if x.strip()])
    write_bundle(plan, out)
    print(render_report_md(plan))
    print(f"[draft] wrote {out}/plan.json (+ plan.draft.json [read-only original], walls.md, report.md, "
          f"spec.draft.json, wall_files.txt, candidates.draft.json, links.draft.json, env_report.json)")
    return EXIT.get(plan["outcome"], 1)


if __name__ == "__main__":
    sys.exit(main())
