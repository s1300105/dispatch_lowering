"""``ctaudit-toolmodel`` — classify a repo's tools into ONE shared model and emit
it to both legs (proposal §6 fusion #5).

    ctaudit-toolmodel <repo> [--src-root DIR] [--classifier heuristic|anthropic]
                      [--emit json|pysa|enum|both]

* ``--emit json``  : the shared RepoToolModel (single source of truth)
* ``--emit pysa``  : leg (a) Pysa ``.pysa`` model text
* ``--emit enum``  : leg (b) SOURCES/SINKS + the surviving §4.5 routing pairs
* ``--emit both``  : pysa + enum (default)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .classify import get_classifier
from .emit import to_enumeration, to_pysa


def _render_enum(model) -> str:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "corpus" / "agentdojo"))
    from _common import _flows, render_flows_by_guard  # noqa: E402

    SOURCES, SINKS = to_enumeration(model)
    flows = _flows(SOURCES, SINKS)
    head = (f"SOURCES ({len(SOURCES)}): {', '.join(SOURCES) or '-'}\n"
            f"SINKS   ({len(SINKS)}): {', '.join(SINKS) or '-'}\n")
    return head + "\n" + render_flows_by_guard(flows, SINKS, title=model.repo)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ctaudit-toolmodel")
    ap.add_argument("repo", help="path to the agent repository")
    ap.add_argument("--src-root", default=None,
                    help="import root for qualifying module names (default: repo)")
    ap.add_argument("--classifier", default="heuristic",
                    choices=["heuristic", "anthropic", "deepseek", "openai", "llm"],
                    help="heuristic (offline, deterministic) or an LLM backend "
                         "(anthropic/deepseek/openai) with the recall-first grounding "
                         "+ guard-tracing post-filter")
    ap.add_argument("--no-ground", dest="ground", action="store_false",
                    help="disable the deterministic grounding + guard-tracing post-filter")
    ap.set_defaults(ground=True)
    ap.add_argument("--emit", default="both", choices=["json", "pysa", "enum", "both"])
    args = ap.parse_args(argv)

    clf = get_classifier(args.classifier, ground=args.ground)
    model = clf.classify(args.repo, src_root=args.src_root)

    backends = sorted({t.classifier for t in model.tools}) or ["(no tools)"]
    print(f"# {model.repo}: {len(model.tools)} tool(s); "
          f"LLM call = {model.llm_call.callable if model.llm_call else 'NOT FOUND'}; "
          f"classifier = {', '.join(backends)}\n")

    if args.emit == "json":
        print(model.to_json())
    elif args.emit == "pysa":
        print(to_pysa(model))
    elif args.emit == "enum":
        print(_render_enum(model))
    else:
        print("===== leg (a): emitted Pysa models =====")
        print(to_pysa(model))
        print("===== leg (b): emitted enumeration =====")
        print(_render_enum(model))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
