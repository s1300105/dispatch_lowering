"""Tool-version fingerprint for plan.json / row.json / ablation.json (review item C7).

Every artifact that feeds a benchmark row records the sha256 of the code and catalogue
that produced it, so that ``aggregate`` can flag rows made by a different version
instead of silently mixing rule/catalogue generations in one table.
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict

HERE = os.path.dirname(os.path.abspath(__file__))
M2 = os.path.join(os.path.dirname(HERE), "taintp2x_m2_verification")

# Files whose content decides what a draft / lowering / row looks like.
TRACKED = [
    os.path.join(HERE, "engine_walls.py"),
    os.path.join(HERE, "links.py"),
    os.path.join(HERE, "draft.py"),
    os.path.join(HERE, "anchoring.py"),
    os.path.join(HERE, "catalog.py"),
    os.path.join(HERE, "pipeline.py"),
    os.path.join(HERE, "dispatch_lowering.py"),
    os.path.join(HERE, "spec.presets.json"),
    os.path.join(M2, "ablation_helpers.py"),
    os.path.join(M2, "run_ablation.sh"),
]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version() -> Dict[str, object]:
    """Return ``{"files": {basename: sha256}, "combined": sha256}``.

    ``combined`` is the sha256 over ``"<basename>=<sha>\\n"`` lines in TRACKED order, so it
    changes whenever any tracked file changes. Missing files hash as ``"missing"``.
    """
    files: Dict[str, str] = {}
    for p in TRACKED:
        files[os.path.basename(p)] = _sha256(p) if os.path.exists(p) else "missing"
    combined = hashlib.sha256(
        "".join(f"{k}={v}\n" for k, v in files.items()).encode()
    ).hexdigest()
    return {"files": files, "combined": combined}


def same_version(a: object, b: object) -> bool:
    """True when two ``tool_version()`` dicts (or None) denote the same code+catalogue."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    return a.get("combined") == b.get("combined") and a.get("combined") is not None


if __name__ == "__main__":  # pragma: no cover
    import json
    print(json.dumps(tool_version(), indent=2))
