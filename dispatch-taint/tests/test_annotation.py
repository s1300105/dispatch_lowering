"""Tests for the independent-annotation infrastructure (external validity)."""
import math
import tempfile
from pathlib import Path

from benchmark.annotation import (
    candidate_pool, label_from_gold, cohens_kappa, agreement_report,
    write_csv, read_csv, build_sheet,
)


def test_cohens_kappa_known_values():
    assert cohens_kappa(["x", "x", "y"], ["x", "x", "y"])["kappa"] == 1.0           # perfect
    z = cohens_kappa(["x", "x", "y", "y"], ["x", "y", "x", "y"])                     # chance-only
    assert abs(z["kappa"] - 0.0) < 1e-9 and abs(z["po"] - 0.5) < 1e-9
    k = cohens_kappa(["x", "x", "x", "y", "y"], ["x", "x", "y", "y", "y"])           # po=.8 pe=.48
    assert abs(k["kappa"] - 0.61538) < 1e-4


_TOOLMOD = '''
class ShellTool:
    @property
    def name(self) -> str:
        return "shell"
    def run(self, cmd):
        import subprocess; subprocess.Popen(cmd, shell=True)

def write_file(path, content):
    open(path, "w").write(content)

def _helper(x):
    return x
'''


def _tmp_repo():
    d = tempfile.mkdtemp(prefix="ctaudit_annot_test_")
    (Path(d) / "agent.py").write_text(_TOOLMOD)
    return d


def test_candidate_pool_extracts_and_resolves_names():
    cands = candidate_pool(_tmp_repo())
    names = {c.name for c in cands}
    assert "ShellTool" in names and "write_file" in names
    assert "_helper" not in names                          # private excluded
    shell = next(c for c in cands if c.name == "ShellTool")
    assert "shell" in shell.match_names                    # resolved from the name property


def test_label_from_gold_uses_match_names():
    cands = candidate_pool(_tmp_repo())
    tools = {"shell": {"roles": ["source", "sink"], "category": "code_execution", "guard": "_chk"},
             "write_file": {"roles": ["sink"], "category": "file_write", "guard": None}}
    shell = next(c for c in cands if c.name == "ShellTool")
    wf = next(c for c in cands if c.name == "write_file")
    helper_like = next(c for c in cands if c.name == "run")    # not a gold tool by name
    ls = label_from_gold(shell, tools)
    assert ls["is_tool"] == "Y" and ls["role"] == "both" and ls["sink_category"] == "code_execution" and ls["guarded"] == "yes"
    lw = label_from_gold(wf, tools)
    assert lw["role"] == "sink" and lw["guarded"] == "no"      # sink with no guard
    assert label_from_gold(helper_like, tools)["is_tool"] == "N"


def test_agreement_report_matches_by_qualname_and_tools_only():
    a = [{"qualname": "m.f1", "is_tool": "Y", "role": "sink", "sink_category": "file_write", "guarded": "yes"},
         {"qualname": "m.f2", "is_tool": "N", "role": "none", "sink_category": "none", "guarded": "na"},
         {"qualname": "m.f3", "is_tool": "Y", "role": "source", "sink_category": "none", "guarded": "na"}]
    b = [{"qualname": "m.f1", "is_tool": "Y", "role": "sink", "sink_category": "file_write", "guarded": "yes"},
         {"qualname": "m.f2", "is_tool": "N", "role": "none", "sink_category": "none", "guarded": "na"},
         {"qualname": "m.f3", "is_tool": "N", "role": "none", "sink_category": "none", "guarded": "na"}]  # disagree on f3
    rep = agreement_report(a, b)
    assert rep["n_matched"] == 3
    assert rep["is_tool"]["n"] == 3 and abs(rep["is_tool"]["po"] - 2 / 3) < 1e-9
    assert rep["role_tools_only"]["n"] == 2                    # f1 and f3 (either marked Y)


def test_csv_roundtrip():
    rows = build_sheet(_tmp_repo(), None, "blank")
    d = tempfile.mkdtemp(prefix="ctaudit_annot_csv_")
    p = str(Path(d) / "sheet.csv")
    write_csv(rows, p)
    back = read_csv(p)
    assert len(back) == len(rows)
    assert {r["qualname"] for r in back} == {r["qualname"] for r in rows}
    assert all(r["is_tool"] == "" for r in back)              # blank sheet has empty labels
