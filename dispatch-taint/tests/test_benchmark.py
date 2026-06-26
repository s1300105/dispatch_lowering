"""Tests for the RQ4 classifier benchmark.

* the harness scoring math (pure unit, no repos);
* a *characterisation* of the heuristic's known recall hole: it misses the
  dict-registry idiom. When that gap is closed (e.g. by the LLM backend in
  part (b) or a registry-aware extension), this test flips and flags the progress.
"""
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctaudit.toolmodel import get_classifier
from benchmark.run_benchmark import _eval_one
from benchmark.labels import CORPUS_BASE, SYNTHETIC_DICT_REGISTRY, SYNTHETIC_GOLD


def _tool(name, roles, category=None, guard=None):
    sink = SimpleNamespace(category=category, guard=guard, arg=None) if "sink" in roles else None
    return SimpleNamespace(name=name, roles=roles, sink=sink)


def test_eval_one_counts():
    detected = [
        _tool("write_file", ["sink"], "file_write", None),       # cat ok, guard MISMATCH (gold has guard)
        _tool("read_file", ["source"]),                          # exact match
        _tool("bogus", ["sink"], "code_execution"),              # false positive
    ]
    gold = {
        "write_file": {"roles": ["sink"], "category": "file_write", "guard": "confirm_action"},
        "read_file":  {"roles": ["source"], "category": None, "guard": None},
        "search_text": {"roles": ["source"], "category": None, "guard": None},  # missed -> FN
    }
    tp, fp, fn, ro, rt, co, ct, go, gt, _ = _eval_one(detected, gold)
    assert set(tp) == {"write_file", "read_file"}
    assert fp == ["bogus"]
    assert fn == ["search_text"]
    assert ro == 2 and rt == 2          # both matched tools have correct roles
    assert co == 1 and ct == 1          # one sink matched, category correct
    assert go == 0 and gt == 1          # guard presence DISAGREES (detected None vs gold set)


def test_heuristic_misses_dict_registry_idiom():
    # characterisation: the deterministic heuristic does not yet recognise a
    # dict-registry of top-level functions + central dispatcher (the codecli idiom).
    d = tempfile.mkdtemp(prefix="ctaudit_bench_test_")
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (Path(d) / rel).write_text(body)
    model = get_classifier("heuristic").classify(d, src_root=d)
    detected = {t.name for t in model.tools}
    gold = set(SYNTHETIC_GOLD["tools"])
    # KNOWN GAP: recall is currently 0 on this idiom (no gold tool recovered).
    assert not (detected & gold), (
        "dict-registry idiom now partially detected -- update the benchmark "
        "characterisation; the RQ4 recall hole has improved."
    )
    # the aliased LLM call IS recovered even here (that part generalises)
    assert model.llm_call and model.llm_call.callable == "openai._Completions.create"


def test_discovery_pass_closes_recall_hole_with_fake_transport():
    """Architectural proof (no model, no fixtures): a discovery transport lets the
    LLM classifier recover dict-registry tools the heuristic misses, unioned
    recall-first with the heuristic floor."""
    from ctaudit.toolmodel import LLMToolClassifier

    d = tempfile.mkdtemp(prefix="ctaudit_disc_test_")
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (Path(d) / rel).write_text(body)

    discovery_json = (
        '{"tools": ['
        '{"name": "read_file", "callable": "files.read_file", "roles": ["source"],'
        ' "sink": null, "source": {"capacity": "string", "attacker": true}},'
        '{"name": "write_file", "callable": "files.write_file", "roles": ["sink"],'
        ' "sink": {"category": "file_write", "arg": "content", "guard": "confirm_action"},'
        ' "source": null}'
        '], "llm_call": null}'
    )
    calls = {"n": 0}

    def fake_complete(system, user):
        calls["n"] += 1
        assert "REPO:" in user and "TOOL REGISTRY" in system   # discovery prompt was built
        return discovery_json

    # heuristic alone finds nothing here
    assert get_classifier("heuristic").classify(d, src_root=d).tools == []

    model = LLMToolClassifier(complete=fake_complete).classify(d, src_root=d)
    by = {t.name: t for t in model.tools}
    assert calls["n"] == 1
    assert set(by) == {"read_file", "write_file"}             # recall hole closed
    assert by["write_file"].sink.category == "file_write"
    assert by["write_file"].sink.guard == "confirm_action"    # cross-layer guard recovered
    assert "source" in by["read_file"].roles
    # the aliased LLM call still comes from the heuristic floor (union preserved it)
    assert model.llm_call and model.llm_call.callable == "openai._Completions.create"


def test_llm_classifier_without_transport_is_heuristic_floor():
    # no transport => never below the heuristic (recall-first floor), no crash
    from ctaudit.toolmodel import LLMToolClassifier
    d = tempfile.mkdtemp(prefix="ctaudit_floor_test_")
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (Path(d) / rel).write_text(body)
    model = LLMToolClassifier(complete=None).classify(d, src_root=d)
    assert model.tools == []   # same as heuristic on this idiom; degraded gracefully


def test_discovery_tolerates_trailing_content():
    """Regression: DeepSeek sometimes appends prose / a second block after the JSON,
    which made json.loads fail with 'Extra data'. The brace-depth extractor must
    take just the first balanced object."""
    from ctaudit.toolmodel import LLMToolClassifier
    from ctaudit.toolmodel.classify import _first_json_object

    obj = '{"a": {"b": "}{"}, "c": [1,2]}'          # braces/quotes inside strings
    assert _first_json_object(obj + "\n\nHere is the analysis...\n```") == obj
    assert _first_json_object("```json\n" + obj + "\n```") == obj
    assert _first_json_object(obj + "\n" + '{"second": true}') == obj   # ignore 2nd block

    d = tempfile.mkdtemp(prefix="ctaudit_trail_test_")
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (Path(d) / rel).write_text(body)
    noisy = ('{"tools": [{"name": "write_file", "callable": "files.write_file",'
             ' "roles": ["sink"], "sink": {"category": "file_write", "arg": "content",'
             ' "guard": "confirm_action"}, "source": null}], "llm_call": null}'
             '\n\nNote: I also considered read_file but focused on the sink.')  # trailing prose
    model = LLMToolClassifier(complete=lambda s, u: noisy).classify(d, src_root=d)
    assert "write_file" in {t.name for t in model.tools}      # parsed despite trailing text


# ---- grounding (recall-first precision filter) ---------------------------- #
_GROUND_REPO = {
    "tools.py": (
        "import impl\n"
        "TOOL_SCHEMAS = {'read_doc': {}, 'list_dir': {}, 'safe_write': {},\n"
        "                'apply_patch': {}, 'report_status': {}}\n"
        "def run_tool(name, args):\n"
        "    if name == 'apply_patch':\n"
        "        new = impl.apply_patch(args['original'], args['patch'])\n"
        "        return impl.safe_write(args['path'], new)   # output -> sink fn\n"
        "    if name == 'report_status':\n"
        "        return impl.report_status(args)\n"
        "    return None\n"
    ),
    "impl.py": (
        "from pathlib import Path\n"
        "def read_doc(path):\n"
        "    return Path(path).read_text()\n"
        "def list_dir(root):\n"
        "    return [p.name for p in Path(root).rglob('*')]\n"
        "def safe_write(path, content):\n"
        "    Path(path).write_text(content)\n"
        "    return 'ok'\n"
        "def apply_patch(original, patch):\n"
        "    return original + patch          # pure transform, NO i/o\n"
        "def report_status(args):\n"
        "    return {'ok': True, 'info': args}   # no i/o, output not consumed by a sink\n"
    ),
}
_GROUND_DISCOVERY = (
    '{"tools": ['
    '{"name":"read_doc","callable":"impl.read_doc","roles":["source"],"sink":null,"source":{"capacity":"string","attacker":true}},'
    '{"name":"list_dir","callable":"impl.list_dir","roles":["source"],"sink":null,"source":{"capacity":"string","attacker":true}},'
    '{"name":"safe_write","callable":"impl.safe_write","roles":["sink"],"sink":{"category":"file_write","arg":"content","guard":null},"source":null},'
    '{"name":"apply_patch","callable":"impl.apply_patch","roles":["sink"],"sink":{"category":"file_write","arg":"patch","guard":null},"source":null},'
    '{"name":"report_status","callable":"impl.report_status","roles":["source"],"sink":null,"source":{"capacity":"string","attacker":true}}'
    '], "llm_call": null}'
)


def test_grounding_is_recall_safe_and_drops_ungrounded():
    from ctaudit.toolmodel import LLMToolClassifier
    d = tempfile.mkdtemp(prefix="ctaudit_ground_test_")
    for rel, body in _GROUND_REPO.items():
        (Path(d) / rel).write_text(body)

    # grounding ON (default): report_status (no I/O, output not consumed) is dropped,
    # everything else is kept — including apply_patch (output flows to safe_write, a
    # cross-layer sink) and list_dir (source via rglob enumeration).
    model = LLMToolClassifier(complete=lambda s, u: _GROUND_DISCOVERY, ground=True).classify(d, src_root=d)
    kept = {t.name for t in model.tools}
    assert kept == {"read_doc", "list_dir", "safe_write", "apply_patch"}, kept
    by = {t.name: t for t in model.tools}
    assert "sink" in by["apply_patch"].roles      # kept via output->sink (recall-safe)
    assert "source" in by["list_dir"].roles       # kept via enumeration source

    # grounding OFF: the spurious report_status survives (reproduces the precision cost)
    raw = LLMToolClassifier(complete=lambda s, u: _GROUND_DISCOVERY, ground=False).classify(d, src_root=d)
    assert "report_status" in {t.name for t in raw.tools}


_CAND = Path(CORPUS_BASE)   # real corpus root (set CTAUDIT_CORPUS_BASE); tests skip if absent


@pytest.mark.skipif(not (_CAND / "codecli").exists(), reason="codecli not present")
def test_grounding_preserves_codecli_gold_via_replay():
    # grounding must NOT drop any of codecli's 5 real source/sink tools.
    from ctaudit.toolmodel import LLMToolClassifier, make_replay_transport
    fixtures = str(Path(__file__).resolve().parents[1] / "benchmark" / "llm_fixtures")
    clf = LLMToolClassifier(complete=make_replay_transport(fixtures), ground=True)
    model = clf.classify(str(_CAND / "codecli"), src_root=str(_CAND / "codecli" / "app"))
    names = {t.name for t in model.tools}
    assert {"list_files", "read_file", "search_text", "write_file", "apply_diff"} <= names


# ---- cross-layer guard tracing (deterministic, conservative) -------------- #
_GUARD_REPO = {
    "tools.py": (
        "import impl\n"
        "TOOL_SCHEMAS = {'save': {}, 'wipe': {}}\n"
        "def confirm_action(prompt):\n"
        "    return input(prompt) == 'y'\n"
        "def run_tool(name, args):\n"
        "    if name == 'save':\n"
        "        if not confirm_action('save? [y/N] '):\n"
        "            return {'ok': False}\n"
        "        return impl.save(args['path'], args['content'])   # GUARDED branch\n"
        "    if name == 'wipe':\n"
        "        return impl.wipe(args['path'])                      # UNGUARDED branch\n"
        "    return None\n"
    ),
    "impl.py": (
        "from pathlib import Path\n"
        "def save(path, content):\n"
        "    Path(path).write_text(content)\n"
        "    return 'ok'\n"
        "def wipe(path):\n"
        "    Path(path).write_text('')\n"
        "    return 'wiped'\n"
    ),
}


def _guard_model(discovery_json, ground=True):
    from ctaudit.toolmodel import LLMToolClassifier
    d = tempfile.mkdtemp(prefix="ctaudit_guard_test_")
    for rel, body in _GUARD_REPO.items():
        (Path(d) / rel).write_text(body)
    m = LLMToolClassifier(complete=lambda s, u: discovery_json, ground=ground).classify(d, src_root=d)
    return {t.name: (t.sink.guard if t.sink else None) for t in m.tools}


def test_guard_tracing_recovers_dispatcher_guard():
    # the fake LLM reports NO guard; the tracer must recover confirm_action for the
    # dispatcher-guarded sink (cross-layer), deterministically.
    disc = ('{"tools": ['
            '{"name":"save","callable":"impl.save","roles":["sink"],"sink":{"category":"file_write","arg":"content","guard":null},"source":null},'
            '{"name":"wipe","callable":"impl.wipe","roles":["sink"],"sink":{"category":"file_write","arg":"path","guard":null},"source":null}'
            '], "llm_call": null}')
    guards = _guard_model(disc)
    assert guards["save"] == "confirm_action"       # recovered cross-layer
    assert guards["wipe"] is None                   # sibling branch's guard does NOT leak


def test_guard_tracing_rejects_hallucinated_guard():
    # the fake LLM HALLUCINATES a guard on the unguarded sink; the tracer ignores the
    # claim (conservative: a guard is set only if a real guard call dominates the call).
    disc = ('{"tools": ['
            '{"name":"save","callable":"impl.save","roles":["sink"],"sink":{"category":"file_write","arg":"content","guard":"confirm_action"},"source":null},'
            '{"name":"wipe","callable":"impl.wipe","roles":["sink"],"sink":{"category":"file_write","arg":"path","guard":"confirm_action"},"source":null}'
            '], "llm_call": null}')
    guards = _guard_model(disc)
    assert guards["save"] == "confirm_action"       # real guard kept
    assert guards["wipe"] is None                   # hallucinated guard rejected (unguarded => high priority)


@pytest.mark.skipif(not (_CAND / "codecli").exists(), reason="codecli not present")
def test_guard_tracing_codecli_confirm_action_via_replay():
    from ctaudit.toolmodel import LLMToolClassifier, make_replay_transport
    fixtures = str(Path(__file__).resolve().parents[1] / "benchmark" / "llm_fixtures")
    m = LLMToolClassifier(complete=make_replay_transport(fixtures), ground=True).classify(
        str(_CAND / "codecli"), src_root=str(_CAND / "codecli" / "app"))
    g = {t.name: (t.sink.guard if t.sink else None) for t in m.tools if t.sink}
    assert g.get("write_file") == "confirm_action"
    assert g.get("apply_diff") == "confirm_action"


# ---- deterministic provenance (callable/site) + llm_call gating ----------- #
def test_callable_site_filled_and_llm_call_gated():
    """The LLM often omits `callable` and mis-identifies the LLM call. We fill
    callable/site deterministically from the located impl (so leg-a's Pysa emit is
    complete) and reject an implausible llm_call (so the join@LLM node is not corrupted)."""
    from ctaudit.toolmodel import LLMToolClassifier
    from ctaudit.toolmodel.emit import to_pysa

    d = tempfile.mkdtemp(prefix="ctaudit_prov_test_")
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (Path(d) / rel).write_text(body)

    disc = ('{"tools": ['
            '{"name":"write_file","callable":null,"roles":["sink"],'
            '"sink":{"category":"file_write","arg":"content","guard":null},"source":null},'
            '{"name":"read_file","callable":null,"roles":["source"],'
            '"sink":null,"source":{"capacity":"filesystem_read","attacker":true}}],'
            '"llm_call":{"callable":"build_base_prompt","prompt_arg":"x"}}')   # bogus llm_call
    m = LLMToolClassifier(complete=lambda s, u: disc, ground=True).classify(d, src_root=d)
    by = {t.name: t for t in m.tools}

    assert by["write_file"].callable == "files.write_file"     # filled despite callable:null
    assert "files.py:" in by["write_file"].site                # file:line provenance filled
    assert by["read_file"].source.capacity == "string"         # out-of-vocab capacity normalized
    # the implausible LLM-claimed call ("build_base_prompt") is never used as the join node
    assert m.llm_call is None or m.llm_call.callable != "build_base_prompt"

    pysa = to_pysa(m)
    assert "def files.write_file(content: TaintSink[FileSystem])" in pysa   # leg-a emit complete now
    assert "def files.read_file(" in pysa and "TaintSource[ToolOutput" in pysa

    # the plausibility gate itself: helper names rejected, real SDK calls accepted
    from ctaudit.toolmodel.classify import _plausible_llm_call
    from ctaudit.toolmodel.schema import LLMCallSpec
    assert not _plausible_llm_call(LLMCallSpec(callable="build_base_prompt"))
    assert not _plausible_llm_call(LLMCallSpec(callable="tool_dispatcher"))
    assert _plausible_llm_call(LLMCallSpec(callable="client.chat.completions.create"))
    assert _plausible_llm_call(LLMCallSpec(callable="llm.invoke"))
