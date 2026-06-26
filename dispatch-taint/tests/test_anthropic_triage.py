"""Integration coverage for the AnthropicTriage path (§4.6).

A *successful* completion needs a live ``ANTHROPIC_API_KEY``, so the genuine
end-to-end call is exercised by ``scripts/triage_smoke.py`` (run it with a key).
These tests cover everything else about the real code path deterministically and
offline:

* the success path — ``_call`` actually runs: it invokes ``client.messages
  .create(...)``, extracts the text blocks, parses the JSON verdict and maps it
  onto the finding — driven by a *stub* client so no network is touched;
* fenced-JSON tolerance;
* a malformed model reply falling back per-finding (with an annotation);
* no key / no SDK falling back to the mock (with an annotation).

The stub is injected as ``triager._client``; the real ``AnthropicTriage.triage``
orchestration and ``_call`` parsing run unchanged.
"""

from __future__ import annotations

import pytest

from ctaudit.labels import SourceMark
from ctaudit.report import Finding
from ctaudit.triage.llm_triage import AnthropicTriage, MockTriage


def a_finding():
    return Finding(
        kind="implicit",
        sink_name="subprocess.run",
        sink_category="exec",
        severity="high",
        sink_site="50:4",
        arg_expr="call['args']['command']",
        param_type="string",
        source_marks=(SourceMark("read_webpage", "langchain", "f.py:10", out_type="string"),),
        exit_sites=("f.py:40:1",),
        file="f.py",
    )


# --------------------------------------------------------------------------- #
# a stub Anthropic client matching the Messages API response shape
# --------------------------------------------------------------------------- #
class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Msg:
    def __init__(self, text):
        self.content = [_Block(text)]


class _Messages:
    def __init__(self, text):
        self._text = text
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)        # record what was sent
        return _Msg(self._text)


class _StubClient:
    def __init__(self, text):
        self.messages = _Messages(text)


def _triager_with_stub(monkeypatch, text):
    # ensure construction takes the no-key branch (client None), then inject stub.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    t = AnthropicTriage(model="claude-sonnet-4-5-20250929")
    assert t._client is None          # no real client built without a key
    t._client = _StubClient(text)     # inject the stub transport
    return t


# --------------------------------------------------------------------------- #
# success path — real _call parsing/verdict mapping
# --------------------------------------------------------------------------- #
def test_call_parses_json_verdict_and_maps_it(monkeypatch):
    t = _triager_with_stub(
        monkeypatch,
        '{"is_true_positive": true, "confidence": 0.91, "rationale": "exploitable routing"}',
    )
    f = a_finding()
    t.triage([f], source="x = 1\n")
    assert f.triage_verdict == "true-positive"
    assert f.triage_confidence == 0.91
    assert f.triage_rationale == "exploitable routing"
    # the contract really was sent to the (stub) Messages API
    assert t._client.messages.calls
    sent = t._client.messages.calls[0]
    assert sent["model"] == "claude-sonnet-4-5-20250929"
    assert sent["messages"][0]["role"] == "user"


def test_call_maps_false_positive(monkeypatch):
    t = _triager_with_stub(
        monkeypatch,
        '{"is_true_positive": false, "confidence": 0.2, "rationale": "constrained"}',
    )
    f = a_finding()
    t.triage([f], source="x = 1\n")
    assert f.triage_verdict == "false-positive"
    assert f.triage_confidence == 0.2


def test_call_tolerates_markdown_fenced_json(monkeypatch):
    t = _triager_with_stub(
        monkeypatch,
        '```json\n{"is_true_positive": true, "confidence": 0.7, "rationale": "ok"}\n```',
    )
    f = a_finding()
    t.triage([f], source="x = 1\n")
    assert f.triage_verdict == "true-positive"
    assert f.triage_confidence == 0.7


def test_confidence_is_clamped(monkeypatch):
    t = _triager_with_stub(
        monkeypatch,
        '{"is_true_positive": true, "confidence": 5, "rationale": "over"}',
    )
    f = a_finding()
    t.triage([f], source="x = 1\n")
    assert f.triage_confidence == 1.0


# --------------------------------------------------------------------------- #
# malformed reply -> per-finding fallback (annotated)
# --------------------------------------------------------------------------- #
def test_malformed_reply_falls_back_per_finding(monkeypatch):
    t = _triager_with_stub(monkeypatch, "not json at all")
    f = a_finding()
    t.triage([f], source="x = 1\n")
    # still produces a verdict (from the mock heuristic) ...
    assert f.triage_verdict in ("true-positive", "false-positive")
    # ... and says it fell back.
    assert "anthropic error" in (f.triage_rationale or "")


# --------------------------------------------------------------------------- #
# no key / no SDK -> mock fallback (annotated)
# --------------------------------------------------------------------------- #
def test_no_key_falls_back_to_mock(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    t = AnthropicTriage()
    assert t._client is None
    f = a_finding()
    t.triage([f], source="x = 1\n")
    assert f.triage_verdict is not None
    assert "anthropic unavailable" in (f.triage_rationale or "")


def test_anthropic_fallback_matches_mock_verdict(monkeypatch):
    # the fallback verdict should equal what the offline mock would have said.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    f1, f2 = a_finding(), a_finding()
    AnthropicTriage().triage([f1], source="x = 1\n")
    MockTriage().triage([f2], source="x = 1\n")
    assert f1.triage_verdict == f2.triage_verdict
    assert f1.triage_confidence == f2.triage_confidence
