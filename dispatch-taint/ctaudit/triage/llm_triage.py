"""Pluggable LLM-triage backends (§4.6).

Two backends with the same interface:

* :class:`MockTriage` — offline, deterministic.  No network, no key.  It encodes
  the *shape* of the borrowed heuristic (a finding is a likely true positive when
  it reaches a high-severity sink through a free-form-string parameter over a
  schema-compatible channel) so the pipeline is fully runnable and testable in
  CI without any external dependency.

* :class:`AnthropicTriage` — uses the standard ``anthropic`` Messages API with a
  structured-contract prompt (§4.6).  Reads ``ANTHROPIC_API_KEY`` from the
  environment and degrades gracefully to :class:`MockTriage` if the key or the
  SDK is unavailable, so ``--triage anthropic`` never hard-fails a CI run.

Both return their verdict by writing ``triage_verdict`` / ``triage_confidence`` /
``triage_rationale`` onto the :class:`~ctaudit.report.Finding` (a structured JSON
verdict: ``{is_true_positive, confidence, rationale}``).  Channel capacity is used
only as a *down-weight* (bool/enum sources are less attacker-controllable), which
is ablatable per §4.6.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional, Protocol

from ..analysis.pruning import kept
from ..models.base import channel_capacity
from ..report import Finding
from .contract import TriageContract, build_contract

_FREEFORM = {"string", "object", "any"}


class Triager(Protocol):
    def triage(self, findings: List[Finding], source: Optional[str] = None) -> List[Finding]:
        ...


def _verdict(is_tp: bool, confidence: float, rationale: str):
    return ("true-positive" if is_tp else "false-positive",
            round(max(0.0, min(1.0, confidence)), 2),
            rationale)


def _parse_verdict_json(text: str) -> dict:
    """Robustly extract the verdict JSON object from an LLM reply.

    Handles: bare JSON, ```json fenced blocks, and JSON embedded in prose
    (reasoning models often emit explanation before/after the object). Scans for
    the first brace-balanced {...} and parses it. Raises ValueError if none is
    found or it doesn't parse, so the caller's existing except-clause fires."""
    text = (text or "").strip()
    # strip code fences if present
    if "```" in text:
        # take the content of the first fenced block if it looks like JSON
        import re as _re
        m = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re.S)
        if m:
            text = m.group(1)
    # find the first balanced {...}
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object in response")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON object in response")


class MockTriage:
    """Deterministic, offline triager (default).

    Heuristic (mirrors the borrowed technique's decision surface):

    * high-severity sink reached through a free-form-string/object parameter
      -> true positive (high confidence);
    * dispatch findings -> true positive (medium-high);
    * narrow channel (bool/enum source into a wider sink) -> down-weighted toward
      false positive;
    * everything else -> uncertain-leaning true positive at medium confidence.
    """

    name = "mock"

    def triage(self, findings: List[Finding], source: Optional[str] = None) -> List[Finding]:
        for f in kept(findings):
            c = build_contract(f, source)
            v, conf, why = self._judge(c)
            f.triage_verdict, f.triage_confidence, f.triage_rationale = v, conf, why
        return findings

    def _judge(self, c: TriageContract):
        free_param = c.sink_param_type.lower() in _FREEFORM

        if c.flow_kind == "dispatch":
            return _verdict(True, 0.7,
                            "LLM-selected tool dispatch on attacker-influenced "
                            "reasoning; the callee itself is chosen by the model.")
        if c.flow_kind == "explicit":
            return _verdict(True, 0.85,
                            "data-layer flow: tool output reaches the sink "
                            "verbatim (classic TITO), independent of the model.")
        # implicit
        if c.severity == "high" and free_param:
            return _verdict(True, 0.8,
                            f"attacker-influenced tool output can steer a "
                            f"free-form '{c.sink_param_type}' argument into the "
                            f"high-severity sink {c.sink} via the model's "
                            f"tool-call routing (CWE-1426).")
        if c.severity == "medium" and free_param:
            return _verdict(True, 0.55,
                            f"medium-severity sink {c.sink} reachable through "
                            f"model routing; review impact.")
        return _verdict(False, 0.4,
                        f"sink parameter '{c.sink_param_type}' is too constrained "
                        f"for the model to carry an attacker payload through; "
                        f"likely low-bandwidth (§4.6 channel capacity).")


class AnthropicTriage:
    """LLM triager using the standard Anthropic Messages API (§4.6).

    Falls back to :class:`MockTriage` when the SDK or key is missing so a run is
    never blocked by triage configuration.
    """

    name = "anthropic"

    SYSTEM = (
        "You are a security triage assistant for a static analyzer that finds "
        "cross-tool implicit (control-dependency) taint flows in LLM agents "
        "(CWE-1426): one tool's attacker-influenceable output, via the model's "
        "reasoning, selects a dangerous call to another tool. You are given a "
        "structured finding. Decide whether it is a TRUE POSITIVE (a real, "
        "exploitable wiring) or a FALSE POSITIVE.\n"
        "THREAT MODEL — what counts as a vulnerability. An attacker who controls "
        "a tool's output can steer a subsequent tool call. ALL of the following "
        "harm classes are in scope and equally count as exploitable; do NOT "
        "treat only data exfiltration as dangerous:\n"
        "  (1) EXFILTRATION / disclosure — sending or leaking data outward "
        "(network, email, messages to others).\n"
        "  (2) INTEGRITY / modification — altering, overwriting, creating, or "
        "reconfiguring state (writing files, changing settings, updating "
        "records, account/permission changes).\n"
        "  (3) DESTRUCTION / availability — deleting, cancelling, removing, or "
        "disrupting (deleting files/emails, cancelling or rescheduling events, "
        "removing users, dropping data). Attacker-driven deletion or cancellation "
        "IS a real vulnerability, just as much as exfiltration.\n"
        "  (4) UNAUTHORIZED ACTION / transaction — money transfers, bookings, "
        "sending messages on the user's behalf.\n"
        "A flow is a TRUE POSITIVE when an attacker-influenced source can plausibly "
        "drive the sink to cause ANY of (1)-(4). Judge it a FALSE POSITIVE only when "
        "the channel genuinely cannot carry attacker influence (e.g. the tainted "
        "argument is a tightly constrained bool/enum that cannot encode an attacker "
        "payload, the source is not actually attacker-controllable, or the trace is "
        "implausible) — NOT merely because the harm is destruction/modification "
        "rather than disclosure. Consider sink severity, the tainted argument's "
        "bandwidth (free-form string/object = high; bool/enum = low), and trace "
        "plausibility. Respond with ONLY a JSON object, no prose, no markdown "
        "fences: "
        '{"is_true_positive": bool, "confidence": number 0..1, "rationale": string}.'
    )

    def __init__(self, model: Optional[str] = None) -> None:
        self.model = model or os.environ.get("CTAUDIT_TRIAGE_MODEL",
                                             "claude-sonnet-4-5-20250929")
        self._fallback = MockTriage()
        self._client = self._make_client()

    def _make_client(self):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            import anthropic  # type: ignore
        except Exception:
            return None
        try:
            return anthropic.Anthropic()
        except Exception:
            return None

    def triage(self, findings: List[Finding], source: Optional[str] = None) -> List[Finding]:
        if self._client is None:
            # graceful, explicit fallback.
            self._fallback.triage(findings, source)
            for f in kept(findings):
                if f.triage_rationale:
                    f.triage_rationale = "[anthropic unavailable; mock] " + f.triage_rationale
            return findings

        for f in kept(findings):
            contract = build_contract(f, source)
            try:
                v, conf, why = self._call(contract)
            except Exception as exc:  # network / parse error -> fall back per-finding
                v, conf, why = self._fallback._judge(contract)
                why = f"[anthropic error: {type(exc).__name__}; mock] {why}"
            f.triage_verdict, f.triage_confidence, f.triage_rationale = v, conf, why
        return findings

    def _call(self, contract: TriageContract):
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=512,
            system=self.SYSTEM,
            messages=[{"role": "user", "content": contract.to_json()}],
        )
        text = "".join(
            block.text for block in msg.content if getattr(block, "type", "") == "text"
        )
        data = _parse_verdict_json(text)
        return _verdict(
            bool(data.get("is_true_positive", True)),
            float(data.get("confidence", 0.5)),
            str(data.get("rationale", "")),
        )


class OpenAICompatTriage:
    """LLM triager over any OpenAI-compatible Chat Completions endpoint (§4.6).

    Covers OpenAI itself and any provider that speaks the OpenAI API by changing
    ``base_url`` — notably **DeepSeek** (``https://api.deepseek.com``), plus
    Together / Groq / OpenRouter / local Ollama / vLLM. Same structured-contract
    prompt as :class:`AnthropicTriage`, same graceful fallback to
    :class:`MockTriage` when the SDK or key is missing, so a run never hard-fails.

    The triage LLM is independent of whatever LLM the *analysed agent* uses; it
    only affects the §4.6 precision-refinement quality, never detection.
    """

    SYSTEM = AnthropicTriage.SYSTEM  # identical contract prompt across backends

    def __init__(self, *, provider: str = "openai-compat",
                 api_key_env: str = "OPENAI_API_KEY",
                 base_url: Optional[str] = None,
                 default_model: str = "gpt-4o-mini",
                 model: Optional[str] = None) -> None:
        self.name = provider
        self.api_key_env = api_key_env
        self.base_url = base_url or os.environ.get("CTAUDIT_TRIAGE_BASE_URL")
        self.model = model or os.environ.get("CTAUDIT_TRIAGE_MODEL", default_model)
        self._fallback = MockTriage()
        self._client = self._make_client()

    def _make_client(self):
        key = os.environ.get(self.api_key_env) or os.environ.get("CTAUDIT_TRIAGE_API_KEY")
        if not key:
            return None
        try:
            from openai import OpenAI  # type: ignore
        except Exception:
            return None
        try:
            kwargs = {"api_key": key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            return OpenAI(**kwargs)
        except Exception:
            return None

    def triage(self, findings: List[Finding], source: Optional[str] = None) -> List[Finding]:
        if self._client is None:
            self._fallback.triage(findings, source)
            for f in kept(findings):
                if f.triage_rationale:
                    f.triage_rationale = f"[{self.name} unavailable; mock] " + f.triage_rationale
            return findings

        for f in kept(findings):
            contract = build_contract(f, source)
            try:
                v, conf, why = self._call(contract)
            except Exception as exc:  # network / parse error -> per-finding fallback
                v, conf, why = self._fallback._judge(contract)
                why = f"[{self.name} error: {type(exc).__name__}; mock] {why}"
            f.triage_verdict, f.triage_confidence, f.triage_rationale = v, conf, why
        return findings

    def _call(self, contract: TriageContract):
        # temperature 0 for determinism; reasoning models (e.g. deepseek-reasoner)
        # ignore it harmlessly. We rely on the strict system prompt + JSON parse
        # rather than response_format, for the broadest provider compatibility.
        msg = self._client.chat.completions.create(
            model=self.model,
            max_tokens=512,
            temperature=0,
            messages=[{"role": "system", "content": self.SYSTEM},
                      {"role": "user", "content": contract.to_json()}],
        )
        text = (msg.choices[0].message.content or "")
        data = _parse_verdict_json(text)
        return _verdict(
            bool(data.get("is_true_positive", True)),
            float(data.get("confidence", 0.5)),
            str(data.get("rationale", "")),
        )


def get_triager(name: str = "mock", model: Optional[str] = None) -> Triager:
    if name == "anthropic":
        return AnthropicTriage(model=model)
    if name == "deepseek":
        # DeepSeek is OpenAI-compatible. Default model deepseek-chat (DeepSeek-V3,
        # valid now); the V4 ids are deepseek-v4-flash / deepseek-v4-pro. Note:
        # deepseek-chat / deepseek-reasoner are scheduled to retire 2026-07-24 —
        # pass --model deepseek-v4-flash to switch.
        return OpenAICompatTriage(provider="deepseek", api_key_env="DEEPSEEK_API_KEY",
                                  base_url="https://api.deepseek.com",
                                  default_model="deepseek-chat", model=model)
    if name == "openai":
        return OpenAICompatTriage(provider="openai", api_key_env="OPENAI_API_KEY",
                                  base_url=None, default_model="gpt-4o-mini", model=model)
    if name == "openai-compat":
        # fully generic: set CTAUDIT_TRIAGE_BASE_URL / _API_KEY / _MODEL
        return OpenAICompatTriage(provider="openai-compat",
                                  api_key_env="CTAUDIT_TRIAGE_API_KEY",
                                  default_model=os.environ.get("CTAUDIT_TRIAGE_MODEL",
                                                               "deepseek-chat"),
                                  model=model)
    return MockTriage()
