"""Candidate pruning — turning the over-approximation into something auditable (§4.5).

The naive pc-label rule taints *every* tool call after a tainted output, giving
an N² graph.  The proposal's design choice is deliberate: for a *pre-deployment
all-paths audit*, over-approximation (recall) is the goal, not a weakness — the
real precision is recovered later by the borrowed LLM-triage stage (§4.6).  So
pruning here is conservative: it only removes a candidate when a *static, visible*
fact rules it out, and every prune is recorded (with a reason) rather than
deleted, so an analyst can audit the pruning itself.

Implemented prunes:

* **§4.5(2) schema / channel compatibility.**  If the *source tool* declares a
  narrow output type (``bool`` / ``enum``) but the sink's dangerous parameter is
  a free-form ``string`` / ``object``, the attacker cannot drive the dangerous
  value through such a narrow channel (constrained-decoding capacity,
  bool ⊑ enum ⊑ string of §4.6).  This is the one place the channel-capacity
  idea has real bite; the proposal is honest that it rarely fires because most
  tool outputs are strings, so it is ablatable.

* **§4.5(4) selective hiding (FIDES HIDE).**  A finding all of whose marks are
  ``hidden`` (passed by reference, never expanded into the prompt) has its
  control edge cut.  Note the join in :func:`~ctaudit.labels.join_to_ctl` already
  drops hidden marks, so a *purely* hidden flow never produces a CTL finding in
  the first place; this stage is the explicit, ablatable backstop and also
  documents the decision in the report.

* **§4.5(1) prompt-construction reachability.**  A candidate whose sink lies in
  dead code — after an unconditional ``return`` / ``raise`` / ``break`` /
  ``continue`` in the same suite — can never execute, so it is a static
  over-approximation and is removed.  The engine processes statements linearly
  (it does not stop at a terminator), so such candidates really are produced and
  this prune really removes them; the reachability fact is computed soundly in
  :func:`~ctaudit.models.base.unreachable_nodes`.  The full cross-procedure
  "does the tainted message reach the prompt" question is established by
  construction intra-procedurally (a CTL label is only raised by actually wiring
  an output through a modelled history/exit) and is the inter-procedural
  extension point.

* **§4.5(3) role constraints.**  Tools may carry a declared role/permission
  (``ToolSpec.role`` or a name->role map on the registry); a :class:`RolePolicy`
  states which roles cannot influence which sink categories.  A finding is pruned
  when every contributing source role is known and forbidden for the sink's
  category.  Role assignment is a policy the auditor supplies (real agent code
  rarely annotates roles), so with no policy this prune is a conservative no-op.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional

from ..models.base import channel_capacity
from ..report import Finding


@dataclass(frozen=True)
class RolePolicy:
    """Role-compatibility policy for the §4.5(3) role prune.

    ``forbidden`` maps a sink *category* to the set of source *roles* that are
    declared incapable of dangerously influencing that category (e.g. a tool
    whose role is ``"label-only"`` cannot meaningfully drive an ``"exec"`` sink,
    because the model can only route a constrained label, not an attacker
    payload).  A finding is pruned only when *every* contributing source role is
    known and forbidden for the sink's category; an unknown or allowed role
    keeps the finding (conservative).  An empty policy never prunes.
    """

    forbidden: Dict[str, FrozenSet[str]] = field(default_factory=dict)

    def disallows(self, category: str, roles: FrozenSet[str]) -> bool:
        forb = self.forbidden.get(category)
        if not forb or not roles:
            return False
        return roles <= forb


@dataclass
class PruneConfig:
    """Ablation switches for the evaluation (each prune can be turned off)."""

    schema: bool = True            # §4.5(2)
    selective_hiding: bool = True  # §4.5(4)
    reachability: bool = True      # §4.5(1) (structural; near no-op intra-proc)
    role: bool = True              # §4.5(3) (hook)


def _schema_incompatible(f: Finding) -> Optional[str]:
    """A source whose declared output is strictly narrower than the sink's
    dangerous parameter cannot carry enough attacker bits to drive it."""
    # Capacity pruning is about fitting attacker *data* into a dangerous arg. A
    # `dispatch` finding is about the model's *routing choice* (which tool to
    # call) — a control channel, not a data-into-arg channel — so the
    # source-vs-arg capacity comparison does not apply. (A short tool output is
    # still enough to steer tool selection.)
    if f.kind == "dispatch":
        return None
    sink_cap = channel_capacity(f.param_type)
    # only meaningful for the wide, dangerous sinks (string/object params).
    if sink_cap < channel_capacity("string"):
        return None
    declared = [m.out_type for m in f.source_marks if m.out_type]
    if not declared:
        return None
    # if *every* contributing source is strictly narrower than the sink param,
    # the channel is too narrow to be dangerous.
    if all(channel_capacity(t) < sink_cap for t in declared):
        widest = max(declared, key=channel_capacity)
        return (f"source channel '{widest}' is narrower than sink param "
                f"'{f.param_type}' (constrained-decoding capacity, §4.6)")
    return None


def _all_hidden(f: Finding) -> bool:
    return bool(f.source_marks) and all(m.hidden for m in f.source_marks)


def _unreachable(f: Finding) -> Optional[str]:
    """§4.5(1): a sink in dead code can never execute, so the candidate is a
    static over-approximation and is removed."""
    if not f.reachable:
        return ("sink is unreachable (dead code after an unconditional "
                "return/raise/break/continue) — §4.5(1)")
    return None


def _role_incompatible(f: Finding, policy: Optional[RolePolicy]) -> Optional[str]:
    """§4.5(3): prune when every contributing source role is declared incapable
    of influencing the sink's category."""
    if policy is None:
        return None
    roles = frozenset(m.role for m in f.source_marks if m.role)
    if policy.disallows(f.sink_category, roles):
        return (f"source role(s) {sorted(roles)} cannot influence "
                f"'{f.sink_category}' sinks (role policy, §4.5(3))")
    return None


def prune(findings: List[Finding], config: Optional[PruneConfig] = None,
          role_policy: Optional[RolePolicy] = None) -> List[Finding]:
    """Mark non-viable findings ``pruned`` (with a reason).  Returns the same list."""
    cfg = config or PruneConfig()
    for f in findings:
        if f.pruned:
            continue

        if cfg.selective_hiding and f.kind == "implicit" and _all_hidden(f):
            f.pruned = True
            f.prune_reason = "selective hiding: all sources passed by reference (§4.5(4))"
            continue

        if cfg.reachability:
            reason = _unreachable(f)
            if reason is not None:
                f.pruned = True
                f.prune_reason = reason
                continue

        if cfg.schema:
            reason = _schema_incompatible(f)
            if reason is not None:
                f.pruned = True
                f.prune_reason = reason
                continue

        if cfg.role:
            reason = _role_incompatible(f, role_policy)
            if reason is not None:
                f.pruned = True
                f.prune_reason = reason
                continue

    return findings


def kept(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not f.pruned]
