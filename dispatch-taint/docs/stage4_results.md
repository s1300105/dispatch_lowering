# Stage-4 results log — M1 (DVLA) + M2 (AgentDojo)

This records the real-repository results produced so far. The numbers are
computed by the aggregator, not hand-entered:

```bash
PYTHONPATH=. python -m ctaudit.eval --real-corpus
# per-suite detail:
python corpus/agentdojo/analyze_{banking,workspace,travel,slack}.py
# DVLA (M1) is reproduced by running Pyre on pysa/projects/dvla (see its README)
```

## Unified result (RQ1 / RQ2)

| target              | method    | scope | raw | flagged | TP | FN | recall | precision | discriminating prune (Δ) |
|---------------------|-----------|-------|-----|---------|----|----|--------|-----------|--------------------------|
| AgentDojo·banking   | enumerate | 6×5   | 30  | 20      | 4  | 0  | 100%   | n/a¹      | role (+5)                |
| AgentDojo·workspace | enumerate | 14×10 | 140 | 90      | 5  | 0  | 100%   | n/a¹      | role (+40)               |
| AgentDojo·travel    | enumerate | 22×6  | 132 | 30      | 3  | 0  | 100%   | n/a¹      | role (+48)               |
| AgentDojo·slack     | enumerate | 5×7   | 35  | 21      | 6  | 0  | 100%   | n/a¹      | role (+14)               |
| DVLA (M1)           | Pysa      | 1 path| —   | 1       | 1  | 0  | 100%   | 100%      | —                        |

- **RQ1 (recall):** 19/19 = 100% — pruning kept every tested attack path across
  all five targets (AgentDojo 18/18, DVLA 1/1). No soundness violation.
- **RQ2 (prune reduction, AgentDojo):** 337 raw → 161 flagged (52% cut) with no
  tested positive lost. The **role** prune accounts for 107 of the removed
  candidates and is the discriminator on every suite; schema/reachability/hiding
  have zero *marginal* effect on these suites (schema does the source-capacity
  work but overlaps role here).

¹ AgentDojo labels exploitable pairs (positives) only, not all *safe* pairs, so
the flagged count is a **candidate set** for the §4.6 LLM triage — not a precision
figure. Every hand-added negative in the label CSVs is correctly dropped by the
prunes. DVLA's negatives are complete (1 positive, 1 negative), so its precision
is honest.

## Per-target notes

**DVLA (M1) — Pysa dataflow port.** Real ReAct agent (LangChain `AgentExecutor`)
whose `userId` flows through `tools.get_transactions` into a raw f-string SQL
sink. Level 1 (verbatim `TaintSource`) finds the explicit SQLi (CWE-89); level 2
(the same source tagged `Via[llm_node]` at the framework boundary) reports it as
a cross-tool **implicit** flow (CWE-1426), trace `ToolOutput ==(history)==>
llm[node] ==(tool_calls)==> get_user_transactions`, triage true-positive 0.80.
The constant-`userId` `get_current_user -> get_user` path is correctly silent
(expected negative). This exercises the dataflow port on a real code path.

**AgentDojo (M2) — enumeration (registry + join@LLM).** Tools are isolated
functions; there is no code path between a source tool and a sink tool, so the
flow is enumerated over each suite's `TOOLS` registry and pruned with §4.5, then
scored against the suites' injection tasks. The same role prune discriminates on
all four suites by removing sources that are not attacker injection vectors
(the user's own data, factual lookups) and non-sensitive reads.

## Milestone status

- **M1 (pilot, DVLA):** done — pipeline + inter-procedural + implicit-flow tag
  confirmed on a real repo.
- **M2 (AgentDojo, all 4 suites):** done — recall + prune-reduction + ablation,
  aggregated here.
- **Pending:** real precision via the **defended-vs-undefended** comparison;
  aggregation already wired (`ctaudit/eval --real-corpus`); **M3** MCP pilot
  (`opena2a-org/damn-vulnerable-ai-agent`); **M4** dedicated negatives/FP study.

## Precision vs AgentDojo's own injection points (no manual labels)

AgentDojo does not ship a static per-(source→sink) safe/unsafe table, but it does
define **where** attacker text is placed (`injection_vectors.yaml`). Treating the
tools that surface those slots as the true injection vectors
(`corpus/agentdojo/injection_ground_truth.py`), a flagged pair is a true positive
iff its source is a real injection vector; otherwise it is a source-side over-flag.
Run: `ctaudit-eval --real-corpus --precision-vs-vectors`.

| suite | flagged | real-vector TP | over-flag FP | precision | over-flagged sources |
| --- | --- | --- | --- | --- | --- |
| banking | 20 | 10 | 10 | 50% | get_scheduled_transactions, get_user_info |
| workspace | 90 | 90 | 0 | 100% | — |
| travel | 30 | 18 | 12 | 60% | get_day_calendar_events, search_calendar_events |
| slack | 21 | 7 | 14 | 33% | read_channel_messages, read_inbox |
| **aggregate** | **161** | **125** | **36** | **78%** | — |

Caveat (rubric): an over-flag is a false positive **only relative to this
benchmark's chosen injection points** (e.g. travel injects only in reviews, not the
calendar; slack injects on web pages, not in channel messages). For a general
pre-deployment audit, flagging any attacker-readable free-form field is the
conservative, recall-preserving choice — so this is "precision vs AgentDojo
injection points", not an absolute precision. Recall over the tested attacks is
unaffected (still 18/18). This gives a meaningful precision figure with **no manual
labelling**; the LLM-triage / manual-label routes refine it further under the
broader threat model.

See `corpus/agentdojo/README.md` for the per-suite modeling and honesty notes,
and `docs/stage4_evaluation.md` for the full evaluation design.
