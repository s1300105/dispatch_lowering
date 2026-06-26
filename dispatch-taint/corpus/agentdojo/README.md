# M2: AgentDojo (Stage-4 corpus)

This folder runs the cross-tool implicit-flow audit on **AgentDojo** (ETH SpyLab),
the scaled, labelled Stage-4 target. It covers all four default suites:
**banking**, **workspace**, **travel**, and **slack**.

```
corpus/agentdojo/
  _common.py             shared enumeration + §4.5 prune + scoring (imported by the analyzers)
  analyze_banking.py     banking registry (11 tools)   -> _common.analyze
  analyze_workspace.py   workspace registry (24 tools)  -> _common.analyze
  analyze_travel.py      travel registry (28 tools)     -> _common.analyze
  analyze_slack.py       slack registry (11 tools)      -> _common.analyze
  labels_banking.csv     ground-truth pairs from the 9 banking injection tasks
  labels_workspace.csv   ground-truth pairs from the 6 workspace injection tasks
  labels_travel.csv      ground-truth pairs from the 7 travel injection tasks
  labels_slack.csv       ground-truth pairs from the 5 slack injection tasks
  README.md              this file
```

Each `analyze_<suite>.py` is a thin file: it declares the suite's real tool
registry as `SOURCES`/`SINKS` metadata (transcribed from AgentDojo's source) and
calls `analyze()` in `_common.py`. Adding a suite = adding one such pair of files.

## Why this is NOT a Pyre/Pysa run (important)

In AgentDojo, tools are isolated functions registered in a suite's `TOOLS` list
(see `default_suites/v1/banking/task_suite.py`). There is **no code dataflow**
between a source tool (e.g. `get_most_recent_transactions`, whose returned
transaction `subject` carries attacker-injected text) and a sink tool (e.g.
`send_money`): the only thing linking them is the **LLM's routing inside
AgentDojo's runtime**. So a dataflow analysis — even the inter-procedural Pysa
port that worked on DVLA — finds nothing, because source and sink never touch in
code.

The cross-tool implicit flow here is a property of the **tool registry + the
join-at-LLM semantics** (proposal §4.2 wiring + §4.4 join): any co-registered
(source, sink) pair is a candidate, because the LLM can route any source output
to any sink input. This is exactly the *standalone* ctaudit layer, so M2 uses an
enumeration + §4.5 prune approach rather than Pyre.

Net: **DVLA (M1)** had a code path (tool input → SQL sink) → the Pysa port
applies. **AgentDojo (M2)** has no code path; the flow is registry + LLM-join →
the standalone enumeration applies. The two real targets exercise the two
implementations.

## Run

```bash
# from the repo root (needs nothing but Python 3.10+; no AgentDojo install)
python corpus/agentdojo/analyze_banking.py
python corpus/agentdojo/analyze_workspace.py
python corpus/agentdojo/analyze_travel.py
python corpus/agentdojo/analyze_slack.py
# or point at a different label file:
python corpus/agentdojo/analyze_slack.py corpus/agentdojo/labels_slack.csv
```

## Results so far

| suite     | tools | raw (S×K) | pruned | recall | discriminating prune (ablation) |
|-----------|-------|-----------|--------|--------|---------------------------------|
| banking   | 11    | 30        | 20     | 4/4    | role (−5: own-iban, numeric balance) |
| workspace | 24    | 140       | 90     | 5/5    | role (−40: own/sent/draft mail, contacts, date) |
| travel    | 28    | 132       | 30     | 3/3    | role (−48: PII, names/addresses, prices, enums) |
| slack     | 11    | 35        | 21     | 6/6    | role (−14: channel list, user list) |
| **total** | —     | **337**   | **161**| **18/18** | role is the discriminator on every suite |

Across all four suites: pruning drops **no** tested attack path (recall 100%, 18/18);
on every suite the **role** prune is the discriminator while schema/reachability/
hiding have zero *marginal* effect (their targets are already role-pruned, or the
suite has no constrained-capacity sink / dead code / `hide()` helper — schema does
share the work on the source side, it just overlaps role here). The pruned counts
are candidate sets for the §4.6 LLM triage, **not** precision figures (see the
honesty note below).

## What it reports (and how to read it)

- **raw candidates**: every co-registered (source × sink) pair (the join@LLM
  cross-product).
- **after §4.5 pruning**: candidates surviving reachability / schema-capacity /
  role / hiding.
- **recall on tested positives**: of the ground-truth exploitable pairs (from the
  injection tasks), how many survive pruning. This is the headline soundness
  check — pruning must not drop a real attack path. It is 100% on every suite
  (18/18 across all four).
- **ablation**: flows when each prune is disabled (RQ2). On every suite the
  **role** prune is the discriminator (it removes sources that are not attacker
  injection vectors — the user's own data, factual lookups — and sinks that are
  not sensitive); schema removes low-capacity sources (numbers, dates, enums) but
  here those are also role-pruned, so its *marginal* effect is zero; reachability
  and hiding become active on suites with dead code or `hide()` helpers.
- **surviving-but-untested**: pairs we flag that have no injection task. These
  are **candidates, not false positives** — AgentDojo simply did not test them.

## Honesty / threats to validity

AgentDojo labels POSITIVES well (the injection tasks) but does **not** enumerate
all *safe* pairs, so a flagged-but-untested pair is not a proven FP. True
precision/FP needs either (a) the **defended-vs-undefended** comparison (run with
AgentDojo's defenses and check the tool's flags shrink appropriately), or (b) a
**manually completed label set** marking the remaining pairs safe/unsafe. Each
label CSV includes a few hand-added `label=0` negatives (e.g. `get_balance`,
`get_iban`, `get_user_information`, `get_channels`) that the prunes should — and
do — drop.

The injection-endpoint → source attribution uses each suite's canonical vector:
banking = the transaction `subject` (`get_most_recent_transactions`); workspace =
the received-email body (`get_received_emails`; `search_emails` for the
search-then-send tasks); travel = a planted review (`get_rating_reviews_for_hotels`);
slack = a posted message (`read_channel_messages`). Refine by inspecting a suite's
injection points if needed.

## RQ3 / precision workflow (LLM triage)

The aggregator (`ctaudit/eval/real_corpus.py`) also runs the §4.6 LLM triage on
each suite's flagged set and reports the 3-stage view. Workflow:

```bash
# 1. dump the flagged candidate set per suite (for inspection / labelling)
python -m ctaudit.eval --real-corpus --dump-flagged corpus/agentdojo/generated

# 2. emit manual-labelling templates (every flagged pair; `label` blank to fill,
#    tested positives pre-filled, plus tool_rule_guess + mock_triage references)
python -m ctaudit.eval --real-corpus --emit-label-templates   # writes labels_<suite>_full.csv here

# 3. RQ3 experiment with the mock backend (offline, deterministic)
python -m ctaudit.eval --real-corpus --triage mock
#    …and a controlled variant that leaves residual FPs for the triage to remove:
python -m ctaudit.eval --real-corpus --triage mock --prune-config no-role

# 4. RQ3 with a real LLM (needs `pip install -e ".[triage]"` + a provider key)
#    Anthropic (Claude):
ANTHROPIC_API_KEY=... python -m ctaudit.eval --real-corpus --triage anthropic --runs 5
#    DeepSeek (OpenAI-compatible; key = DEEPSEEK_API_KEY):
DEEPSEEK_API_KEY=... python -m ctaudit.eval --real-corpus --triage deepseek --runs 5 --emit-verdicts corpus/agentdojo/generated
#      default model = deepseek-chat (DeepSeek-V3). The V4 ids are deepseek-v4-flash /
#      deepseek-v4-pro; deepseek-chat & deepseek-reasoner retire 2026-07-24, so:
DEEPSEEK_API_KEY=... python -m ctaudit.eval --real-corpus --triage deepseek --model deepseek-v4-flash --runs 5
#    OpenAI: --triage openai (OPENAI_API_KEY). Any other OpenAI-compatible endpoint:
#      --triage openai-compat with CTAUDIT_TRIAGE_BASE_URL / _API_KEY / _MODEL.
#    once labels_<suite>_full.csv are filled in, get full-corpus precision:
DEEPSEEK_API_KEY=... python -m ctaudit.eval --real-corpus --triage deepseek --full-labels corpus/agentdojo/generated
```

What the mock run reveals (a real, honest RQ3 motivation): the mock heuristic
keys on whether the sink's argument is a free-form string, so it **wrongly drops
enum-argument destructive sinks** — `delete_file`, `delete_email` (workspace),
`add_user_to_channel`, `remove_user_from_slack` (slack) — even though those are
labelled exploitable. Mock recall@triaged is therefore ~78% (it loses 4 tested
positives). The open question for the real LLM: does it (a) recover those
destructive-sink positives (recall back to 100%) and (b) under `--prune-config
no-role`, drop the role-type false positives the cheap rules let through
(precision up)? That comparison is RQ3.

Precision with NO manual labels (recommended first): AgentDojo's own
`injection_vectors.yaml` says where attacker text is placed, so the tools that
surface those slots are the true injection vectors
(`injection_ground_truth.py`). Score the flagged set against them:

```bash
python -m ctaudit.eval --real-corpus --precision-vs-vectors
```

A flagged pair whose source is a real injection vector is a true positive; one
whose source is not (e.g. travel calendar readers, slack channel/inbox readers —
the slack payload is on a web page, not in messages) is a source-side over-flag.
Result: banking 50%, workspace 100%, travel 60%, slack 33%, aggregate 78%. This
is a false positive ONLY relative to this benchmark's chosen injection points; for
a general audit, flagging any attacker-readable free-form field is the conservative
choice. Recall over the tested attacks stays 18/18.

Manual-labelling protocol (Step 2 → full-threat-model precision): fill the blank `label` in
each `labels_<suite>_full.csv` by judging **exploitability from the AgentDojo tool
docstrings**, independently of the tool's own §4.5 rules (do not just copy
`tool_rule_guess` — that would be circular). Record a short reason in `notes`.
Where the human label diverges from the tool's flag is exactly the tool's
false-positive set; that is what makes the precision number meaningful.

## Other remaining work
- **Aggregate (RQ1/RQ2)**: feed the per-suite results into `ctaudit/eval` (the
  real-corpus mode described in `docs/stage4_evaluation.md` §8) to produce the
  cross-suite recall / prune-reduction / ablation tables, alongside the DVLA
  (Pysa-port) pilot.
- **More targets**: the MCP pilot (`opena2a-org/damn-vulnerable-ai-agent`, M3) and
  a dedicated negatives/FP study (M4).
