# Pilot (M1): ReversecLabs/damn-vulnerable-llm-agent

This folder holds everything to run the cross-tool implicit-flow audit on the
**Damn Vulnerable LLM Agent** (DVLA), the first Stage-4 target.

```
projects/dvla/
  taint.config           sources/sinks/features/rules (self-contained copy)
  dvla.pysa              models tailored to DVLA (SQL sinks + tool-input source)
  labels.csv             ground-truth: the two CTF flags (+ one negative)
  pyre_configuration.dvla  config template (edit source_directories, then use)
```

## What DVLA is (and why it's a good first target)

A LangChain ReAct agent (`ConversationalChatAgent` + `AgentExecutor`, LLM =
`ChatLiteLLM`) with two tools registered via `Tool(func=...)`:
`get_current_user` and `get_transactions`. `get_transactions(userId)` calls
`TransactionDb.get_user_transactions`, which builds **raw SQL by f-string** and
runs it — a SQL sink. The agent chooses `userId`. The CTF has two flags: (1)
steer the agent to read `userId=2`'s rows; (2) SQL-inject via the `userId`
argument to leak DocBrown's password.

**Honest note.** In a ReAct agent the "LLM output → tool argument" wiring lives
**inside** LangChain's `AgentExecutor`, not in user code — that is why
`setup_project.py` finds no `.invoke` and no `@tool` here (only the framework
constructs in section `[1b]`). Two levels of demonstration follow.

## Steps (run on your machine, where pyre + the deps are installed)

```bash
# 1) clone the target
git clone https://github.com/ReversecLabs/damn-vulnerable-llm-agent.git ~/dvla

# 2) install ITS dependencies into the same venv so Pyre can resolve imports
#    (langchain, langchain-litellm, streamlit, ...). Required for a clean run.
pip install -r ~/dvla/requirements.txt

# 3) point Pyre at the clone: edit source_directories in this template to the
#    absolute path, then put it where Pyre will read it (back up the example one)
cd /path/to/cross_tool_audit/pysa
sed -i "s#/ABSOLUTE/PATH/TO/damn-vulnerable-llm-agent#$HOME/dvla#" projects/dvla/pyre_configuration.dvla
cp .pyre_configuration .pyre_configuration.example.bak   # keep the example config
cp projects/dvla/pyre_configuration.dvla .pyre_configuration

# 4) check the models verify against DVLA, then analyse
pyre validate-models
pyre analyze --save-results-to ./pysa-results-dvla

# 5) restore the example config when done
cp .pyre_configuration.example.bak .pyre_configuration
```

If model verification ever blocks the run, add `--no-verify` to `pyre analyze`.

## What to expect

- **LEVEL 1 (default in `dvla.pysa`)** — an **explicit** SQL finding (code 9002):
  `tools.get_transactions(userId)` → `TransactionDb.get_user_transactions` (SQL).
  This validates the pipeline end-to-end on real code and the general
  inter-procedural flow (across `tools.py` → `transaction_db.py`). It corresponds
  to the SQL-injection path of the CTF (flag 2). It is *explicit* because no LLM
  node sits on this user-code path.
- **LEVEL 2 (switch the source line in `dvla.pysa`)** — tagging the tool input
  `Via[llm_node]` reclassifies the same flow as **implicit (CWE-1426)**, modeling
  the fact that the argument is LLM-routed by the AgentExecutor. Use this to
  demonstrate the cross-tool implicit detection on a real ReAct agent. Document
  the modeling choice (asserting `llm_node` at the framework boundary).

## Scoring against labels

`labels.csv` lists the ground-truth dangerous pair (label 1) and one expected
negative (label 0). Compare with `findings.json` by `(source_tool, sink_tool)`:
the LEVEL-2 run should report the labelled-1 pair (true positive) and stay silent
on the labelled-0 pair (no false positive). This is the first real, non-circular
data point for RQ1/RQ2 and the seed for the `ctaudit/eval` real-corpus mode
described in `docs/stage4_evaluation.md`.
