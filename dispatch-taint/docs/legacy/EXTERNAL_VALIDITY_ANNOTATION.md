# External validity — independent annotation & inter-annotator agreement (RQ4)

The tool-classifier gold (`benchmark/labels.py::GOLD`) is **single-annotator**, which is a
threat to validity for the recall/precision claims. This component lets a **second,
independent annotator** label the same repos so we can report **Cohen's κ** (inter-annotator
agreement) and **annotator-vs-tool** agreement, rather than trusting one labeler.

Everything except the 2nd annotator's judgments is deterministic: the candidate pool, the
GOLD/MODEL sheets, and the κ computation are reproducible (`ctaudit-annotate`,
`benchmark/annotation.py`, `tests/test_annotation.py`).

## Unit of annotation — the candidate pool

The fixed unit is a **candidate** = every **public** `function` / `method` / `class` in the
repo source (`tests/`, private `_name`, and dunder excluded). The pool is produced
deterministically by AST (`candidate_pool`), so both annotators (and the model) label the
**same** set, matched by qualified name.

For class-based tools the tool name differs from the class/def name, so each candidate also
carries `match_names` — the names it may be **registered** under: the class name, a
class-level `name = "…"` / `name: str = "…"` attribute, a `@property def name(): return "…"`,
and the `"name"` key of a dict in a schema method (`openai_schema`, `args_schema`, …). A gold
tool maps to the candidate whose `match_names` contains it. `coverage_check` (and
`ctaudit-annotate coverage`) reports any gold tool that fails to map — on the current corpus
**all** gold tools map (shellgpt 2/2, termwise 4/4, codecli 5/5; the precision repos have no
gold tools by design), so the GOLD sheet is faithful.

## Label schema

Per candidate, each annotator fills:

| column | values | meaning |
|---|---|---|
| `is_tool` | `Y` / `N` | is this an LLM-exposed / registry tool? |
| `role` | `source` / `sink` / `both` / `none` | data role for cross-tool flow |
| `sink_category` | `network` / `code_execution` / `file_write` / `sql` / `deserialize` / `none` | sink kind |
| `guarded` | `yes` / `no` / `na` | is the dangerous call behind a confirmation/guard? (`na` if not a sink) |

The `signature` and `file:line` columns are provided to make labeling possible without
running the agent.

## Blinding

The 2nd annotator receives a **BLANK** sheet (`emit`) — the candidate pool with empty label
columns, **no gold, no model output, and no marker of which rows are gold-positive** (the
sample is shuffled by seed). This keeps their judgments independent.

## Workflow

```bash
export CTAUDIT_CORPUS_BASE=/path/to/corpus

# 0. (sanity) every gold tool maps to a candidate
ctaudit-annotate coverage --repo codecli

# 1. blank sheet for the 2nd annotator (sample to bound effort; gold tools always kept)
ctaudit-annotate emit  --repo codecli --sample 40 --seed 0 --out codecli.blank.csv

# 2. annotator #1 sheet, auto-derived from GOLD  (SAME --sample/--seed = aligned rows)
ctaudit-annotate gold  --repo codecli --sample 40 --seed 0 --out codecli.gold.csv

# 3. the 2nd annotator fills codecli.blank.csv  ->  codecli.annot2.csv

# 4. inter-annotator agreement
ctaudit-annotate kappa --a codecli.gold.csv --b codecli.annot2.csv

# optional: agreement of each annotator with the tool (heuristic or LLM) classifier
ctaudit-annotate model --repo codecli --classifier deepseek --sample 40 --seed 0 --out codecli.model.csv
ctaudit-annotate kappa --a codecli.gold.csv  --b codecli.model.csv      # gold   vs model
ctaudit-annotate kappa --a codecli.annot2.csv --b codecli.model.csv     # 2nd-annotator vs model
```

Use the **same `--sample` and `--seed`** for `emit`, `gold`, and `model` so the three sheets
cover the identical candidate set; `kappa` matches rows by qualified name regardless.

## Reading the κ report

`kappa` prints, matched/only-a/only-b counts and then per dimension:

```
is_tool        : kappa=0.91  po=0.98  n=148
role           : kappa=…  po=…  n=148   | tools-only: kappa=…  po=…  n=12
sink_category  : …                       | tools-only: …
guarded        : …                       | tools-only: …
```

* `po` (raw agreement) and `n` are reported alongside κ, because κ can be deflated by skewed
  marginals (most candidates are non-tools).
* `role` / `sink_category` / `guarded` are also reported on the **tools-only** subset (rows
  where *either* annotator marked `is_tool=Y`), which is the agreement that matters for the
  flow labels; the full-pool figure is dominated by the easy `none`/`na` agreements.
* Reference bands (Landis & Koch): κ > 0.80 almost perfect, 0.61–0.80 substantial.

A worked sanity point: on held-out **codecli**, `gold` vs the **heuristic** model gives
`is_tool κ = 0` (the heuristic recovers none of codecli's dict-registry tools), matching the
RQ4 story; `gold` vs the **DeepSeek** model is expected to be near-perfect (the LLM recovers
them). The headline external-validity number is `gold` vs the **2nd human annotator**.

## Scope / threats

* The candidate pool is the source-level def set; a tool synthesised entirely at runtime
  (no def) is out of scope (as it is for the classifier).
* κ is over the (optionally sampled) pool; report the sample size and seed. For a fixed
  effort budget, sampling keeps gold-positive candidates and draws negatives reproducibly.
* This measures agreement on **labels given the pool**; it does not by itself establish that
  the pool enumerates every tool — pair it with the idiom coverage discussion.
