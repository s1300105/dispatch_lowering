# CLEANUP_PLAN — 自前データフローエンジン遺物の整理

作成: 2026-06-27  
目的: 削除済みの `ctaudit/` `benchmark/` パッケージへの参照を整理し、dispatch_lowering + TaintP2X 実証だけを残す。

## 不変条件（変更禁止）

| # | ファイル/ディレクトリ | 意味 |
|---|---|----|
| 1 | `taintp2x_extension/dispatch_lowering.py` | 自動 lowering 本体 |
| 2 | `taintp2x_m2_verification/` | AutoGPT M2 検証 (cond_A=0, cond_B=7) |
| 3 | `pysa/projects/sk_real/` | SK real 検証 (cond_A=0, cond_B=1, code 5001) |
| 4 | `evidence/sk_real_5001/`（存在する場合） | 証跡 |
| 5 | `taintp2x_m2_verification/ablation_helpers.py`, `run_ablation.sh` | ablation スクリプト |

**確認済み**: 上記ファイルはいずれも `ctaudit` / `benchmark` を Python import していない（文字列リテラルや print の中だけ）。

---

## フェーズ0 依存マップ（grep 結果要約）

### A. 削除対象 (git rm) — 壊れた Python ファイル

ctaudit/benchmark を直接 import しており、パッケージが存在しないため実行不能。

| ファイル | 依存内容 | 判定 |
|---|---|---|
| `hybrid.py` | `import ctaudit`, `postprocess` 多数 | **削除** |
| `agentdojo_all_suites.py` | `from ctaudit import render_html` | **削除** |
| `pysa/postprocess.py` | `ctaudit.analysis.pruning`, `ctaudit.labels`, etc. | **削除** |
| `scripts/triage_smoke.py` | `import ctaudit` | **削除** |
| `pyproject.toml` | `ctaudit` パッケージ定義（エントリポイント群）。pyre analyze も dispatch_lowering も不使用。 | **削除** |
| `tests/conftest.py` | `from ctaudit import Finding, analyze_path` | **削除** |
| `tests/test_agentdojo_coverage.py` | ctaudit import | **削除** |
| `tests/test_annotation.py` | ctaudit import | **削除** |
| `tests/test_anthropic_triage.py` | ctaudit import | **削除** |
| `tests/test_arg_reachability.py` | ctaudit import | **削除** |
| `tests/test_benchmark.py` | benchmark import | **削除** |
| `tests/test_collections.py` | ctaudit import | **削除** |
| `tests/test_cve_bench.py` | benchmark import | **削除** |
| `tests/test_discovery_scaling.py` | ctaudit import | **削除** |
| `tests/test_dispatch_resolution.py` | ctaudit import | **削除** |
| `tests/test_end_to_end.py` | ctaudit import | **削除** |
| `tests/test_eval.py` | ctaudit import | **削除** |
| `tests/test_flow_bench.py` | ctaudit import | **削除** |
| `tests/test_framework_dispatch_bench.py` | ctaudit/benchmark import | **削除** |
| `tests/test_framework_dispatch.py` | ctaudit import | **削除** |
| `tests/test_hybrid.py` | ctaudit import | **削除** |
| `tests/test_labels.py` | ctaudit import | **削除** |
| `tests/test_pruning.py` | ctaudit import | **削除** |
| `tests/test_pysa_postprocess.py` | postprocess import | **削除** |
| `tests/test_realworld_react_agent.py` | ctaudit import | **削除** |
| `tests/test_toolmodel.py` | ctaudit import | **削除** |

**合計**: 26 ファイル（Python 25 + pyproject.toml 1）

### B. legacy 隔離 (git mv → docs/legacy/) — 誤解を招く最上位ドキュメント

| ファイル | 理由 |
|---|---|
| `SETUP_AND_RUN.md` | 冒頭から `ctaudit` CLI のインストール・使い方を説明。そのまま読むと誤解を招く。 |

### C. 更新 (EDIT in place) — postprocess/ctaudit の言及のみ残るドキュメント・スクリプト

| ファイル | 更新内容 |
|---|---|
| `pysa/run_pysa.sh` | line 15 の `python3 postprocess.py ...` をコメントアウト |
| `pysa/setup_project.py` | docstring・print 内の `ctaudit` / `postprocess.py` 表記を修正 |
| `pysa/README.md` | postprocess 中心の記述を dispatch_lowering 中心に書き換え |
| `README.md` | `ctaudit` CLIツールの説明を dispatch_lowering + TaintP2X 実証の概要に書き換え |
| `pysa/projects/dvla/README.md` | `postprocess.py` ステップを削除またはコメント |
| `pysa/projects/http_provider_demo/README.md` | 同上 |
| `pysa/projects/recursion_demo/README.md` | 同上 |
| `pysa/projects/shellgpt_faithful/FINDINGS.md` | postprocess 参照をコメント/削除 |
| `docs/stage4_evaluation.md` | ctaudit/postprocess 参照に「(削除済み)」注記を追加 |
| `docs/stage4_results.md` | `ctaudit-eval` コマンド参照に注記追加 |
| `scripts/fetch_cve_corpus.sh` | echo 内の `benchmark.cve_bench` 参照を修正（シェルスクリプト・実行影響なし） |

### D. 触らない — ctaudit は文字列・コメントのみ、または不変条件

| ファイル/ディレクトリ | 理由 |
|---|---|
| `taintp2x_extension/dispatch_lowering.py` | 不変条件 1 |
| `taintp2x_m2_verification/` | 不変条件 2, 5 |
| `pysa/projects/sk_real/` | 不変条件 3, 4 |
| `fixtures/` | `ctaudit` Python import なし（`_postprocess` はメソッド名のみ） |
| `corpus/` | ctaudit import なし |
| `realworld/` | コメント 1 行のみ（import なし） |
| `gen_agentdojo_full_fixtures.py` | ctaudit import なし |
| `RESEARCH_DIRECTION.md` | 研究文脈テキスト（postprocess は言及のみ）。歴史記録として保存 |
| `FUSION4_DISPATCH_RESOLUTION.md` | 技術解説（ctaudit はコードスニペット例のみ）。歴史記録 |
| `docs/stage4_evaluation.md` (B section) | ※上記 C で注記追加のみ（削除しない） |
| `BENCHMARK_RESULTS.md`, `CVE_COMPARISON.md`, 等 | 研究ドキュメント。テキスト内 mention のみ |
| `AGENTDOJO_RECON.md`, `REAL_AGENTDOJO_VALIDATION.md`, 等 | 同上 |
| `pysa/models/`, `pysa/frameworks/`, `pysa/example/` | 解析モデル・フレームワーク定義 |
| `pysa/requirements.txt` | pyre-check 依存のみ |
| `pysa/projects/sk_inmemory/`, `pysa/projects/hybrid_demo/` | ctaudit import なし |
| `pysa/projects/README.md`, `SK_REAL_M2_GUIDE.md`, `REAL_CORPUS_EVAL.md` | postprocess 言及のみ or クリーン |
| `package.json`, `package-lock.json` | フロント不関連 |
| `.pyre/` | pyre キャッシュ |

---

## 実行順序

```
フェーズ1: git rm  (A 群: 26 ファイル)
フェーズ2: git mv  (B 群: 1 ファイル → docs/legacy/)
フェーズ3: 編集    (C 群: 11 ファイル)
フェーズ4: 不変条件確認
フェーズ5: git commit
```

### フェーズ1 コマンド (案)

```bash
# 壊れた Python ファイル
git rm hybrid.py agentdojo_all_suites.py pysa/postprocess.py scripts/triage_smoke.py pyproject.toml

# テストスイート全体
git rm tests/conftest.py \
       tests/test_agentdojo_coverage.py tests/test_annotation.py \
       tests/test_anthropic_triage.py tests/test_arg_reachability.py \
       tests/test_benchmark.py tests/test_collections.py \
       tests/test_cve_bench.py tests/test_discovery_scaling.py \
       tests/test_dispatch_resolution.py tests/test_end_to_end.py \
       tests/test_eval.py tests/test_flow_bench.py \
       tests/test_framework_dispatch_bench.py tests/test_framework_dispatch.py \
       tests/test_hybrid.py tests/test_labels.py \
       tests/test_pruning.py tests/test_pysa_postprocess.py \
       tests/test_realworld_react_agent.py tests/test_toolmodel.py
```

### フェーズ2 コマンド (案)

```bash
mkdir -p docs/legacy
git mv SETUP_AND_RUN.md docs/legacy/SETUP_AND_RUN.md
```

---

## 懸念事項・迷った点

1. **`pyproject.toml`**: `ctaudit` パッケージの定義のみ。`pip install -e .` が動かなくなるが、現状すでに ctaudit パッケージは存在しない。pyre analyze も dispatch_lowering.py も参照しないため削除可。
2. **`scripts/fetch_cve_corpus.sh`**: シェルスクリプトとしては動作する（clone 部分は正常）。echo の中の `benchmark.cve_bench` は「使い方の説明テキスト」なので、削除ではなく書き換えで対応。
3. **`realworld/botextract_react_agent.py`**: コメント 1 行のみ（`ctaudit reasons about`）。Python import なし。触らない。
4. **`corpus/agentdojo/`**: ctaudit import なし（README と csv だけ）。触らない。
5. **`SETUP_AND_RUN.md` の legacy 隔離**: 削除ではなく `docs/legacy/` に移動することで、git 履歴に残しつつ最上位から除去。

---

**この計画を確認後、フェーズ1から実行する。**
