# セットアップ & 実行ガイド（自分のPCで動かす）

`ctaudit` ：LLMエージェントの「クロスツール暗黙的フロー（CWE-1426）」をデプロイ前に
静的検出するツール。**2つの静的レッグ**を持つ：

- **標準エンジン**（純Python・依存なし）：join@LLM（§4.2）＋ 別名解決（part-A）＋
  動的ディスパッチ認識（part-B）＋ 枝刈り（§4.5）＋ トリアージ（§4.6）。
- **Pysaレッグ**（任意・`pyre-check` が必要）：手続き間＋再帰の値フローを健全に追う。
- **hybrid**：両レッグを1レポートに統合（`hybrid.py`）。

標準エンジンだけなら **Python 3.10+ と `pip install -e .` だけ**で動く。Pysaレッグを使う
ときだけ `pyre-check` を入れる。

---

## 1. 必要なもの

| 用途 | 要件 |
| --- | --- |
| 標準エンジン / eval / hybrid の標準レッグ | Python 3.10+（標準ライブラリのみ。外部依存なし） |
| Pysaレッグ（`pyre analyze` + `postprocess.py`） | `pip install pyre-check`（Linux/macOS。Pyre 0.9.25 で確認） |
| 実LLMトリアージ（任意） | `ANTHROPIC_API_KEY` など。無ければ決定的Mockに自動フォールバック |

---

## 2. フォルダ構成（主要部）

```
cross_tool_audit/
├─ pyproject.toml            # console scripts: ctaudit, ctaudit-eval
├─ README.md                 # プロジェクト概要
├─ SETUP_AND_RUN.md          # 本ファイル
├─ hybrid.py                 # ★ハイブリッド駆動（標準＋Pysaをマージ）
├─ ctaudit/                  # 標準エンジン本体（純Python）
│  ├─ __init__.py            #   analyze_path() などの公開API
│  ├─ cli.py                 #   `ctaudit <path>` 本体
│  ├─ labels.py              #   二層テイント＋join_to_ctl（§4.2 核心）
│  ├─ report.py              #   Finding / レポート整形
│  ├─ analysis/
│  │  ├─ taint_engine.py     #   AST前方解析・LLMノード・別名解決・part-B dispatch
│  │  ├─ collections.py      #   コレクション伝播＋不動点（§4.4）
│  │  └─ pruning.py          #   4枝刈り（§4.5）
│  ├─ models/
│  │  ├─ base.py             #   配線モデル（entry/bridge/exit/sink）＋名前解決
│  │  ├─ aliases.py          # ★別名/束縛解決（part-A）
│  │  ├─ langchain.py / mcp_sdk.py / openai_agents.py  # フレームワーク配線
│  │  └─ sinks.py            #   sink カタログ
│  ├─ triage/                #   LLMトリアージ（Mock/Anthropic/DeepSeek/OpenAI互換）
│  └─ eval/                  #   ベンチ実行（ctaudit-eval）
├─ fixtures/                 # 合成テストケース（9種）
├─ corpus/agentdojo/         # AgentDojo 列挙エンジン（実コーパス評価, レッグ(b)）
├─ tests/                    # pytest
└─ pysa/                     # ★Pysaレッグ（要 pyre-check）
   ├─ postprocess.py         #   Pysa出力 → ctaudit Finding（構造的に暗黙判定）
   ├─ example/agent.py       #   依存ゼロの動作確認ターゲット
   ├─ models/                #   taint.config + example.pysa
   └─ projects/
      ├─ recursion_demo/     #   手続き間＋再帰の実証（値スレッド／共有リスト）
      ├─ shellgpt_faithful/  #   shell_gpt構造を忠実再現（end-to-end点灯）
      └─ hybrid_demo/        #   ★ハイブリッドが各レッグ単独より優れる実証
```

---

## 3. インストール

```bash
cd cross_tool_audit
python3 -m venv .venv && source .venv/bin/activate     # 任意（推奨）
pip install -e .                                        # 標準エンジン（依存なし）
# Pysaレッグも使うなら：
pip install pyre-check
```

> 注：OSによっては `pip install -e .` に `--break-system-packages` が必要。

動作確認：
```bash
pytest -q          # 全テストがパスするはず
ctaudit-eval       # 合成ベンチ：pruned/triaged が recall 100%
```

---

## 4. 実行方法

### (A) 標準エンジン（純Python・これだけで動く）
```bash
ctaudit path/to/agent_repo            # ディレクトリでも単一ファイルでもOK
ctaudit fixtures/langchain_2tool_vuln.py
ctaudit path/to/repo --show-pruned    # 枝刈りされた候補も表示
ctaudit path/to/repo --json           # JSON出力
ctaudit path/to/repo --fail-on-finding  # CI用（検出があれば非ゼロ終了）
```

### (B) Pysaレッグ（手続き間＋再帰の値フロー、要 pyre-check）
各プロジェクトには `.pyre_configuration`（解析対象・モデルパス）が入っている。
```bash
cd pysa/projects/shellgpt_faithful
pyre analyze --save-results-to ./res        # Pysa本体（初回はやや時間がかかる）
python ../../postprocess.py ./res --implicit-only   # → CWE-1426 暗黙フローを表示
```
自前の依存ゼロ確認なら：
```bash
cd pysa && pyre analyze --save-results-to ./pysa-results
python postprocess.py ./pysa-results --implicit-only
```

### (C) ハイブリッド（標準＋Pysaを1レポートに統合）
```bash
# まず対象のPysa結果を作る
cd pysa/projects/hybrid_demo && pyre analyze --save-results-to ./res && cd -
# 両レッグをマージ（リポジトリ直下から実行）
python hybrid.py pysa/projects/hybrid_demo/src --pysa-results pysa/projects/hybrid_demo/res
```
→ `dispatchy.py`（標準エンジンが動的dispatchを検出）と `resolvable.py`（Pysaが
手続き間フローを検出）の**2件**が1レポートに出る（各レッグ単独なら1件ずつ）。

---

## 5. 自分のエージェントを検査する

- **手早く**：`ctaudit /path/to/your/agent`（標準エンジン）。自前 while ループ型の
  生SDKエージェントに有効。別名 `x = client.chat.completions.create` や
  `registry[name](...)` ／ `get_function(name)(...)` のディスパッチも拾う。
- **手続き間／再帰が絡むなら**：Pysaレッグを使う。`pysa/projects/shellgpt_faithful/`
  を雛形に、対象の `.pyre_configuration`・`models/*.pysa`（exit=LLM呼び出しを
  `TaintInTaintOut[Via[llm_node]]`、sink、必要なら履歴appendの `Updates`）を用意。
  重い依存（openai→pydantic等）は型チェックが重いので、`stubs/openai/__init__.pyi`
  のように最小スタブを置くと速い。
- **両方**：`hybrid.py` でマージ。

---

## 6. つまずきポイント

- `ctaudit: command not found` → `pip install -e .` を実行（venvを有効化）。
- **Pysa が `pyre analyze` の途中でクラッシュする**（`Base__Sys0.getenv` の
  バックトレース＋`Pyre exited with non-zero return code: 1`）→ 真の例外は
  `Analysis.ClassHierarchy.Untracked("dict")`：Pyre の型階層に**組み込み型
  （`dict` など）が無い** = typeshed/builtins が読めていない。`getenv` は
  クラッシュ処理側の二次失敗で原因ではない。**対処**：プロジェクトで
  `pyre init` を実行する（typeshed と site-packages を自動設定）か、
  `.pyre_configuration` に同梱 typeshed を明示する：
  ```json
  { "source_directories": ["src"],
    "taint_models_path": ["models"],
    "typeshed": "<pyre-checkの同梱typeshedパス>" }
  ```
  同梱パスは `find / -path '*pyre_check*typeshed*stdlib/builtins.pyi'` で探せる
  （例: `/usr/local/lib/pyre_check/typeshed`）。typeshed を入れると下の
  「list.append/subprocess が環境にない」問題も同時に解消し、stdlib の sink を
  直接モデル化できる。重い実リポ（termwise 等）で再現しやすい。
- Pysa が `list.append`/`subprocess` を「環境にない」と言う → 上と同じ原因。
  `typeshed` を設定すれば直接モデル化できる。設定しない簡易運用では、sink を
  ユーザ関数側でモデル化して回避（履歴appendは名前付きヘルパを `Updates` で）。
- Pysa が `pydantic` の型チェックで止まる → 重依存をスタブ化（`search_path` に
  最小 `stubs/` を置く）。`shellgpt_faithful/stubs/openai/__init__.pyi` が例。
- ディスパッチが検出されない → `get_function(name)(...)` が dict添字や `@classmethod`
  だと Pyre は解決しない。標準エンジン（part-B）か列挙レッグ(b)が担当する領域。

---

## 7. 共有ツールモデル（#5）・RQ4ベンチ・dispatch解決（#4）

### (D) 共有ツールモデルを生成（`ctaudit-toolmodel`）
リポのツールを **1つの共有モデル**に分類し、両レッグ向けに emit する（§6 fusion #5）。
```bash
# オフライン・決定的（鍵不要）
ctaudit-toolmodel path/to/repo --src-root path/to/repo/src --classifier heuristic --emit both

# LLMディスカバリ（dict-registry等、ヒューリスティックが見逃すイディオムを解錠）
#   recall優先のグラウンディング＋層またぎガード追跡が既定でON（--no-ground で無効化）
export DEEPSEEK_API_KEY=sk-...; export CTAUDIT_TOOLMODEL_MODEL=deepseek-chat
ctaudit-toolmodel path/to/repo --classifier deepseek --emit json     # 共有モデル(JSON)
ctaudit-toolmodel path/to/repo --classifier deepseek --emit enum     # レッグ(b) 列挙＋§4.5
ctaudit-toolmodel path/to/repo --classifier deepseek --emit pysa     # レッグ(a) .pysa
```
`--classifier` は `heuristic|anthropic|deepseek|openai|llm`。LLM系は `openai` パッケージ
（DeepSeek/OpenAI互換）または `anthropic` が必要：`pip install -e ".[triage]"`。
鍵/SDKが無い場合はヒューリスティック floor に自動フォールバック（recallを下げない）。

### (E) RQ4ベンチ（過適合の定量化＋LLMディスカバリの効果）
```bash
export CTAUDIT_CORPUS_BASE=/path/to/corpus        # 7リポの展開先（同梱 corpus_repos.zip）
# ヒューリスティック（held-out recall 0% = イディオム特化を定量化）
python -m benchmark.run_benchmark --classifier heuristic
# 実LLM（DeepSeek）：held-out recall 0→100%
export DEEPSEEK_API_KEY=sk-...; export CTAUDIT_TOOLMODEL_MODEL=deepseek-chat
python -m benchmark.run_benchmark --classifier deepseek --repeat 10          # 分布（mean±popstdev[min–max]）
python -m benchmark.run_benchmark --classifier deepseek --repeat 10 --no-ground   # グラウンディング無し（before）
# 鍵なしでLLMロジックを確認（捕捉済みJSONを再生）
python -m benchmark.run_benchmark --classifier replay
```
`--repeat N` は N回回して recall/precision/role/sink-cat/**guard-presence** を分布で報告し、
どのツールが実行ごとにぶれるか（recall/precision instability）も一覧する。

### (F) dispatch解決（fusion #4）
データフロー・レッグが局所化した動的dispatchの壁（`kind="dispatch"`）を、共有ツール
モデルで具象シンクへ解決する。
```bash
python -m pytest tests/test_dispatch_resolution.py -q        # デモ＋recall安全性
```
コードからの最小例：
```python
from ctaudit import analyze_path
from ctaudit.analysis import resolve_dispatch
from ctaudit.toolmodel import get_classifier
findings = analyze_path("app.py").findings                   # レッグa（dispatch壁を含みうる）
model    = get_classifier("deepseek").classify("repo")       # 共有モデル（#5）
resolved = resolve_dispatch(findings, model)                 # #4: 壁→命名済み・ガード付き具象シンク
```
詳細は `FUSION4_DISPATCH_RESOLUTION.md`。
