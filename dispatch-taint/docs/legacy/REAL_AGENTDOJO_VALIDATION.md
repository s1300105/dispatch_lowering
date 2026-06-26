# 本物の AgentDojo 実コードでの検証 — 中間整理

最終更新: 2026-06-05

## 目的

これまでの検証は、AgentDojo の構造を再現した「縮約 fixture / フル版 fixture」
(模型) を解析対象にしていた。本節では、GitHub で公開されている**本物の
AgentDojo 実コード** (`ethz-spylab/agentdojo`, MIT ライセンス) を直接解析し、
模型での結果が本物でも再現するかを検証した。

## 本物の構造（模型との違い）

模型は、壁・ツール一覧・ツール実体を 1 ファイルに圧縮していた。本物は 4 つに
分かれている:

| 役割 | 本物のファイル |
|------|----------------|
| ディスパッチの壁 (`runtime.run_function(env, name, args)`) | `agent_pipeline/tool_execution.py` |
| 壁の実装 (`self._functions[name]` を引く) | `functions_runtime.py` |
| ツール一覧の登録 (`TOOLS = [...]`) | `default_suites/v1/<suite>/task_suite.py` |
| ツールの実体 (関数定義) | `default_suites/v1/tools/<*>_client.py` |

本物のツールは `make_function(tool)` でラップされ、`Annotated[..., Depends(...)]`
の依存性注入デコレータで装飾される。引数も本物の形 (`send_money(recipient,
amount, subject, date)` など)。

## 外部正解 (injection_vectors) の検証

本物の `data/suites/banking/injection_vectors.yaml` は、ツール名のリストではなく
**注入スロット** (`injection_bill_text`, `injection_incoming_transaction` など) と
そのデフォルト文面を定義していた。これらが `environment.yaml` のどこに埋め込まれる
かを追ったところ:

- `injection_incoming_transaction` → 取引の `subject` → `get_most_recent_transactions` が読む
- `injection_bill_text` / `injection_landloard_notice` / `injection_address_change`
  → `.txt` ファイルの内容 → `read_file` が読む

よって、本研究が使ってきた「banking のベクトル = `get_most_recent_transactions`,
`read_file`」という対応づけは、**本物の environment.yaml に照らして正しい**ことを
確認した。外部正解の対応づけは恣意的ではなく、本物のデータ構造に根拠がある。

## 達成できたこと

1. **本物の壁の検出**: 本物の `tool_execution.py` から、ディスパッチの壁
   (`runtime.run_function`) を構文的に検出できた。

2. **ファイルをまたぐ解決**: 壁 (`tool_execution.py`) とツール登録
   (`task_suite.py`) が別ファイルにある本物の構造で、リポジトリ全体を解析し、
   分類器が回収したツール一覧を壁の候補集合に補完することで、壁を具体的な
   危険シンクに解決できた。本物の `src/agentdojo` 全体で **16 種類の危険シンク
   すべてに解決、未解決の壁ゼロ、解決検出 48 件**。

3. **本物での採点**: 本物の banking スイートを単体で解析し、injection_vectors で
   採点できた。**解決+ソース展開で TP=20 / FP=20 / FN=0 / recall 100% /
   precision 50%**。模型 banking (TP=10/FP=10/precision 50%) と同じ傾向で、
   本物でも recall を完全回復できることを確認した。

## 判明した本物特有の課題（今後の作業）

1. **分類器のツール取りこぼし**: 本物の banking は 11 ツールあるが、分類器は
   9 ツールしか抽出できなかった。`get_balance` (引数なし・float 返し) と
   `get_iban` (引数なし・str 返し) が漏れた。これらは「引数を取らない単純な
   ゲッター」で、分類器のソース/シンク判定ヒューリスティックの基準に合わな
   かったため。本物の多様な実装パターンへの対応が必要。

2. **本物で静的枝刈りが効かない**: 上記の取りこぼしの結果、`trusted-readonly`
   (attacker=False) のソース (`get_balance`, `get_iban`) が展開ソースに含まれず、
   ロール枝刈り (§4.5(3)) の対象が無くなった。このため本物では TN=0、枝刈りで
   precision が上がらない (模型では get_balance/get_iban を抑制して TN=10、
   precision 維持)。分類器が全ツールを拾えれば、模型と同じく枝刈りが効くはず。

3. **ソースのロール判定がメタデータ依存**: 展開時のソースの role
   (attacker-influenced / trusted-readonly) は、現状 `analyze_<suite>.py` の
   メタデータ (AgentDojo の attacker フラグ) に依拠している。本物のツール実装
   からの自動判定は未対応。

4. **ガードの検証が未着手**: 本物の AgentDojo は `--defense tool_filter` など
   防御機構を持つ (attack と defense が独立コンポーネント)。現状の解析はこの
   防御機構を対象に含めておらず、すべて guard: NONE。「ガードされていない危険な
   経路を脆弱性として検出する」という目的に対し、ガード有無で検出が変わるかの
   検証が今後必要。

## 位置づけ

本物検証により、これまでの最大の弱点だった「模型でしか動かない」状態を脱し、
実在のベンチマークの実コードで壁を検出・解決・採点できることを示した。一方で、
模型では見えなかった本物特有の難しさ (分類器の取りこぼし、ガードの未対応) が
具体的な課題として明確になった。これらの課題自体が、本物検証によって初めて
得られた知見である。
