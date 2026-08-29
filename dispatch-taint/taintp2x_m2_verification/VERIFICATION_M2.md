# VERIFICATION_M2 — TaintP2X M2 レベルでの動的ディスパッチ壁越え検証

本書は、TaintP2X（ICSE 2026）の静的テイント伝播（M2）に、動的ディスパッチ解決
（lowering）を前処理として外付けした効果を、実在の AutoGPT に対して検証した記録
である。検証は実機で再現済み（後述のステータス参照）。再現は同じフォルダの
`reproduce_m2.sh` を実行するだけで完結する。

## ステータス（再現確認済み）

- 結果: 条件A（lowering 無し）= **Found 0 issues** → 条件B（lowering 有り）= **Found 7 issues**
- 再現方式: 素の AutoGPT `agent.py` に `dispatch_lowering` を適用して cond_B を
  動的に生成する方式（静的に保存済みのファイルを読むのではなく、毎回作り直す）
- 確認環境: Python 3.12.3、pyre-check（`.venv`）、AutoGPT コミット `9210d44`
  （タグ autogpt-platform-beta-v0.5.0）
- 再現コマンド: `taintp2x_m2_verification/` で `./reproduce_m2.sh`
- 検証の位置づけ: TaintP2X の 4 モジュール（M1 source 識別／M2 静的テイント伝播／
  M3 controllability／M4 LLM 検証）のうち **M2 レベル**。lowering の貢献は M2 で生じる。

---

## 1. 何を検証したか

LLM エージェント AutoGPT（autogpt-platform-beta-v0.5.0、TaintP2X Benchmark 対象版）
の `agent.py` には、LLM が選んだツール名で動的にコマンドを実行する壁がある。

```python
command = self._get_command(tool_call.name)   # LLM 出力で関数を選ぶ
result = command(**tool_call.arguments)        # 動的ディスパッチ（壁）
```

この `command` は実行時まで実体が決まらず、コールグラフに辺が無い。そのため
TaintP2X の M2（Pysa による静的テイント伝播）は、`tool_call`（LLM 由来 = source）
から、解決先 `code_executor.py` の `@command` メソッド内の `subprocess`（RCE sink）
まで、テイントを運べない。

lowering は、この壁の直後に、到達しうる `@command` メソッド 4 つへの直接呼び出しを
`if False:` ブロックとして挿入する。実行時の振る舞いは変えず（`if False` なので
決して実行されない）、Pysa の静的なデータフローにだけ、壁を越える辺を与える。

解決先の `@command` メソッド 4 つ（`dispatch_lowering` が AutoGPT の code_executor
コンポーネントから自動収集）:

- `execute_python_code`
- `execute_python_file`
- `execute_shell`
- `execute_shell_popen`

---

## 2. 比較設計（差は lowering の有無のみ）

| 条件 | agent.py | code_executor.py | source 宣言 | 解析設定 |
|---|---|---|---|---|
| A（baseline） | 素のまま | 同一 | 同一 | 同一 |
| B（+lowering） | lowering 挿入 | 同一 | 同一 | 同一 |

両条件とも、TaintP2X の taint 定義（`Taint_Propagation/taint`）・stubs・typeshed を
使い、`pyre analyze --no-verify` で解析する。TaintP2X 本体（`run_download_and_check.py`）
には一切手を触れない。lowering は clone したソースへの前処理として完全に外付け。

source 宣言（`source/autogpt_v05.pysa`、両条件で同一）:

```
def agent.Agent._execute_tool(self, tool_call: TaintSource[LLMControlled]): ...
def subprocess.run(args: TaintSink[RemoteCodeExecution], **kwargs): ...
def subprocess.Popen.__init__(self, args: TaintSink[RemoteCodeExecution], **kwargs): ...
```

---

## 3. 結果

```
条件A（lowering 無し）: Found 0 issues
条件B（lowering 有り）: Found 7 issues
```

条件 B の 7 件の内訳（すべて callable = `agent.Agent._execute_tool`）:

| code | ルール名 | source → sink | 件数 |
|---|---|---|---|
| 5005 | Possible ExecArgSink | LLMControlled → ExecArgSink | 4 |
| 5001 | Possible RemoteCodeExecution | LLMControlled → RemoteCodeExecution | 3 |

差分検証: `diff cond_A/src/agent.py cond_B/src/agent.py` は、`result = command(...)`
（277 行目）の直後への 5 行挿入のみを示す。

```
277a278,282
>             if False:  # [ctaudit] resolved dynamic dispatch -> 4 targets
>                 CodeExecutorComponent.execute_python_code(code=tool_call.arguments)
>                 CodeExecutorComponent.execute_python_file(filename=tool_call.arguments, args=tool_call.arguments)
>                 CodeExecutorComponent.execute_shell(command_line=tool_call.arguments)
>                 CodeExecutorComponent.execute_shell_popen(command_line=tool_call.arguments)
```

`code_executor.py` と `source/autogpt_v05.pysa` は両条件で完全に同一（diff で確認）。
つまり、検出件数 0 → 7 の差は、**lowering の有無だけ**に起因する。

実機での実行ログ（要点）:

```
=== 2. cond_A を TaintP2X M2（Pysa）で解析 → 0 issues を期待 ===
ƛ  Found 0 issues
=== 3. cond_B を cond_A から複製し、dispatch_lowering を適用 ===
[ctaudit] 収集した @command メソッド数: 4
[ctaudit] lowering 適用後の行数: 318
=== 5. cond_B を同じ設定で解析 → 7 issues を期待 ===
ƛ  Found 7 issues
=== 6. 検出 issue の内訳 ===
  code 5001 (RemoteCodeExecution): 3 件
  code 5005 (ExecArgSink): 4 件
  agent.Agent._execute_tool: 7 件
```

---

## 4. 主張範囲（誠実な限定）

正確に言えること:
- TaintP2X の M2（静的テイント伝播）は、LLM の動的ディスパッチの壁で、自身の
  RCE ルールを発火できない（条件 A = 0）。
- lowering は壁を解決し、TaintP2X 自身の taint 定義で、LLM 由来データの
  コード実行 sink への到達を検出可能にする（条件 B = 7）。
- 差は lowering の有無のみ（diff で証明）。
- これは TaintP2X 論文が Limitations で認める「リフレクション・動的 import・
  実行時コード生成などの暗黙的テイント伝播を静的解析エンジンが追えない」という
  M2 の限界に直接対応する。

慎重に述べるべきこと:
- 本検出は「攻撃者影響下データがコード実行 sink に到達する」到達可能性であり、
  個々の `@command` 実装の欠陥そのものを理解した検出ではない。したがって
  「特定 CVE を検出した」と単純化せず、「TaintP2X が動的ディスパッチの壁により
  見逃すコード実行経路への到達を、lowering により検出する」と述べるのが正確。
- 本検証は M2 レベル。M1（source 識別）・M3（controllability）・M4（LLM 検証）は
  含まない。これらは主に FP を減らすモジュールであり、lowering の貢献（壁を越えて
  検出する）とは独立な軸。本研究の貢献は M2 レベルで生じる。
- 件数 7 は TaintP2X の正式 taint 定義（sink の粒度が細かい）での値。簡易な
  手書き source/sink（subprocess のみ）では 3 だった。同じ壁越え経路の検出であり、
  差は sink 定義の粒度による。主たる数字は正式定義の 7 とする。
- 評価規模は現状 AutoGPT 1 例。複数フレームワークでの ablation 集計は今後の作業。

---

## 5. 再現手順

同じフォルダの `reproduce_m2.sh` を実行する。スクリプトは次を自動で行う。

1. 前提（pyre、TaintP2X taint 定義、typeshed、dispatch_lowering、AutoGPT クローン）の確認
2. cond_A を素の AutoGPT で構築（agent.py + code_executor.py + source 宣言）
3. cond_A を解析 → Found 0 issues を確認
4. cond_A を cond_B に複製し、`dispatch_lowering` を agent.py に適用
5. diff で「挿入のみ」を確認
6. cond_B を同じ設定で解析 → Found 7 issues を確認
7. code 別内訳（5005×4, 5001×3）を表示

```bash
cd taintp2x_m2_verification
./reproduce_m2.sh
```

いずれかの段で期待値に届かない場合、スクリプトはエラーで止まる（0 でない、7 でない、
前提が無い、など）。最後まで進めば 0 → 7 が成立している。

### パス解決について

スクリプト冒頭の変数で各リポジトリの場所を解決する。`taintp2x_m2_verification/` は
リポジトリ群ルート `dispatch-taint-system/` の **二段下**にあり（`taintp2x_m2_verification`
→ `dispatch-taint` → `dispatch-taint-system`）、`ROOT` はそれを前提に導く。

```
ROOT     = <HERE>/../..                              （= dispatch-taint-system）
TP2X     = $ROOT/TaintP2X/Taint_Propagation
TYPESHED = $ROOT/.venv/lib/pyre_check/typeshed
EXT      = $ROOT/dispatch-taint/taintp2x_extension
AUTOGPT  = $ROOT/autogpt
```

配置が違う環境では、各変数を環境変数で上書きできる。

```bash
TP2X=/path/to/TaintP2X/Taint_Propagation \
TYPESHED=/path/to/.venv/lib/pyre_check/typeshed \
EXT=/path/to/dispatch-taint/taintp2x_extension \
AUTOGPT=/path/to/autogpt \
  ./reproduce_m2.sh
```

### AutoGPT クローン（永続化済み）

本検証では AutoGPT を `dispatch-taint-system/autogpt/`（= `$ROOT/autogpt`）に永続化して
あり、スクリプトの既定もそこを指す。別環境で用意し直す場合は次のとおり。

```bash
git clone https://github.com/Significant-Gravitas/AutoGPT.git <ROOT>/autogpt
cd <ROOT>/autogpt && git checkout autogpt-platform-beta-v0.5.0
```

lowering が参照するのは次の 2 箇所:
- `@command` 収集元: `<AUTOGPT>/classic/forge/forge/components/code_executor`
- 素の agent.py: `<AUTOGPT>/classic/original_autogpt/autogpt/agents/agent.py`

---

## 6. ファイル構成

```
taintp2x_m2_verification/
├── reproduce_m2.sh                # この検証の動的再現スクリプト
├── VERIFICATION_M2.md             # 本書
├── cond_A/                        # lowering 無し（スクリプトが毎回再構築）
│   ├── .pyre_configuration        # スクリプトが ROOT 相対で書き直す
│   ├── src/agent.py               # 素の AutoGPT agent.py
│   ├── src/forge/components/code_executor/code_executor.py
│   └── source/autogpt_v05.pysa
├── cond_B/                        # lowering 有り（スクリプトが生成）
│   └── （cond_A と同構成、agent.py のみ lowering 挿入）
└── results/
    ├── cond_A_taint-output.json   # 0 issues
    └── cond_B_taint-output.json   # 7 issues
```

外部依存（このフォルダ外、`$ROOT` 配下）:
- `$ROOT/TaintP2X/Taint_Propagation/`（taint 定義・stubs、TaintP2X 由来・無改変）
- `$ROOT/dispatch-taint/taintp2x_extension/dispatch_lowering.py`（lowering 本体・本研究）
- `$ROOT/autogpt/`（AutoGPT v0.5.0、コミット 9210d44）
- `$ROOT/.venv/`（pyre-check 入りの venv）
