# フローレベル・ベンチマーク (FLOW_BENCHMARK.md)

## これは何を測るか

ツールモデル・ベンチ (`benchmark/run_benchmark.py`, RQ1) は「**ツールモデル**(どの関数が source/sink か・カテゴリ・ガード)を回収できたか」を測る。本ベンチは見出しの主張を1段上で測る:**(gold) ツールモデルを与えたとき、ctaudit のフロー機構――データフロー・レッグ、§4.5 枝刈り、絞り込み付きディスパッチ解決――が、各フィクスチャに構成上実在する cross-tool 暗黙フローを出力するか**。

指標:

- **フロー recall / precision**(検出):期待フロー集合と出力フロー集合を、検出 key `(kind, sink, category)` で突き合わせる。
- **ガード分類精度**:マッチしたフローについて guarded/unguarded を当てられたか(安全側の信号)。

ディスパッチ系フィクスチャには **gold ツールモデルを与える**。これにより「フロー検出」を「ツールモデル回収(RQ1 が別途測る)」から **分離** する。

## RQ1 との違い(重要)

- RQ1 の 0→100% / 92.7→100% / κ=1.0 は **ツールモデル**指標であり、フロー検出指標ではない。
- 本ベンチは **フロー**指標(source→LLM→sink を当てたか)。論文では両者を別 RQ として書き、0→100% を「フロー検出 recall」と書かないこと。
- これは **構成的に正解が既知の統制ベンチ**であり、実リポジトリのフロー gold(将来課題 (A)(B)(C))を **置き換えるものではなく補完する**。

## フロー単位と正解の定義

フロー = `Flow(kind, sink, category, guarded)`。

- `kind`:`implicit`(LLM 経由の cross-tool フロー、見出しの対象)/ `explicit`(データ層 verbatim = TITO)。
- `sink`:出力された sink 名(`subprocess.run` のような呼び出し、または解決された具象ツール名 `run_cmd`)。
- `category`:正規化後 `code_execution | file_write | sql | network | deserialize`(エンジンの `exec` は `code_execution` に正規化)。
- `guarded`:経路/シンク上にガードが検出されたか。

検出マッチは `(kind, sink, category)` で行い(ガードは検出 key に含めない)、マッチしたフローについて guarded の一致を **ガード分類精度** として別に集計する。これにより「フローを見つけたか」と「ガードを正しく分類したか」を切り分ける。

## フィクスチャと、それが対応する主張

| フィクスチャ | 期待フロー | 何を検査するか |
|---|---|---|
| `langchain_2tool_vuln.py` | implicit `subprocess.run`/code_exec | 基本の cross-tool 暗黙フロー |
| `langgraph_multinode_app.py` | implicit `subprocess.run`/code_exec | 複数ノード経由の暗黙フロー |
| `langgraph_state_app.py` | implicit `requests.get`/network | network sink の暗黙フロー |
| `mcp_sdk_app.py` | implicit `cursor.execute`/sql | SQL sink の暗黙フロー |
| `openai_agents_app.py` | implicit `os.system`/code_exec | 別フレームワークの暗黙フロー |
| `guarded_agent_app.py` | implicit `os.system`/code_exec, **guarded** | **ガード分類**(緩和済みフローを guard 付きで報告) |
| `dynamic_dispatch_agent.py` | implicit `run_cmd`/code_exec, `fetch_url`/network | **fusion #4**:ディスパッチ壁→具象 sink 解決 |
| `phase_gated_agent.py` | implicit `write_file`/file_write のみ | **phase 絞り**:登録済みだが非許可の `run_cmd` を健全に除外 |
| `data_layer_verbatim.py` | explicit `subprocess.run`/code_exec | データ層 verbatim(implicit と区別) |
| `langchain_2tool_safe.py` | (なし) | precision:安全時に誤検出しない |
| `schema_pruned_app.py` | (なし) | §4.5 枝刈り(制約付き引数チャネル)で正しく抑制 |
| `unreachable_sink_app.py` | (なし) | 到達不能 sink を正しく抑制 |

## 実行方法

unzip 後、リポジトリ直下で:

```bash
python -m benchmark.flow_bench
```

(`pip install -e .` 済みなら `ctaudit-flowbench` でも可。)

期待出力:

```
ALL flows      : recall=1.000 precision=1.000 (TP=10 FP=0 FN=0)
implicit only  : recall=1.000 precision=1.000 (TP=9 FP=0 FN=0)
guard accuracy : 1.000 over 10 matched flow(s)
```

テスト:

```bash
python -m pytest tests/test_flow_bench.py -q
```

## 検証済み結果

- **ALL flows**:recall 1.000 / precision 1.000(TP=10, FP=0, FN=0)。
- **implicit only**(cross-tool 暗黙フローのみ):recall 1.000 / precision 1.000(TP=9, FP=0, FN=0)。
- **guard accuracy**:1.000(マッチ 10 フロー)。
- negatives 3件(safe / pruned / unreachable)はいずれも 0 フロー(誤検出なし)。
- `dynamic_dispatch_agent` は 2 フロー(`run_cmd`, `fetch_url`)に解決、`phase_gated_agent` は phase 絞りで `write_file` のみ(`run_cmd` 健全に除外)。

これらは構成上の正解に対する統制された結果であり、フローレベルの主張を統制環境で裏付ける。実リポジトリのフロー gold とアノテータ間 κ(フローレベル)は将来課題。
