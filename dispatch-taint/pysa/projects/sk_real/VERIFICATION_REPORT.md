# VERIFICATION REPORT — sk_real dispatch_lowering 独立検証

独立検証タスク。前セッションの自己申告を信じず、コマンド実行結果のみで判定する。

## 結論

| Q | 内容 | 判定 |
|---|------|------|
| Q1 | cond_B が code 5001 を検出するか | **PASS** |
| Q2 | 差分は lowering ブロックのみか（手動連結なし） | **PASS** |
| Q3 | lowering を外すと検出が消えるか | **PASS** |
| Q4 | lowering がコマンド一発で自動再現するか | **PASS** ※後述注記あり |
| Q5 | sink が本物の eval (RemoteCodeExecution) か | **PASS** |
| Q6 | AutoGPT M2 回帰なし (0→7 維持) か | **PASS** |

**最終結論**: 実 Semantic Kernel 1.39.3 に対し、自動 dispatch_lowering（コマンド実行・手編集なし）のみで cond_A=0 → cond_B=1 (code 5001) を独立再現・確認。ただし Q4 注記の前提条件（TYPE_CHECKING import）が必要。

---

## Q1: cond_B 現状再解析 — PASS

```
$ cd cond_B && rm -rf r && timeout 600 pyre analyze --no-verify --save-results-to ./r
Found 1 issues
```

```
ISSUES=1
  code 5001: 1
  callable semantic_kernel.data.vector.VectorSearch._create_kernel_function.search_wrapper: 1
```

code 5001 が 1 件。callable は `search_wrapper`（`invoke_function_call` ではない）。

---

## Q2: diff で手動連結チェック — PASS

```
$ diff -rq cond_A/src cond_B/src
Files .../vector.py differ
```

差分があるファイルは **vector.py のみ**。kernel.py を含む他全ファイルは同一。

`diff cond_A/src/.../vector.py cond_B/src/.../vector.py` の全追加行:

```python
# Stage 1 (4 lines inserted before L2103):
            if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
                from semantic_kernel.data._shared import default_dynamic_filter_function
                __ctaudit_ret = default_dynamic_filter_function(kwargs, query, inner_options.filter, ...)
                inner_options.filter = __ctaudit_ret

# Stage 2 (4 lines inserted before L2111):
                        if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
                            from semantic_kernel.connectors.in_memory import InMemoryCollection
                            __ctaudit_ret = InMemoryCollection._parse_and_validate_filter(kwargs, __ctaudit_ret, ...)
                            results = __ctaudit_ret
```

追加行は全て `if __ctaudit_unreachable__:` ブロック。手動の直結コード（中間変数を sink に手で渡す等）なし。

`models/sk.pysa` の実質的な差分はコメント 1 行のみ。両方とも:
```
def semantic_kernel.data.vector.VectorSearch._create_kernel_function.search_wrapper(**kwargs: TaintSource[LLMControlled]): ...
def ast.parse(source: TaintInTaintOut, *args, **kwargs): ...
def compile(source: TaintInTaintOut, *args, **kwargs): ...
```

---

## Q3: lowering 削除テスト (cond_B_nolower) — PASS

`cond_B/src` を元に `if __ctaudit_unreachable__:` ブロックを全削除した `cond_B_nolower` を作成し解析:

```
cond_B_nolower: Found 0 issues
```

lowering ブロックを外すと検出が消える。検出は lowering ブロックに依存している。

---

## Q4: 自動再生成テスト (cond_B_auto) — PASS ※注記あり

`cp -r cond_A cond_B_auto` 後、以下のコードを **手編集なしで** 実行:

```python
from dispatch_lowering import lower_wall_file, LoweringSpec

# Stage 1: BoolOp wall update_func(...) -> default_dynamic_filter_function
spec1 = LoweringSpec(
    detect_higher_order=True, detect_subscript=False, detect_getattr=False,
    candidate_import_module="semantic_kernel.data._shared", insert_before=True,
)
candidates1 = [(None, "default_dynamic_filter_function", ["filter", "parameters"])]
out1 = lower_wall_file(src, candidates1, spec1)  # +4 lines

# Stage 2: attr wall self.search(...) -> InMemoryCollection._parse_and_validate_filter
spec2 = LoweringSpec(
    wall_attr_names=("search",), detect_subscript=False, detect_getattr=False,
    detect_higher_order=False,
    candidate_import_module="semantic_kernel.connectors.in_memory", insert_before=True,
)
candidates2 = [("InMemoryCollection", "_parse_and_validate_filter", ["self", "filter_str"])]
out2 = lower_wall_file(out1, candidates2, spec2)  # +4 lines
```

結果:
- `diff cond_B_auto/.../vector.py cond_B/.../vector.py` → **空（完全一致）**
- `cond_B_auto` 解析: **Found 1 issues, code=5001**

### ※注記: TYPE_CHECKING import について

`cond_A`（および `cond_B_auto` のコピー元）の `vector.py` には以下が手動で追加済み:

```python
from typing import TYPE_CHECKING, ...
if TYPE_CHECKING:
    from semantic_kernel.connectors.in_memory import InMemoryCollection
```

この import は dispatch_lowering.py が自動生成するものではなく、前セッションで手動で追加した。

**必要な理由**: Pysa は `if __ctaudit_unreachable__:` ブロック内の `from ... import InMemoryCollection` を解決できず、`InMemoryCollection._parse_and_validate_filter` を obscure 扱いにする。obscure モデルでは `formal(filter_str, position=1)` の RCE sink 情報が失われ、検出できない。`if TYPE_CHECKING:` import により Pysa が型情報を取得でき、具体的な sink モデルが適用される。

**評価**: この前処理は機械的・決定的であり、dispatch_lowering.py が `if TYPE_CHECKING:` import を自動追加するよう拡張すれば完全自動化できる。現状は「自動 lowering + 手動 1 行前処理」が正確な記述。

---

## Q5: sink は本物の eval か — PASS

`rce_sink.pysa`:
```
def eval(source: TaintSink[RemoteCodeExecution], /, globals, locals): ...
```

`models/sk.pysa` に `_parse_and_validate_filter` の TaintSink 宣言なし。

Backward trace の leaf:
```
kind=RemoteCodeExecution, leaves=['eval:leaf:source']
```

`sink_handle`:
```json
{"kind":"Call","callee":"...InMemoryCollection._parse_and_validate_filter","parameter":"formal(filter_str)"}
```

`_parse_and_validate_filter` は callee（経路上の解決点）であり、sink 宣言されていない。sink は `in_memory.py:384` の `eval(code, ...)` 実体。

実際の taint path (in_memory.py):
```
L337: tree = ast.parse(filter_str, mode="eval")   # TITO: filter_str -> tree
L383: code = compile(tree, ...)                    # TITO: tree -> code
L384: func = eval(code, ...)                       # TaintSink[RemoteCodeExecution]
```

---

## Q6: AutoGPT M2 回帰チェック — PASS

dispatch_lowering.py 改修後（writeback 機能・`__ctaudit_ret` promotion 追加）に再解析:

```
$ cd taintp2x_m2_verification/cond_A && timeout 600 pyre analyze --no-verify --save-results-to ./r
Found 0 issues

$ cd taintp2x_m2_verification/cond_B && timeout 600 pyre analyze --no-verify --save-results-to ./r
Found 7 issues
codes=[5005, 5005, 5005, 5005, 5001, 5001, 5001]
```

改修前と同じ 0→7 を維持。回帰なし。

---

## 検証で気づいた制限・注意点

1. **TYPE_CHECKING import は手動前処理**: 完全自動化のためには dispatch_lowering.py が対象ファイルに `if TYPE_CHECKING:` import を追加するよう実装する必要がある。

2. **`__ctaudit_ret` promotion（position 1 昇格）は dispatch_lowering.py への追加実装**: `_scope_taint_sources` 関数に「`__ctaudit_ret` が scope にあれば position 1 に昇格」するロジックを追加した。これにより Stage 1 の戻り値（tainted filter string）が Stage 2 の `filter_str` 引数に正しくマッピングされる。この実装は dispatch_lowering.py に含まれており、コマンド実行時に自動適用される。

3. **source 宣言は手動（設計上）**: `search_wrapper(**kwargs: TaintSource[LLMControlled])` は分析者が手動で宣言する。「どのデータが LLM 制御か」はコード解析では決定できない。

---

*生成: 独立検証セッション（2026-06-26）*

---

## 追記（2026-08-29）: IccTA 型パイプラインへの移行後の再現手順

Q4 の Python スニペットは 2026-06 時点の `dispatch_lowering.py` 向けで、その後の
汎用検出器の拡張（実行時選択された変数へのメソッド呼び出しも壁とみなす）により
Stage 1 の spec（`detect_higher_order=True`, ヒント無し）は `vector.py` 内の別の
`f = g(...); f.m(...)` も壁として拾い、複数行呼び出しの途中にブロックを挿入して
**構文エラー**になることを確認した（git HEAD `e708cf2` で再現せず）。

現在の再現は `spec.sk_real.json`（2 段 spec）＋ `taintp2x_extension/pipeline.py` で行う
（README.md「Semantic Kernel verification」参照）。手順の対応は次の通り:

| 旧手順（Q4） | 新手順 |
|---|---|
| Stage 1: `detect_higher_order=True` で BoolOp 壁を検出 | `detect_boolop=True, detect_higher_order=False`。BoolOp 壁だけを独立に検出する |
| （メソッド壁は `wall_method_names` 未指定でも検出されていた） | `wall_method_names` が空なら `t.run(x)` 形の壁は検出しない。これにより `embedding_generator.generate_*` の無関係な壁が消え、壁は 2 件（BoolOp 1・attr 1）になる |
| Stage 2: 候補 `("InMemoryCollection", "_parse_and_validate_filter", ["self", "filter_str"])` をスコープ変数ダンプ（17 名）＋ `__ctaudit_ret` 昇格で接続 | 候補に `"forward": ["inner_options.filter"]` を明示（解析者が固定するリンク＝IccTA の設定ファイル・プロバイダ相当）。生成は `__ctaudit_obj = InMemoryCollection.__new__(InMemoryCollection); __ctaudit_ret = __ctaudit_obj._parse_and_validate_filter(inner_options.filter)` |
| Stage 1 の引数もスコープ変数ダンプ | 壁の実引数をそのまま転送: `default_dynamic_filter_function(filter=inner_options.filter, parameters=parameters, **kwargs)` |
| `if TYPE_CHECKING:` import は手動 | 対象名が壁ファイルで既に束縛済みなら import は挿入しない（`default_dynamic_filter_function` は L33、`InMemoryCollection` は L19-20 の TYPE_CHECKING import で束縛済み）。未束縛のクラス候補には `_inject_type_checking_imports` が自動付与する |

生成される 2 ブロック（計 7 行）は旧 cond_B（スコープ変数 17 名を並べた形）より大幅に短く、
`links.json` に壁 2 件と各リンクの判定・転送引数・挿入行が残る。
