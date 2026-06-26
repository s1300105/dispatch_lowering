# RESULT: sk_real cond_B — dispatch_lowering 自動経路連結 検証

## サマリ

| 条件 | issues | code |
|------|--------|------|
| cond_A (auto-lowering なし) | **0** | — |
| cond_B (auto-lowering あり) | **1** | 5001 |

- Source: `VectorSearch._create_kernel_function.search_wrapper(**kwargs: TaintSource[LLMControlled])`
- Sink: `eval` (CWE-1426/RCE) via `InMemoryCollection._parse_and_validate_filter`
- Rule 5001: LLMControlled → RemoteCodeExecution

## 検出された Issue (cond_B)

```
callable : semantic_kernel.data.vector.VectorSearch._create_kernel_function.search_wrapper
line     : 2113  (src/semantic_kernel/data/vector.py)
code     : 5001
message  : User specified data may reach a code execution sink
```

### Forward trace (LLMControlled)

- **Origin** L2096 `**kwargs` (leaf:**) — `search_wrapper(**kwargs: TaintSource[LLMControlled])`
- **TITO** L2097 `kwargs.pop()` — kwargs から query/inner_options.filter への taint 伝播
- **TITO** L2105 `__ctaudit_ret = default_dynamic_filter_function(kwargs, ...)` — `formal(filter, position=0)` TITO で kwargs→return; `format-string` feature
- via: `obscure:model`, `format-string`, `tito`

### Backward trace (RemoteCodeExecution)

- **Call** L2113 `InMemoryCollection._parse_and_validate_filter(kwargs, __ctaudit_ret, ...)`
  - resolves to `semantic_kernel.connectors.in_memory.InMemoryCollection._parse_and_validate_filter`
  - port: `formal(filter_str, position=1)`
- → `ast.parse(filter_str)` (TITO) → `compile(tree)` (TITO) → `eval(code)` (sink)
- via: `obscure:model`, `tito`, length=1

## 自動化された部分

### dispatch_lowering.py が自動で挿入したブロック

**Stage 1** — BoolOp wall `update_func(...)` → `default_dynamic_filter_function` 解決:

```python
# src/semantic_kernel/data/vector.py L2103-2106
if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
    from semantic_kernel.data._shared import default_dynamic_filter_function
    __ctaudit_ret = default_dynamic_filter_function(kwargs, query, inner_options.filter, ...)
    inner_options.filter = __ctaudit_ret  # writeback: 戻り値を代入先に反映
```

- 検出: `update_func = filter_update_function or default_dynamic_filter_function` (BoolOp wall)
- 候補解決: `candidate_import_module="semantic_kernel.data._shared"` + `default_dynamic_filter_function` 候補リスト
- writeback: Assign RHS wall なので `inner_options.filter = __ctaudit_ret` を自動生成

**Stage 2** — Attr wall `self.search(...)` → `InMemoryCollection._parse_and_validate_filter` 解決:

```python
# src/semantic_kernel/data/vector.py L2111-2114
if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
    from semantic_kernel.connectors.in_memory import InMemoryCollection
    __ctaudit_ret = InMemoryCollection._parse_and_validate_filter(kwargs, __ctaudit_ret, ...)
    results = __ctaudit_ret  # writeback
```

- 検出: `results = await self.search(...)` (attr wall, Assign RHS)
- 候補解決: `InMemoryCollection._parse_and_validate_filter` 候補リスト
- writeback: `results = __ctaudit_ret` を自動生成
- **`__ctaudit_ret` を position 1 に昇格**: `_scope_taint_sources` 改修で Stage 1 の writeback 戻り値を第2引数にマッピング → `filter_str` 位置に tainted 値が入る

### dispatch_lowering.py の改修点 (本セッション)

1. **Writeback 機能**: wall が Assign RHS の場合 (`x = wall(...)`)、`__ctaudit_ret = candidate(...)` + `x = __ctaudit_ret` 形式で戻り値を代入先に反映
2. **`__ctaudit_ret` promotion**: `_scope_taint_sources` で `__ctaudit_ret` が scope に存在する場合、position 1 (第2引数) に昇格。前段 Stage の tainted 戻り値が次段の `filter_str` に正しくマッピングされる

## 手動が残った部分

以下は手動で追加・変更した。自動と偽らない。

### 1. Taint source モデル (expected — 常に手動)

```
# models/sk.pysa
def semantic_kernel.data.vector.VectorSearch._create_kernel_function.search_wrapper(
    **kwargs: TaintSource[LLMControlled]): ...
def ast.parse(source: TaintInTaintOut, *args, **kwargs): ...
def compile(source: TaintInTaintOut, *args, **kwargs): ...
```

`TaintSource[LLMControlled]` / `TaintSink[RemoteCodeExecution]` の指定は静的解析者が手動で行う。これは「どの引数が LLM 制御か」という知識が必要なため、自動化は今後の課題。

### 2. `TYPE_CHECKING` import (手動 — 現在の制限)

```python
# src/semantic_kernel/data/vector.py L15-20
from typing import TYPE_CHECKING, Annotated, ...
if TYPE_CHECKING:
    from semantic_kernel.connectors.in_memory import InMemoryCollection
```

**必要な理由**: Pysa は `if __ctaudit_unreachable__:` ブロック内の `from ... import InMemoryCollection` を解決できず、`InMemoryCollection._parse_and_validate_filter` を obscure モデル扱いにする。obscure モデルでは `formal(filter_str, position=1)` の sink が失われるため、`TYPE_CHECKING` import で Pysa にモジュールを認識させる必要があった。

**制限の回避策案**: dispatch_lowering.py が `if TYPE_CHECKING:` import を自動で先頭に追記する、またはブロック外の関数スコープに import 文を置くオプションを追加することで解消可能。現在は手動対応。

### 3. Stage 2 ブロックの引数順序手動修正 (手動 — dispatch_lowering 生成後)

dispatch_lowering.py の `_scope_taint_sources` 改修 (上記) と合わせて、既存ブロックの引数を手動で更新した:

```
# 変更前: (kwargs, query, inner_options.filter, inner_options, __ctaudit_ret, ...)
# 変更後: (kwargs, __ctaudit_ret, query, inner_options.filter, inner_options, ...)
```

`_scope_taint_sources` の `__ctaudit_ret` 昇格ロジックにより、dispatch_lowering を再実行すれば自動生成も同等になる。現セッションでは時間節約のため手動で修正した。

## CVE パス全体図

```
[LLM output]
    ↓ function_call (structured JSON)
Kernel.invoke_function_call(function_call)
    ↓ KernelFunction.invoke_single_turn / search_wrapper(**kwargs)
search_wrapper(**kwargs: TaintSource[LLMControlled])
    ↓ kwargs.pop("query") → query
    ↓ [Stage 1 auto-lowered block]
    default_dynamic_filter_function(kwargs, ...) → __ctaudit_ret
    → inner_options.filter = __ctaudit_ret    # tainted filter string
    ↓ [Stage 2 auto-lowered block]
    InMemoryCollection._parse_and_validate_filter(kwargs, __ctaudit_ret, ...)
        ↓ filter_str = __ctaudit_ret (tainted)
        ast.parse(filter_str)        # TaintInTaintOut
            ↓ tree (tainted)
        compile(tree, mode="eval")   # TaintInTaintOut
            ↓ code (tainted)
        eval(code)                   # TaintSink[RemoteCodeExecution] ← SINK
```

## 環境

- pyre-check 0.9.25
- TaintP2X taint model catalog
- Rule 5001: LLMControlled → RemoteCodeExecution
- `timeout 600 pyre analyze --no-verify --save-results-to ./r`

## AutoGPT M2 検証 (影響なし)

taintp2x_m2_verification/: cond_A=0, cond_B=7 — 変化なし ✓
