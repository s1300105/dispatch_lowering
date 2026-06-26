# Semantic Kernel CVE-2026-26030 — ctaudit 検証成果物（本日分）

semantic-kernel 1.39.3 の CVE-2026-26030（InMemory フィルタの eval、ツールディスパッチ壁の背後）を
ctaudit/TaintP2X で検証した一式。

## 中身

- `sk_inmemory/` — TaintP2X(Pysa) M2 アブレーション（構造忠実再現）
  - `cond_A/`    壁あり・lowering なし → **Found 0 issues**
  - `cond_B/`    手挿入 lowering（`**args`）→ **Found 1 issue**
  - `cond_auto/` spec 駆動の自動 lowering → **Found 2 issues**（recall-first 過大近似）
  - `spec.semantic_kernel.json` — 自動 lowering 用 SK LoweringSpec（6行）
  - 各 cond の `models/{taint.config, sk.pysa}` が source(LLM出力)/sink(eval)/TITO 定義
- `realworld/semantic_kernel_inmemory_hotelfinder.py` — ネイティブ ctaudit 用の忠実転記標的
  （`ctaudit <path>` のベースラインは現状 0。models/semantic_kernel.py を書けば 0→1 が次の作業）
- `SK_REAL_M2_GUIDE.md` — 実 semantic-kernel ライブラリ本体で 0→検出 を取る詳細手順

## 各 cond の再実行（要 pyre-check, typeshed）

    cd sk_inmemory/cond_A
    pyre --noninteractive analyze --no-verify --save-results-to ./r 2>&1 | grep -i "found.*issue"

`.pyre_configuration` の `typeshed` パスは環境に合わせて要調整。

## 実 file:line 対応（semantic-kernel @ python-1.39.3）

- 壁:   functions/kernel_function_extension.py:300 / kernel.py:350
- 補間: data/_shared.py:171  ( f"lambda x: x.{p.name} == '{kwargs[p.name]}'" )
- sink: connectors/in_memory.py:384  ( eval(compile(ast.parse(filter_str))) )
