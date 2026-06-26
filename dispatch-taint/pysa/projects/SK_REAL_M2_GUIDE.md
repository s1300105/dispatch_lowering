# 実 Semantic Kernel 1.39.3 上での M2 アブレーション手順

CVE-2026-26030 を **実ライブラリ本体**で `cond_A(素の TaintP2X/Pysa) = 0 → cond_B(壁解決) = 検出`
として再現するための手順。構造再現では 0→検出 を実証済みなので、本手順は「私の再現コードでなく実
`semantic_kernel` パッケージ」での忠実性アップが目的。

---

## 0. 正直な前提 — 実フローは複数の壁を横断する

実 1.39.3 ソースで確認した、`function_call`(LLM出力) → `eval` 経路上の壁:

| 場所 | 壁 | 種類 |
|---|---|---|
| `kernel.py` invoke_function_call | `function_to_call = get_function(name)` → `function_to_call.invoke(...)` | 名前キー dispatch + attr 呼び出し |
| KernelFunction.invoke | 内部に保持したメソッド(search_wrapper)への呼び出し | 間接 |
| `data/vector.py:2104` search_wrapper | `update_func(...)`(= `default_dynamic_filter_function`) | 高階(or/デフォルト束縛) |
| `data/vector.py:2104` search_wrapper | `self.search(...)` → InMemoryCollection.search | 仮想 dispatch(抽象基底) |
| `connectors/in_memory.py:384` | `eval(compile(ast.parse(filter_str)))` | **SINK** |

AutoGPT は壁1個(`_get_command(name)`)。SK は3〜4個。**「素の Pysa はどれも越えられない」＝ cond_A は確実に 0**、
かつ「ctaudit の壁解決で復元」を示すには **複数の壁を順に解決**する。これは欠点でなく、より強い例。

---

## 1. 環境構築

```bash
mkdir sk_m2 && cd sk_m2
python3 -m venv .venv && source .venv/bin/activate
pip install "pyre-check==0.9.25" "semantic-kernel==1.39.3"

# 実ソース(壁確認 + lowering 対象)。pip 版と同一コードだが行確認しやすい
git clone --depth 1 --branch python-1.39.3 \
  https://github.com/microsoft/semantic-kernel.git sk-src

# typeshed の場所を控える
SITEPKG=$(python3 -c "import site;print(site.getsitepackages()[0])")
TYPESHED="$SITEPKG/pyre_check/typeshed"
ls "$TYPESHED" >/dev/null && echo "typeshed: $TYPESHED"

# ctaudit リポジトリの lowering パス
EXT=/path/to/dispatch-taint/taintp2x_extension   # ← 自分のパスに直す
```

---

## 2. プロジェクト構成

Pysa は **source_directories 内のコードしか taint 解析しない**。だから実 `semantic_kernel`
を src に置く。pydantic 等の依存は search_path で型解決のみ(解析しない)。

```bash
SKPKG=$(python3 -c "import os,semantic_kernel;print(os.path.dirname(semantic_kernel.__file__))")
mkdir -p cond_A/src cond_A/models
cp -r "$SKPKG" cond_A/src/semantic_kernel
```

### cond_A/models/taint.config
```json
{
  "sources": [ { "name": "ToolOutput" } ],
  "sinks":   [ { "name": "CodeExecution" } ],
  "features": [],
  "rules": [
    { "name": "LLM-output reaches code execution", "code": 9001,
      "sources": ["ToolOutput"], "sinks": ["CodeExecution"],
      "message_format": "LLM-controlled tool call {$sources} reaches code-execution sink {$sinks}" }
  ]
}
```

### cond_A/models/sk.pysa
```
# 現実的脅威モデル: モデルが選んだツールコールが攻撃者制御の source
def semantic_kernel.kernel.Kernel.invoke_function_call(self, function_call: TaintSource[ToolOutput]): ...
# ライブラリ内シンク (connectors/in_memory.py:384)
def eval(__code: TaintSink[CodeExecution]): ...
# parse -> compile -> eval イディオムの伝播 (in_memory.py:382-384)
def ast.parse(source: TaintInTaintOut, *args, **kwargs): ...
def compile(source: TaintInTaintOut, *args, **kwargs): ...
```

### cond_A/.pyre_configuration
```json
{
  "source_directories": ["src"],
  "search_path": ["__SITEPKG__"],
  "taint_models_path": ["models"],
  "typeshed": "__TYPESHED__",
  "exclude": [".*/tests/.*", ".*/samples/.*"],
  "strict": false
}
```
`__SITEPKG__` / `__TYPESHED__` を 1 の値に置換。`exclude` で重い tests/samples を解析対象外に。

### cond_A/src/harness.py (任意・関数を解析集合に確実に入れるため)
```python
# Pysa はモデル駆動なので実行不要。実ツール経路を参照に含めるだけ。
from semantic_kernel.connectors.in_memory import InMemoryCollection  # noqa
from semantic_kernel.kernel import Kernel  # noqa
```

---

## 3. cond_A(素)を解析 → 0 を期待

```bash
cd cond_A
pyre --noninteractive analyze --no-verify --save-results-to ./r 2>&1 | grep -i "found.*issue"
cd ..
```
`Found 0 issues` のはず。これは「経路上のいずれかの壁で taint が止まる」ため。次でどの壁かを特定。

---

## 4. 壁の列挙(実コードの証跡 = 論文に載せる)

```bash
PYTHONPATH="$EXT" python3 - sk-src/python/semantic_kernel << 'PY'
import sys, dispatch_lowering as dl
SK = sys.argv[1]
spec = {"resolver_hints": ["get_function"],
        "wall_attr_names": ["invoke", "search"],
        "detect_subscript": True, "detect_getattr": True, "detect_higher_order": True}
for rel in ["kernel.py", "data/vector.py", "connectors/in_memory.py"]:
    walls = dl.describe_walls(open(f"{SK}/{rel}").read(), spec)
    print(f"\n=== {rel}: {len(walls)} wall(s) ===")
    for ln, idiom, callee in walls:
        print(f"  L{ln:<5} {idiom:<14} {callee}")
PY
```
→ `kernel.py` の `function.invoke`、`vector.py` の `self.search` 等が出る。これが
**「素の TaintP2X が越えられない箇所」の実物リスト**。

---

## 5. cond_B: 壁を lowering で順に解決 → 検出

cond_A を複製して反復。**差分は lowering 挿入のみ**(source/sink/config は固定)。

```bash
cp -r cond_A cond_B && rm -rf cond_B/r
```

### 5-1. 名前キー dispatch を解決
SK のツールはクロージャ(search_wrapper)なので名前回収できない。`candidate_import_module` で
補間関数 `default_dynamic_filter_function` を import し、args を通す:

```bash
PYTHONPATH="$EXT" python3 - cond_B/src/semantic_kernel/kernel.py << 'PY'
import sys, dispatch_lowering as dl
wall_file = sys.argv[1]
spec = {
  "resolver_hints": ["get_function"],     # function_to_call = get_function(name)
  "wall_attr_names": ["invoke"],          # function_to_call.invoke(...)
  "detect_higher_order": True, "detect_subscript": False, "detect_getattr": False,
  "candidate_import_module": "semantic_kernel.data._shared",
  "insert_before": True,
}
# candidate は _shared の補間関数を手指定(クロージャの代替経路)
cands = [(None, "default_dynamic_filter_function", ["parameters"])]
src = open(wall_file).read()
print("[walls]", dl.describe_walls(src, spec))
open(wall_file, "w").write(dl.lower_wall_file(src, cands, spec))
print("[lowered] kernel.py")
PY
```

### 5-2. self.search 仮想 dispatch を解決
`vector.py` の `self.search(...)` を InMemoryCollection.search へ:

```bash
PYTHONPATH="$EXT" python3 - cond_B/src/semantic_kernel/data/vector.py \
                            cond_B/src/semantic_kernel/connectors/in_memory.py << 'PY'
import sys, dispatch_lowering as dl
vector_file, _inmem = sys.argv[1], sys.argv[2]
spec = {"wall_attr_names": ["search"], "detect_higher_order": False,
        "detect_subscript": False, "detect_getattr": False,
        "candidate_import_module": "semantic_kernel.connectors.in_memory",
        "insert_before": True}
cands = [("InMemoryCollection", "search", ["values"])]  # 仮想呼びの解決先
src = open(vector_file).read()
print("[walls]", dl.describe_walls(src, spec))
open(vector_file, "w").write(dl.lower_wall_file(src, cands, spec))
print("[lowered] vector.py")
PY
```

### 5-3. 再解析 → 検出を期待
```bash
cd cond_B
pyre --noninteractive analyze --no-verify --save-results-to ./r 2>&1 | grep -i "found.*issue"
grep -h '"kind":"issue"' r/*.json | python3 -c "
import sys,json
for l in sys.stdin:
    try:d=json.loads(l.strip().rstrip(','))['data']
    except:continue
    print('code',d.get('code'),'|',d.get('callable'),'|',d.get('message'))
"
cd ..
```

**0 のままなら**: 手順4の describe_walls をもう一度回し、未解決の壁(KernelFunction.invoke の内部間接や
update_func 高階)が残っていないか確認。該当壁を 5-1/5-2 と同様に解決するか、その関数に TITO モデルを足す
(例: `def semantic_kernel.functions...KernelFunction.invoke(self, arguments: TaintInTaintOut): ...`)。
**繋がったら、解決した壁の一覧を記録** — それが結果。

---

## 6. もっと楽なルート(推奨フォールバック) — 最小実サブツリー

フル実パッケージは壁が多く反復が重い。**実コードのまま壁数を絞る**には、実 `_shared.py`(補間)と
実 `in_memory.py`(`_parse_filter`/`eval`)を import パス通りに取り出し、dispatch は実 `kernel.py` 由来の
名前キー lookup だけ残す。私の再現コードでなく**実コード**なので忠実性は保てて、壁は1〜2個に収まる。
構造再現(済)と実フルパッケージ(本手順)の中間として、まずこれで 0→検出 を取るのが現実的。

---

## 7. トラブルシュート

- `import typeshed failed` → `.pyre_configuration` の `typeshed` 未設定/誤り。手順1の値を入れる。
- 依存の型エラーが大量 → `--no-verify` で best-effort 続行。`search_path` に venv の site-packages。
- 解析が重い/遅い → `exclude` に `".*/tests/.*"`, `".*/samples/.*"`, 使わない connector を追加。
- `eval` のモデル検証エラー → typeshed が無いと builtin 解決不可。typeshed 設定で解消(構造再現で確認済)。
- cond_B が 0 のまま → 未解決の壁が残っている(手順5末尾)。describe_walls で詰める。

---

## 8. 論文に書くこと

- `cond_A = 0`(実 semantic-kernel 1.39.3), `cond_B = 検出`(壁解決後)、差分は lowering 挿入のみ。
- **解決した壁の一覧**(名前キー dispatch / KernelFunction.invoke / self.search 仮想 dispatch)。
- 主張: 「実 SK の CVE-2026-26030 フローは N 個のフレームワーク壁の背後にあり、素の TaintP2X/Pysa は
  どれも越えられない(0)。ctaudit の壁解決で source→eval を復元」。AutoGPT(壁1)より壁が多い分、
  外部妥当性(機構の一般性)を強める第二の実 OSS データ点になる。
- 正直な限界: source 配置・sink モデル・TITO は手動で、SK のディスパッチ仕様は spec として宣言した
  (これは Pysa が Django 等をモデル化するのと同種で、フレームワーク単位の一度きりの作業)。
```
