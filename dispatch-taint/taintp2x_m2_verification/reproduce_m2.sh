#!/usr/bin/env bash
# =============================================================================
# reproduce_m2.sh — TaintP2X M2 レベル検証の動的再現
#
#   素の AutoGPT agent.py に dispatch_lowering を適用して cond_B を生成し、
#   「lowering 無し = 0 issues → lowering 有り = 7 issues（到達 sink 5 組）」を実演する。
#   （7 件なのは execute_python_file が filename と args の両方で汚染を受けるため。
#     到達した (sink 種別, sink メソッド) は 5 組。）
#
#   前提: pyre-check が入った .venv が有効、TaintP2X の taint 定義一式が存在、
#         AutoGPT (autogpt-platform-beta-v0.5.0) のクローンが存在。
#   差分は agent.py への lowering 挿入のみ。それ以外（taint定義・source宣言・
#   code_executor・解析設定）は両条件で完全に同一。
# =============================================================================
set -euo pipefail

# ---- 設定（環境に合わせて、ここだけ直せばよい）-------------------------------
# このスクリプトが置かれているディレクトリ（= taintp2x_m2_verification/ を想定）
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# リポジトリ群のルート（dispatch-taint-system/ を想定）。HERE から二段上。
ROOT="$(cd "$HERE/../.." && pwd)"

# TaintP2X の Taint_Propagation（taint 定義・stubs）
TP2X="${TP2X:-$ROOT/TaintP2X/Taint_Propagation}"

# typeshed（pyre-check 同梱）
TYPESHED="${TYPESHED:-$ROOT/.venv/lib/pyre_check/typeshed}"

# dispatch_lowering.py のあるフォルダ
EXT="${EXT:-$ROOT/dispatch-taint/taintp2x_extension}"

# AutoGPT クローン（@command メソッドの収集元 と 素の agent.py の取得元）
AUTOGPT="${AUTOGPT:-$ROOT/autogpt}"
CMD_DIR="$AUTOGPT/classic/forge/forge/components/code_executor"
AGENT_SRC="$AUTOGPT/classic/original_autogpt/autogpt/agents/agent.py"

# 作業先（このスクリプトと同じ場所に cond_A / cond_B / results を作る）
WORK="$HERE"
# -----------------------------------------------------------------------------

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. 前提チェック ---------------------------------------------------------
say "=== 0. 前提チェック ==="
command -v pyre >/dev/null 2>&1 || die "pyre が見つかりません（.venv を有効化してください）"
[ -d "$TP2X/taint" ] || die "TaintP2X taint 定義が見つかりません: $TP2X/taint"
[ -d "$TP2X/stubs" ] || die "TaintP2X stubs が見つかりません: $TP2X/stubs"
[ -d "$TYPESHED" ]   || die "typeshed が見つかりません: $TYPESHED"
[ -f "$EXT/dispatch_lowering.py" ] || die "dispatch_lowering.py が見つかりません: $EXT"
[ -d "$CMD_DIR" ] || die "AutoGPT の code_executor が見つかりません: $CMD_DIR
  （AutoGPT を取得してください:
     git clone https://github.com/Significant-Gravitas/AutoGPT.git $AUTOGPT
     cd $AUTOGPT && git checkout autogpt-platform-beta-v0.5.0 ）"
[ -f "$AGENT_SRC" ] || die "AutoGPT の素の agent.py が見つかりません: $AGENT_SRC"
[ -f "$WORK/cond_A/source/autogpt_v05.pysa" ] || die "source 宣言が見つかりません: $WORK/cond_A/source/autogpt_v05.pysa"
echo "OK: 全前提を確認"

# 設定ファイル生成のヘルパ（cond_A と cond_B で対象ディレクトリだけ変える）
write_config() {
  local target_dir="$1"   # 例: $WORK/cond_A
  python3 - "$target_dir" "$TP2X" "$TYPESHED" << 'PY'
import json, os, sys
target, tp2x, typeshed = sys.argv[1], sys.argv[2], sys.argv[3]
config = {
    "source_directories": [os.path.join(target, "src")],
    "taint_models_path": [os.path.join(tp2x, "taint"), os.path.join(target, "source")],
    "search_path": [os.path.join(tp2x, "stubs")],
    "typeshed": typeshed,
    "strict": False,
}
with open(os.path.join(target, ".pyre_configuration"), "w") as f:
    json.dump(config, f, indent=2)
PY
}

# Found N issues を取り出すヘルパ
run_pyre() {
  local dir="$1"
  ( cd "$dir" && rm -rf r && pyre analyze --no-verify --save-results-to ./r 2>&1 | grep -i "found.*issue" )
}

# ---- 1. cond_A を素の状態で組む ----------------------------------------------
say "=== 1. cond_A（lowering 無し・素の AutoGPT）を構築 ==="
rm -rf "$WORK/cond_A"
mkdir -p "$WORK/cond_A/src/forge/components/code_executor" "$WORK/cond_A/source"
# import パス通りに配置（Pysa がクラスを実体へ結びつけるため）
touch "$WORK/cond_A/src/forge/__init__.py" \
      "$WORK/cond_A/src/forge/components/__init__.py" \
      "$WORK/cond_A/src/forge/components/code_executor/__init__.py"
cp "$CMD_DIR/code_executor.py" "$WORK/cond_A/src/forge/components/code_executor/"
cp "$AGENT_SRC" "$WORK/cond_A/src/agent.py"
# source 宣言（LLMControlled source と RemoteCodeExecution sink）を復元
cat > "$WORK/cond_A/source/autogpt_v05.pysa" << 'PYSA'
def agent.Agent._execute_tool(self, tool_call: TaintSource[LLMControlled]): ...
def subprocess.run(args: TaintSink[RemoteCodeExecution], **kwargs): ...
def subprocess.Popen.__init__(self, args: TaintSink[RemoteCodeExecution], **kwargs): ...
PYSA
write_config "$WORK/cond_A"
echo "cond_A の agent.py に ctaudit 痕跡があるか: $(grep -c ctaudit "$WORK/cond_A/src/agent.py" || true)（0 なら素）"

# ---- 2. cond_A で解析（0 を確認）--------------------------------------------
say "=== 2. cond_A を TaintP2X M2（Pysa）で解析 → 0 issues を期待 ==="
A_RESULT="$(run_pyre "$WORK/cond_A")"
echo "$A_RESULT"
echo "$A_RESULT" | grep -q "Found 0 issues" || die "cond_A が 0 issues になりませんでした"

# ---- 3. cond_B を cond_A から複製し、lowering を適用 --------------------------
say "=== 3. cond_B を cond_A から複製し、dispatch_lowering を適用 ==="
rm -rf "$WORK/cond_B"
cp -r "$WORK/cond_A" "$WORK/cond_B"
rm -rf "$WORK/cond_B/r"
# 素の agent.py に lowering を適用（cond_A は素のまま温存）
PYTHONPATH="$EXT" python3 - "$CMD_DIR" "$WORK/cond_B/src/agent.py" << 'PY'
import sys, dispatch_lowering as dl
cmd_dir, wall_file = sys.argv[1], sys.argv[2]
spec = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}
cmds = dl.collect_commands(cmd_dir, spec)
print(f"[ctaudit] 収集した @command メソッド数: {len(cmds)}")
src = open(wall_file).read()
out = dl.lower_wall_file(src, cmds, spec)
open(wall_file, "w").write(out)
print(f"[ctaudit] lowering 適用後の行数: {len(out.splitlines())}")
PY
write_config "$WORK/cond_B"

# ---- 4. 差分が lowering 挿入のみであることを確認 -----------------------------
say "=== 4. cond_A と cond_B の差分（lowering 挿入のみのはず）==="
echo "--- agent.py の差分 ---"
diff "$WORK/cond_A/src/agent.py" "$WORK/cond_B/src/agent.py" || true
echo "--- code_executor.py は同一か ---"
diff "$WORK/cond_A/src/forge/components/code_executor/code_executor.py" \
     "$WORK/cond_B/src/forge/components/code_executor/code_executor.py" \
     && echo "code_executor.py: 同一"
echo "--- source 宣言は同一か ---"
diff "$WORK/cond_A/source/autogpt_v05.pysa" "$WORK/cond_B/source/autogpt_v05.pysa" \
     && echo "source 宣言: 同一"

# ---- 5. cond_B で解析（7 を確認）--------------------------------------------
say "=== 5. cond_B を同じ設定で解析 → 7 issues を期待 ==="
B_RESULT="$(run_pyre "$WORK/cond_B")"
echo "$B_RESULT"
echo "$B_RESULT" | grep -q "Found 7 issues" || die "cond_B が 7 issues になりませんでした"

# ---- 6. 検出 issue の内訳（code 別）------------------------------------------
say "=== 6. 検出 issue の内訳（期待: 5005×4, 5001×3、すべて agent.Agent._execute_tool）==="
mkdir -p "$WORK/results"
cp "$WORK/cond_A/r/taint-output.json" "$WORK/results/cond_A_taint-output.json"
cp "$WORK/cond_B/r/taint-output.json" "$WORK/results/cond_B_taint-output.json"
python3 - "$WORK/cond_B/r/taint-output.json" << 'PY'
import json, sys, collections
codes = collections.Counter(); callables = collections.Counter()
for line in open(sys.argv[1]):
    line = line.strip().rstrip(",")
    if not line or line in ("[", "]"): continue
    try: o = json.loads(line)
    except Exception: continue
    if o.get("kind") == "issue":
        d = o.get("data", {})
        codes[d.get("code")] += 1
        callables[str(d.get("callable", ""))] += 1
print("検出 issue 総数:", sum(codes.values()))
for code, n in sorted(codes.items()):
    label = {5001: "RemoteCodeExecution", 5005: "ExecArgSink"}.get(code, "?")
    print(f"  code {code} ({label}): {n} 件")
print("callable 別:")
for c, n in callables.items():
    print(f"  {c}: {n} 件")
PY
echo "--- 到達した (sink 種別, sink メソッド) の組（期待: 5 組）---"
python3 "$HERE/ablation_helpers.py" count "$WORK/cond_B/r/taint-output.json" | sed -n '/^SINK_PAIRS/,$p'

# ---- 7. まとめ ---------------------------------------------------------------
say "=== 完了 ==="
echo "条件A（lowering 無し）: ${A_RESULT##*ƛ }"
echo "条件B（lowering 有り）: ${B_RESULT##*ƛ }"
echo "差分は agent.py への lowering 挿入のみ。0 → 7（到達 sink 5 組）を動的に再現しました。"
echo "結果 JSON: $WORK/results/cond_{A,B}_taint-output.json"
