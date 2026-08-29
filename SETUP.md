# dispatch-taint-system — セットアップと変更点

## これは何か
動的ディスパッチの「壁」を静的に解決し、テイント解析（TaintP2X / Pysa、将来 CodeQL）に
呼び出しエッジを補完する **汎用前処理** システム。中核は壁解決（dynamic-dispatch wall
resolution）で、ベース解析器は改変しない外部前処理として動く。

## 名称変更
機能に合わせてフォルダ名を変更した（旧名 `cross_tool_audit` は「クロスツール」に偏った命名だった）。
- リポジトリルート: `cross_tool_audit2/` → **`dispatch-taint-system/`**
- プロジェクト本体 : `cross_tool_audit/` → **`dispatch-taint/`**

`reproduce_m2.sh` と `run_ablation.sh` の中のパス参照（`$ROOT/cross_tool_audit/...`）も
`$ROOT/dispatch-taint/...` に修正済み。Python パッケージ名 `ctaudit/` は import 互換のため
据え置き（変更すると全コードの import が壊れるため）。

## この ZIP から除外したもの（すべて再生成可能・非可搬）
配信サイズと可搬性のため、以下は含めていない:
- `*/.venv`（193MB・非可搬。symlink が壊れるため再作成が前提）
- 各 `*/.git`（計 ~145MB）、`__pycache__`、`*.egg-info`、`*/.pyre`（pyre キャッシュ）
- ルート直下の `autogpt/`（214MB・第三者クローン。reproduce_m2.sh が再 clone を案内）
- ルート直下の `r/`（pyre 出力の残骸）

`.pyre_configuration`（設定ファイル・極小）は保持。各実行で上書き生成されるので問題ない。

## 復元手順
### 1) 仮想環境（pyre / Pysa を提供）
```bash
cd dispatch-taint-system        # リポジトリルート直下に作る
python3 -m venv .venv
source .venv/bin/activate
pip install pyre-check==0.9.25        # 元の環境と同じバージョン（typeshed 同梱）
pip install -r pysa/requirements.txt  # 解析対象が要求する依存があれば
```
`pyre-check` が `typeshed` を同梱するため、両スクリプトの既定 TYPESHED
（`$ROOT/.venv/lib/pyre_check/typeshed`）が有効になる。
パスが違う場合は環境変数 `TYPESHED=...` で上書き。

### 2) AutoGPT（手順0をゼロから再現する場合のみ必要）
```bash
git clone https://github.com/Significant-Gravitas/AutoGPT.git ../autogpt   # = dispatch-taint-system/autogpt
cd ../autogpt && git checkout autogpt-platform-beta-v0.5.0
```
※ 検証用の `taintp2x_m2_verification/cond_A/src`・`cond_B/src` は**ビルド済みで同梱**して
いるので、AutoGPT 無しでも「手順1（汎用ハーネスの検証）」はそのまま走る。

## 新規・変更ファイル
- `dispatch-taint/taintp2x_extension/dispatch_lowering.py` … **汎用版に置き換え**。
  `@command` 専用から言語レベルのイディオム（subscript / getattr / higher-order）へ一般化。
  レガシー spec を渡すと旧の壁検出・候補収集規則を選択する（生成コードは現行形式＝ガード・
  bound レシーバ・リンクタグ付き。AutoGPT 0→7、到達 sink 5 組は維持）。
- `dispatch-taint/taintp2x_extension/test_registration.py` … 候補収集・links.json 往復のテスト
  （旧 `test_lowering.py` は絶対パス固定で動かないため 2026-08-29 に削除）。
- `dispatch-taint/taintp2x_m2_verification/`:
  - `run_ablation.sh` … 任意 OSS 向けの汎用 ablation ハーネス（cond_A=host単体 vs cond_B=+壁解決）。
  - `ablation_helpers.py` … pyre config / lowering / issue カウント（ヒアドキュメント不使用）。
  - `spec.autogpt.json` … レガシー spec（検証・回帰用）。
  - `spec.general.example.json` … 新規対象用の spec 雛形。
  - `target.example.pysa` … source/sink 宣言の雛形（source は `LLMControlled` を流用）。
  - `README_ABLATION.md` … ハーネスの説明と種別一覧。

## 2026-08-29: IccTA 型パイプラインへの再構成
IccTA（Li et al. ICSE 2015; `soot-infoflow-android-iccta-master/`）の設計に倣い、壁解決を
「リンク IR → フィルタ → 計装」の構造に整理した。対応表は `dispatch-taint/README.md`。
- `dispatch-taint/taintp2x_extension/links.py` … **新規**。`Candidate` / `WallRecord` / `DispatchLink`
  / `LoweringStats`、`build_links`（壁×候補の結合、レジストリ・BoolOp 所属による絞り込み、
  引数整合フィルタ）、`links.json` の入出力、`index_registries`（旧 ctaudit の `analysis/dispatch_resolution.py`
  から移植し健全性条件を強化。原本はこのリポジトリには含まれない）。
- `dispatch-taint/taintp2x_extension/pipeline.py` … **新規**。ドライバ CLI。`AutoLinksProvider`
  （spec 駆動）/ `FileLinksProvider`（手書き `links.json`）、`stages`（多段 lowering）、
  `--emit inline|redirector`、`--links-out` / `--stats-out`。
- `dispatch-taint/taintp2x_extension/dispatch_lowering.py` … リンク列から生成する形に分離。
  `emit="redirector"` で合成モジュール `__ctaudit_redirect.py`（`redirector_N`）を生成。
  クラス候補は inline でも `Cls.__new__(Cls)` でインスタンスを作り bound で呼ぶ（受信側計装）。
  `await` 対応、`return`/複合文の前への自動配置、文単位の挿入位置、`wall=<file>:<line>` タグ。
  `detect_boolop` を `detect_higher_order` から分離。
- `dispatch-taint/taintp2x_extension/bench/` … **新規**。壁イディオム別マイクロベンチ
  （`run_bench.py [--pyre]`）。壊れていた `test_lowering.py` は削除。
- `dispatch-taint/taintp2x_m2_verification/{ablation_helpers.py,run_ablation.sh}` … lowering を
  pipeline 経由に。`EMIT` / `LINKS_IN`、`cond_B/links.json` と `cond_B/stats.json` を出力、
  手順 7 で統計＋A/B 表を表示。
- `dispatch-taint/pysa/projects/sk_real/spec.sk_real.json` … **新規**。SK 2 段 lowering の spec
  （旧手順は現行検出器では構文エラーになるため置き換え。VERIFICATION_REPORT.md 追記参照）。

## 実行
詳細は `dispatch-taint/taintp2x_m2_verification/README_ABLATION.md`。
- 手順0（環境＋回帰確認）: `cd dispatch-taint/taintp2x_m2_verification && ./reproduce_m2.sh` → 0→7
  （到達 sink 5 組）。
- 手順1（汎用ハーネス検証）: 同ディレクトリで `TARGET_SRC`/`WALL_FILES`/`PYSA_MODELS`/`SPEC_JSON`
  を設定して `./run_ablation.sh`（committed cond_A/src を対象に EXPECT_A=0 EXPECT_B=7
  EXPECT_SINKS_B=5。`EMIT=inline|redirector`、`LINKS_IN=links.json` も指定可）。
- 手順2（新規 OSS）: `spec.general.example.json` と `target.example.pysa` を複製して対象に合わせる。
