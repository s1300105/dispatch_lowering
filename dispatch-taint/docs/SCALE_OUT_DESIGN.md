# 複数対象への展開設計 — 対象ごとの手作業をどこまで減らすか（2026-08-29）

## 前提（ユーザーの方針）
静的テイント解析なら一般に必要な作業は**手動のまま**でよい。TaintP2X も同じものを要求する:
1. source / sink の `.pysa` 宣言（「どのデータが LLM 制御か」はコードから決まらない）
2. Pysa が完走する解析環境（venv、`search_path`、`subset_extractor` の入口ファイル、1200 秒予算）

**このシステム固有**の手作業だけを自動化／「生成された草案のレビュー」に縮める:
3. spec（どの壁を、どの候補回収機構で）
4. `WALL_FILES`（計装するファイル）
5. 複数対象のバッチ実行と集計

## 設計の決定（3 案の合議: エンジン駆動 92 / カタログ 81 / AST ランキング 73）

**壁の発見はエンジン自身の成果物で行う**（IccTA が FlowDroid の call graph と `IPCMethods.txt` で
計装位置を決めるのと同型）。`run_ablation.sh` は cond_A（lowering 前）を必ず解析するので、その
`cond_A/r/` を読むだけで追加の pyre 実行は不要。

壁の**操作的定義**: taint が到達しうる呼び出し位置のうち、無改変エンジンが
- **S1 unresolved**: 呼び出し先を名指しできない —
  `call-graph.json` の `{"call":{"unresolved":["BypassingDecorators",["UnknownIdentifierCallee"]]}}`
  （AutoGPT の `command(**tool_call.arguments)` agent.py:277 は実際にこの形。型消去版 LangChain の
  `tool.run(...)` は `UnknownBaseType`）
- **S2 resolved_stub / resolved_obscure**: 名指しはするが本体まで taint を運べない —
  解決先の def 本体が自明（`pass` / `...` / `raise NotImplementedError` / 抽象メソッド。vanna の
  `VannaBase.run_sql`）、または `taint-output.json` のモデルに `obscure:*` 特徴が常時付く
- **S3 resolved_dispatch**: フレームワークの dispatch メソッドに解決される —
  `spec.presets.json` の `dispatch` 行（`BaseTool.run → _run/_arun`、`KernelFunction.invoke`、
  `ToolCollection.execute`、`BaseTool.call` …）に一致、または `higher-order-call-graph.json` の
  `higher_order_parameters` にその先が記録されている（LangChain: `BaseTool.run` 内の
  `Context.run(self._run)` に `Overrides{BaseTool._run}` が記録されている — 実物で確認済み）

のいずれかである位置。「AST が壁に見える」ではなく「**エンジンがそこで taint を失う**」を壁の定義に
する。`method_wall` fixture が型付き dict のせいで lowering なしでも検出されていた（壁ではなかった）
のは、AST 定義の誤りを示す例。

taint 到達度（T1: その位置に source 由来のフレーム、T2: 囲む callable に source、T3: BFS 到達）は
**採否の門ではなく並べ替えの補助**。`.pysa` を書く前は T1/T2 が空になるため（循環）、門にすると
フレームワーク規模では何も出ない。

**AST 側の補完 = レジストリ・アンカリング**（IccTA の explicit Intent に相当: 呼び出し位置が自分の
宛先集合を名指ししている）。値が def に解決する dict/list リテラル、`self.<attr> = <def>`、
`x.register(fn)` / `add_tool(fn)` をアンカーとし、その読み出し（`A[k](...)`、`A.get(k)(...)`、
`for t in A: t.run(...)`）を壁候補にする。エンジンが実体に解決している読み出しは「proposed」
（既定 off）、stub に解決していれば「confirmed」。

## 対象ごとのワークフロー（変更後）
0. 手動（不変）: `.pysa`、環境。任意の事前確認 `engine_walls.py dataset-scan`（TaintP2X 同梱の
   call graph から in-repo 未解決呼び出しの件数とファイルを数える。環境不要）。
1. `DRAFT=1 ./run_ablation.sh`: cond_A 構築 → pyre 1 回 → `draft/` に
   `plan.json` / `walls.md` / `spec.draft.json` / `wall_files.txt` / `candidates.draft.json` /
   `links.draft.json` / `anchors.json` / `env_report.json` / `report.md`。
   終了コードで即分かる: 2 = 壁の面が無い、3 = カタログが古い、4 = source 未宣言、env_failed。
2. **人のレビュー（システム固有の手作業はここだけ）**: `walls.md` を読む。1 行 = 1 壁:
   `file:line:col`、callee、idiom、resolver / key 式、エンジン状態（unresolved:<理由> /
   resolved_stub / resolved_obscure / resolved_dispatch:<API> / resolved）、taint 階層、origin
   （engine / anchor:<名> / catalog:<FW>:<API>）、候補 fan-out（lowered / filtered / unreasonable /
   phantom）、accept フラグ。confirmed 行は事前に accept、proposed と理由不明の行は off。
   フラグを反転、誤アンカーを名前で reject、候補キーを剪定（各キーに `_provenance`、各候補に
   `evidence`）、`env_report.json` から環境の穴を潰す。
3. `PLAN_JSON=draft/plan.json ./run_ablation.sh`（無人回帰は `ACCEPT_DRAFT=1`）: cond_B は
   `pipeline.run_plan`（グループ → `run_spec` → `build_links`（`reject_walls`・narrow・
   filter_unreasonable）→ emit）、diff、pyre、統計表 + 残差指標、`row.json`。
4. バッチ: `run_benchmark.py --stage draft` で 23 対象を無人で fetch / env / condA / scan / draft →
   1 回のレビューセッション → `--stage all` で condB / row → `aggregate` で
   `summary.{jsonl,csv,md}`（修論の表）。

## 見積り（対象 1 件あたり）
- 現状: spec の試行錯誤 + `WALL_FILES` の grep + 数値の手集計で 0.5〜2 人日
- 変更後: 発見は cond_A 後 1〜5 分 CPU（pyre 追加なし）。レビューは catalog / engine で一致する
  対象（AutoGPT、OpenManus、langchain*、llama_index*、SuperAGI、MCP、SK）で 20〜45 分、アンカーのみ
  の対象（vanna*、quivr）で 45〜90 分、面が無い対象（litellm、devika、pandas-ai）は約 5 分（exit 2
  を 1 行として記録）。`WALL_FILES` は入力から消える。23 件のレビューは合計 1〜2 日の見込み。
- 不変（方針通り）: `.pysa` 0.5〜2 時間、環境は数時間で依然として支配的コスト。

## コンポーネント（実装順）
| # | 場所 | 内容 | 再利用 |
|---|---|---|---|
| 1 | `links.py` | `WallRecord` に resolver / key_expr / col / engine_status / engine_reason / engine_tier / origin、`Candidate` に evidence。BoolOp のメンバーが def に解決するなら `boolop_member` 候補（level 1）。`reject_walls` を尊重（status `rejected_by_review`、`walls_rejected`）。`walls_by_engine_status` / `walls_by_origin` | `_runtime_bindings`, `_lookup_binding`, `build_links`, `dump/load_links` |
| 2 | `dispatch_lowering.py` | spec に `wall_positions`（`path:line[:col]`、_NEW_KEYS）、`reject_walls`・`wall_files`・`exclude_paths`（_META_KEYS）。`find_walls` は `wall_positions` があればその Call だけ（col が古ければ行 + callee 文字列で照合）。`describe_walls_ex`（col・囲む qualname 付き）。`_index_defs(include_nested)`（vanna の入れ子 def を名指し、`not_importable` として報告） | `_coerce_spec`, `find_walls_with_scope`, `_adopt_links` の行照合, `_index_defs` |
| 3 | `engine_walls.py`（新規） | `call-graph.json`（新旧スキーマ、ストリーミング）、`higher-order-call-graph.json`、`taint-output.json` のモデル、`functions.json` + 本体の自明性判定、`decorator-counts.json` × `modules.json`（in-repo のみ）、`override-graph.json`、`taint-metadata.json`（Pysa 版、`model_verification_errors`、source を持つモデル数）。S1/S2/S3 の判定、AST への位置合わせ、idiom 分類、`env_report.json`、`residual`（cond_B で残った未解決・obscure な taint 到達呼び出し数） | `links._runtime_bindings`, `_stmt_map`, `_idiom_of`, `ablation_helpers._issues` |
| 4 | `anchoring.py`（新規） | 上記のアンカリング。`anchors.json` に根拠行付きで出し、名前で reject 可能 | `links.index_registries`, `Candidate.from_def`, `_index_defs` |
| 5 | `spec.presets.json` + `catalog.py`（小） | 各プリセットに `match`（imports / base_classes / decorators）と `dispatch` 行を追加（`IPCMethods.txt` 相当。**1 ファイル・少数行**。FW ごとのファイルや必須 fixture は作らない）。`detect` / `check`（木にその API が無ければ「カタログが古い」を「面が無い」と区別） | `setup_project.FRAMEWORK_CALLS`, `_coerce_spec` |
| 6 | `draft.py`（新規） | 上記 1〜5 を結合して `plan.json` と レビュー束を書く。`run_spec(write=False)` のドライランで壁ごとの fan-out / phantom / no_args を記録し、`candidate_import_module` / `insert_before` はそれが必要と出たときだけ立てる。lowering 先のファイルにさらに壁があれば「stage 2 の可能性」としてヒント（多段の自動化はしない） | `pipeline.run_spec`, `describe_candidates` |
| 7 | `pipeline.py` | `run_plan`（グループを 1 つの `RedirectModuleBuilder` で回す。id は `G<i>` / `G<i>S<j>`）、`--plan`、`--walls` を任意に（`spec.wall_files` / `@wall_files.txt`）。報告に origin / engine_status / evidence | `run_spec`, `_remap_lowered_lines` |
| 8 | `ablation_helpers.py` / `run_ablation.sh` | `cmd_draft`、`PLAN_JSON`、`DRAFT=1` の停止、`ACCEPT_DRAFT=1`、`cmd_table` にエンジン状態別・origin 別・残差指標、`cmd_row`（対象 1 件 = `row.json`: 環境状態、pyre 秒、未解決理由別件数、壁の状態別件数、草案の手直し数、リンク統計、issue A/B、sink 組 A/B、新規到達 sink、残差、環境の穴、データセット同梱の参照 issue 数、outcome ∈ {env_failed, no_sources, no_surface, catalog_stale, no_walls, delta0, delta_pos}） | 既存の全サブコマンド |
| 9 | `run_benchmark.py` + `benchmark.json` | 23 行のマニフェスト（fetch は git tag / pypi、`pkg_root`、任意の subset 入口、**手動の** `pysa_models` と env、`dataset_dir`）。fetch → env → condA → scan → draft → review 門 → condB → row を `state.json` で再開可能に。`aggregate` で `summary.{jsonl,csv,md}`（1 対象 1 行 + FW 別の集計: カタログ行の命中数、アンカー数、confirmed / proposed / accepted） | `subset_extractor`, `TaintP2X/run_download_and_check.py` の 1200 秒・再開パターン |
| 10 | テスト | `test_engine_walls.py`（pyre 不要。`r_min/` に AutoGPT・lc_real・sk_real・データセット OpenManus・vanna の in-repo 抜粋をコミット）: AutoGPT は 1 行だけ（277:21 unresolved / T1）、lc_real は `resolved_dispatch`（S3）、vanna は `resolved_stub`（S2）、`method_wall` は already_resolved で草案に出ない。`run_bench.py --engine`。`test_anchoring.py`。S1/S2/S3/anchoring を 1 つずつ外した leave-one-out 報告（正直さの成果物） | `bench/`, `test_registration.py` |

1〜3 + 6 + 8 で単一対象のワークフロー（AutoGPT 同等）が動き、4〜5（アンカー・カタログ）と 9（バッチ）は
その後。多段の自動反復、ライブラリの vendoring 自動化、AST 分類付きデータセット走査は**保留**。

## リスクと対策
- **再現率（審査員が致命的とした点）**: Pysa が `BaseTool.run` や stub や型付きレジストリに解決した
  壁は unresolved に出ない → S2 / S3 を最初から一級のエンジン状態にし、lc_real / vanna の `r_min`
  テストでそれが発火することを固定する。
- **taint 階層と手動 `.pysa` の循環**: 階層は門にしない。
- **アンカーの誤検出**（LLM と無関係な dispatch 表: provider map、logging callback）: 値が def に
  解決するもののみ、エンジンが実体に解決する読み出しは off、名前で reject、on/off を ablation 軸に。
- **過剰検出の再発**（追記9 の vector.py 構文エラー）: 草案は `wall_positions` で位置を固定し
  `detect_*` を全て false、`resolver_hints` は必ずレジストリ名で修飾（`tool_map.get`）、ヒント無しの
  `detect_higher_order=true` は草案が絶対に出さない。
- **位置の脆さ**: `wall_positions` は前処理の入らない cond_A 側で取り、行 + callee 文字列で照合。
- **候補側は依然ヒューリスティック**（デコレータ調査 × プリセット、override-graph × カタログ、
  アンカー）: fan-out の性質は変わらない。ドライランで壁ごとの fan-out と phantom / no_args を
  人が受理する前に見せる。レガシー AutoGPT spec との sink 5 組一致を検証門にする。
- **Pysa 版への結合**: 未解決理由の一覧は 0.9.25 で経験的に作る。未知の理由は `other`、
  `taint-metadata.json` の版で管理。データセット同梱の graph は理由を持たないので count-only。
- **カタログの陳腐化・過適合**: 行数を最小にし、木ごとに `catalog.check`。命中数を毎行に出す。
  評価対象で較正した過適合リスクは修論に明記。
- **環境が支配的**: cond_A が完走しなければ発見も動かない。`env_failed` を独立した outcome に。
- **入れ子 def の対象**（vanna の `run_sql_*`）: `not_importable` として名指しのみ。hoist 前処理は
  「壁ファイル以外は差分なし」の不変条件を壊すので本計画から外す（否定的結果として記録）。

## 検証の門
- 門 0（pyre 追加なし）: `/tmp/f_inline/cond_A` から AutoGPT の 1 行だけが accept される。fixture の
  cond_A 木で `run_bench.py --engine` が全壁を期待理由で発見し、`method_wall` は already_resolved。
  `lc_real/cond_A/r` で 1398 / 1549 が `resolved_dispatch`、`sk_real` で 2103 が boolop +
  `boolop_member`。データセット同梱の旧スキーマ graph（AutoGPT classic、OpenManus、vanna）で
  期待の位置と状態。
- 門 1（AutoGPT）: `DRAFT=1` → `PLAN_JSON` で両 emit とも `EXPECT_A=0 EXPECT_SINKS_B=5`（レガシー
  spec と同じ (sink 種別, callee) 5 組）。
- 門 2（2〜3 件の Benchmark）: OpenManus（アンカー `tool_map` + カタログ）、langchain 1 版（S3）、
  vanna 1 版（S2 + `not_importable`）で draft → review → condB を通し、`row.json` と
  `summary.md` が出ること。レビュー分数を記録して見積りを較正する。

## 修論での位置づけ
IccTA は「どこを計装するか」をエンジン側の事実（FlowDroid の到達 call graph）と小さな固定
カタログ（`IPCMethods.txt`）で決め、リンク解決と計装は汎用。本設計はその Python / Pysa 版だが、
Android ICC が API レベルの現象（34 シグネチャ）なのに対し Python の動的ディスパッチは言語レベル
なので、**一次カタログはエンジン自身の解決結果**になる。壁を「無改変エンジンが (i) 呼び出し先を
名指しできない、または (ii) 名指しはするが taint を本体まで運べない（stub / obscure / 高階パラメータ
経由の dispatch メソッド）taint 到達位置」と操作的に定義し、未解決理由 → idiom → spec キーの対応表
と少数の dispatch 行が `IPCMethods.txt` の役を担う（小さく、版管理され、命中数で監査できる）。
レジストリ・アンカリングは explicit Intent 相当のロングテール補完であり、値解析ではない。

## 参考（今回の検証で確認した事実）
- `cond_A/r/call-graph.json` は JSON lines。AutoGPT の壁は
  `"277:21-277:51": {"call": {"unresolved": ["BypassingDecorators", ["UnknownIdentifierCallee"]]}}`。
- 型消去版 LangChain（`lc_real/cond_A_notype/r`）の壁 1398:26-1404:13 は `UnknownBaseType` で未解決。
- `higher-order-call-graph.json` の `langchain_core.tools.base.BaseTool.run` 1066:27-1066:76 に
  `contextvars.Context.run` の `higher_order_parameters` として `Overrides{BaseTool._run}` が記録
  されている（S3 の根拠）。
