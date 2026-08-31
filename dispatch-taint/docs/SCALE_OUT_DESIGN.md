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

**壁の発見はエンジン自身の成果物で行う**。IccTA との対応で言えばここは**同型ではなく違い**（添削 M8）:
IccTA は外部のリンク解析（IC3/Epicc の DB、または設定ファイルのリンク）が名指した文を `IPCMethods.txt` の署名
（約 30。非コメント行の数。実物 `soot-infoflow-android-iccta-master/res/IPCMethods.txt` は 34 行中 30 行）で限定して
計装し、FlowDroid は書き換え後に無改変で走る。本手法は外部のリンク解析を持たず、エンジン自身の未解決記録
（と stub / obscure / dispatch メソッドへの解決）を一次カタログにする。`run_ablation.sh` は cond_A（lowering 前）を
必ず解析するので、その `cond_A/r/` を読むだけで追加の pyre 実行は不要。

壁の**操作的定義**（添削 M7 で到達条件を外した）: in-repo の呼び出し位置のうち、無改変エンジンが
- **S1 unresolved**: 呼び出し先を名指しできない —
  `call-graph.json` の `{"call":{"unresolved":["BypassingDecorators",["UnknownIdentifierCallee"]]}}`
  （AutoGPT の `command(**tool_call.arguments)` agent.py:277 は実際にこの形。型消去版 LangChain の
  `tool.run(...)` は `UnknownBaseType`）
- **S2 resolved_stub / resolved_obscure**: 名指しはするが本体まで taint を運べない —
  解決先の def 本体が自明（`pass` / `...` / `raise NotImplementedError` / 抽象メソッド。vanna の
  `VannaBase.run_sql`）、または `taint-output.json` のモデルに `obscure:*` 特徴が常時付く。stub は種別を持つ
  （添削 C5 方針、2026-08-30 決定）: **abstract** = `@abstractmethod` / `abc.abstractmethod` / `abstractproperty`、または本体が
  `NotImplementedError` を raise するもの、**empty** = `pass` / docstring のみ / `...` / それ以外の raise。受け手から到達できる
  木内実装が無い abstract stub は候補 0 の **unlowerable な壁**として残り、empty stub は `resolved`（フェーズ C の規則 (ii)）
- **S3 resolved_dispatch**: フレームワークの dispatch メソッドに解決される —
  `spec.presets.json` の `dispatch` 行（`BaseTool.run → _run/_arun`、`KernelFunction.invoke`、
  `ToolCollection.execute`、`BaseTool.call` …）に一致、または `higher-order-call-graph.json` の
  `higher_order_parameters` にその先が記録されている（LangChain: `BaseTool.run` 内の
  `Context.run(self._run)` に `Overrides{BaseTool._run}` が記録されている — 実物で確認済み）

のいずれかである位置。「AST が壁に見える」ではなく「**エンジンがそこで taint を失う**」を壁の定義に
する。`method_wall` fixture が型付き dict のせいで lowering なしでも検出されていた（壁ではなかった）
のは、AST 定義の誤りを示す例。S2 の宛先集合は**受け手の静的型で絞ったクラス階層（CHA）**（後述、添削 C5）。宛先が空のときは
stub の種別で分かれる（abstract → unlowerable な壁、empty → resolved。フェーズ C の規則 (ii) と「添削の反映と限界」）。

taint 到達度（T1: その位置に source / parameter_source を持つモデルの位置が触れる（tito / sink の要約は数えない）、
T2: 囲む callable に source、T3: BFS 到達）は**採否の門ではなく報告のみ**。accept は engine_status / idiom だけで
決まる。`.pysa` を書く前は T1/T2 が空になるため（循環）、門にするとフレームワーク規模では何も出ない。`none` は
別の壁の背後や generic モデル下の位置を含む。`plan.json` の `counts.accepted_by_tier`、`row.json` / summary の
`accepted_tier_T1/T2/T3/none` に分布を出す（llama_index-0.9.28 / litellm / SK 全木では accept 済み壁の大半が none）。

**AST 側の補完 = レジストリ・アンカリング**（IccTA の explicit Intent に相当: 呼び出し位置が自分の
宛先集合を名指ししている）。値が def に解決する dict/list リテラル、`self.<attr> = <def>`、
`x.register(fn)` / `add_tool(fn)` をアンカーとし、その読み出し（`A[k](...)`、`A.get(k)(...)`、
`for t in A: t.run(...)`）を壁候補にする。エンジンが実体に解決している読み出しは「proposed」
（既定 off）、stub に解決していれば「confirmed」。

## 対象ごとのワークフロー（変更後）
0. 手動（不変）: `.pysa`、環境。任意の事前確認 `engine_walls.py dataset-scan`（TaintP2X 同梱の
   call graph から in-repo 未解決呼び出しの件数とファイルを数える。環境不要）。
1. `DRAFT=1 ./run_ablation.sh`: cond_A 構築 → pyre 1 回 → `draft/` に
   `plan.json` / `plan.draft.json`（読み取り専用 0444 の原本。レビュー手直しはこれとの diff — 添削 C7）/ `walls.md` /
   `spec.draft.json` / `wall_files.txt` / `candidates.draft.json` / `links.draft.json` / `anchors.json` /
   `env_report.json` / `report.md`。`plan.json` は version 2 で `tool_version`（`toolver.py`: engine_walls / links / draft /
   anchoring / catalog / pipeline / dispatch_lowering / spec.presets.json / ablation_helpers / run_ablation.sh の sha256）を持つ。
   終了コードで即分かる: 2 = 壁の面が無い、3 = カタログが古い、4 = source 未宣言、env_failed。
   再実行はレビュー済み `plan.json`（`plan.draft.json` と異なるもの）を保持し、`FORCE_DRAFT=1` でだけ捨てる。
2. **人のレビュー（システム固有の手作業はここだけ）**: `walls.md` を読む。1 行 = 1 壁:
   `file:line:col`、callee、idiom、resolver / key 式、エンジン状態（unresolved:<理由> /
   resolved_stub / resolved_obscure / resolved_dispatch:<API> / resolved）、taint 階層、origin
   （engine / anchor:<名> / catalog:<FW>:<API>）、候補 fan-out（lowered / filtered / unreasonable /
   phantom）、accept フラグ。confirmed 行は事前に accept、proposed と理由不明の行は off。
   フラグを反転、誤アンカーを名前で reject、候補キーを剪定（各キーに `_provenance`、各候補に
   `evidence`）、`env_report.json` から環境の穴を潰す。
3. `PLAN_JSON=draft/plan.json ./run_ablation.sh`（無人回帰は `ACCEPT_DRAFT=1`。`PLAN_JSON` はレビュー済み
   `plan.json` であって `plan.draft.json` ではない — preflight が拒否する）: cond_B は
   `pipeline.run_plan`（グループ → `run_spec` → `build_links`（`reject_walls`・narrow・
   filter_unreasonable）→ emit）、diff、pyre、統計表 + 残差指標、`row.json`。候補走査の根 `CAND_DIR` は壁の木
   `$WORK/cond_B/src` が既定（TARGET_SRC とそのコピーを両方走査すると全レジストリが 2 回見えて untrusted になり、
   実走 cond_B では narrowing が消えていた — 添削 C4）。cond_B の pyre が timeout / 失敗なら `row.json`（env_failed）を
   書いて exit 1（`cond_{A,B}/pyre_rc`、124 = timeout）。
4. バッチ: `run_benchmark.py --stage draft` でマニフェスト 26 行（TaintP2X の 23 対象 + 派生 3 行）を無人で fetch / env / condA / scan / draft →
   1 回のレビューセッション → `--stage all` で condB / row → `aggregate` で
   `summary.{jsonl,csv,md}`（修論の表）。

## 見積り（対象 1 件あたり）
- 現状: spec の試行錯誤 + `WALL_FILES` の grep + 数値の手集計で 0.5〜2 人日
- 変更後: 発見は cond_A 後 1〜5 分 CPU（pyre 追加なし）。レビューは catalog / engine で一致する
  対象（AutoGPT、OpenManus、langchain*、llama_index*、SuperAGI、MCP、SK）で 20〜45 分、アンカーのみ
  の対象（vanna*、quivr）で 45〜90 分、面が無い対象（litellm、devika、pandas-ai）は約 5 分（exit 2
  を 1 行として記録）。`WALL_FILES` は入力から消える。26 件（23 対象 + 派生 3 行）のレビューは合計 1〜2 日の見込み。
- 不変（方針通り）: `.pysa` 0.5〜2 時間、環境は数時間で依然として支配的コスト。

## コンポーネント（実装順）
| # | 場所 | 内容 | 再利用 |
|---|---|---|---|
| 1 | `links.py` | `WallRecord` に resolver / key_expr / col / engine_status / engine_reason / engine_tier / origin、`Candidate` に evidence。BoolOp のメンバーが def に解決するなら `boolop_member` 候補（level 1）。`reject_walls` を尊重（status `rejected_by_review`、`walls_rejected`）。`walls_by_engine_status` / `walls_by_origin` | `_runtime_bindings`, `_lookup_binding`, `build_links`, `dump/load_links` |
| 2 | `dispatch_lowering.py` | spec に `wall_positions`（`path:line[:col]`、_NEW_KEYS）、`reject_walls`・`wall_files`・`exclude_paths`（_META_KEYS）。`find_walls` は `wall_positions` があればその Call だけ（col が古ければ行 + callee 文字列で照合）。`describe_walls_ex`（col・囲む qualname 付き）。`_index_defs` はクラスメソッドと module-level def のみ（`include_nested` 分岐は呼び手が無く、二重入れ子 def を 2 回索引していたため削除 — 添削 minor）。vanna の入れ子 def は `anchoring.py` が `importable=False` の候補として名指しし、そのリンクは `phantom` | `_coerce_spec`, `find_walls_with_scope`, `_adopt_links` の行照合, `_index_defs` |
| 3 | `engine_walls.py`（新規） | `call-graph.json`（新旧スキーマ、ストリーミング）、`higher-order-call-graph.json`、`taint-output.json` のモデル、`functions.json` + 本体の自明性判定、`decorator-counts.json` × `modules.json`（in-repo のみ）、`override-graph.json`、`taint-metadata.json`（Pysa 版、`model_verification_errors`、source を持つモデル数）。S1/S2/S3 の判定、AST への位置合わせ、idiom 分類、`env_report.json`、`residual`（cond_B に残った taint 到達（T1/T2）の未解決・stub・obscure 呼び出し数。lowering が生成した `if __ctaudit_unreachable__:` ブロック内と生成 redirector モジュール内の位置は `generated` として除外し、cond_B の行をブロック範囲から cond_A の行へ逆写像した上で、lowered リンクを持つ壁を src_root 相対パス + 行で差し引いた net。raw / net / lowered_walls / generated_excluded / remapped / legacy_links（basename 鍵の旧 links.json で netted した印）に加え、net の分割 `residual_confirmed`（confidence が confirmed の net 壁 = 草案が事前 accept した行）と `residual_unlowerable`（`s2_reason == receiver_subclass_no_overrides` の net 壁 = 木内実装の無い abstract stub）を返し、各行に `confidence` / `s2_reason` を付ける。読み方: `net − residual_unlowerable` = lowering できたはずなのに残った壁、`residual_confirmed` = そのうち confirmed idiom の部分集合。proposed 行（定数キーの inline subscript 受け手 `d['k'].m()` など）も残差に数える — accepted-only 相当は `residual_confirmed` が答える — 添削 C1 / C5 方針）。CLI `residual` は stderr に 1 行要約（raw / net / confirmed / unlowerable …）を出し、stdout は JSON のまま。S2 行は `receiver_class` / `target_form`（plain / overrides）/ `s2_reason`（receiver_subclasses / receiver_unknown / receiver_subclass_no_overrides — 後者は abstract stub なら unlowerable な壁（candidates 0、proposed、accept false、note `unlowerable: no in-tree implementation of <owner>.<m>`）、empty stub なら resolved）を持つ（添削 C5） | `links._runtime_bindings`, `_stmt_map`, `_idiom_of`, `ablation_helpers._issues` |
| 4 | `anchoring.py`（新規） | 上記のアンカリング。`anchors.json` に根拠行付きで出し、名前で reject 可能。`Anchor.name` はモジュール修飾（`pkg.mod.REGISTRY` / `pkg.mod.Cls.attr`）、`Anchor.short` が表示名、`AnchorRead.binding`（`exact` / `inherited`）と `AnchorRead.anchor_closed` を持つ（添削 C6）。入れ子 def の phantom は `_index_defs` ではなく本モジュールが候補を `importable=False` にすることで生じる | `links.index_registries`, `Candidate.from_def` |
| 5 | `spec.presets.json` + `catalog.py`（小） | 各プリセットに `match`（imports / base_classes / decorators）と `dispatch` 行を追加（`IPCMethods.txt` 相当。**1 ファイル・少数行**。FW ごとのファイルや必須 fixture は作らない）。`detect` / `check`（木にその API が無ければ「カタログが古い」を「面が無い」と区別） | `setup_project.FRAMEWORK_CALLS`, `_coerce_spec` |
| 6 | `draft.py`（新規） | 上記 1〜5 を結合して `plan.json` と レビュー束を書く。`run_spec(write=False)` のドライランで壁ごとの fan-out / phantom / no_args を記録し、`candidate_import_module` / `insert_before` はそれが必要と出たときだけ立てる。ヒント（`plan.hints`、kind = stage2 / no_candidates / phantom / fan_out / unlowerable / env / catalog）: lowering 先のファイルにさらに壁があれば「stage 2 の可能性」（多段の自動化はしない）、候補 0 の abstract stub 行は `unlowerable`（`residual_unlowerable` に残る旨を明示）。`build_plan` は候補 0 の `resolved_stub` 行（`receiver_subclass_no_overrides`）を `--include-proposed` でも accept しない（アンカー読みがメンバーを供給した場合だけ例外） | `pipeline.run_spec`, `describe_candidates` |
| 7 | `pipeline.py` | `run_plan`（グループを 1 つの `RedirectModuleBuilder` で回す。id は `G<i>` / `G<i>S<j>`）、`--plan`、`--walls` を任意に（`spec.wall_files` / `@wall_files.txt`）。報告に origin / engine_status / evidence。`run_spec` / `run_plan` は書き換え前の `originals` スナップショットを取り、後段 stage / group の pin と記録を初段前スナップショットの行写像で cond_A 行に揃える（`_line_map` / `_remap_positions` / `_finish_records` / `_remap_lowered_lines(res, src_root, originals)`、添削 M3、「位置の脆さ」参照）。`AutoLinksProvider` / `FileLinksProvider` は `src_root` を受け、`file` を src_root 相対パスで照合（K1）。`pipeline.write_links` が `tool_version` を links.json に刻む。`run_plan` の統計はグループ順に依存しない（無条件 merge、添削 M2） | `run_spec`, `_remap_lowered_lines` |
| 8 | `ablation_helpers.py` / `run_ablation.sh` | `cmd_draft`、`PLAN_JSON`、`DRAFT=1` の停止、`ACCEPT_DRAFT=1`、`cmd_table` にエンジン状態別・origin 別・残差指標、`cmd_row`（対象 1 件 = `row.json`: 環境状態、pyre 秒、未解決理由別件数、壁の状態別件数、レビュー手直し数（読み取り専用の `plan.draft.json` と cond_B の plan の diff。原本が無い旧 bundle では `draft_source` にその旨が出て 0 は「観測不能」— 添削 C7）、リンク統計（`links.walls_lowered`）、`accepted_by_tier`、issue A/B、**sink 組 = (sink 種別, issue callable)** の A/B と新規 / 消失（旧鍵 (sink 種別, 第一呼び出し先) は `first_hops` に診断用として残す — 添削 C2）、残差（`residual.raw / net / confirmed / unlowerable`、`residual_rows[]` に confidence — C5 方針）、環境の穴、データセット同梱の参照 issue 数、`tool_version` / `plan_tool_version` / `versions_match`、outcome ∈ {env_failed, no_sources, no_surface, catalog_stale, no_walls（草案 accept 0）, no_candidates（accept > 0 かつ links_lowered 0。`outcome_reason` = no_links / phantom_majority / unreasonable_majority / filtered_*_majority / no_args_majority / mixed）, drafted（cond_B 未構築）, delta_pos（新規 > 0 かつ消失 0）, delta_mixed（新規 > 0 かつ消失 > 0）, delta_neg（新規 0 かつ消失 > 0）, delta0}。cond_B の pyre timeout は env_failed 行（「cond_B issues = 0」にはしない）） | 既存の全サブコマンド |
| 9 | `run_benchmark.py` + `benchmark.json` | 26 行のマニフェスト = TaintP2X の 23 対象 + 派生 3 行（`derived: true`、`derived_from` = 親対象: コミット済み AutoGPT subset 1、import 閉包 subset 2。TaintP2X 対象ではない）（fetch は git tag / pypi、`pkg_root`、任意の subset 入口、**手動の** `pysa_models` と env、`dataset_dir`）。fetch → env → condA → scan → draft → review 門 → condB → row を `state.json` で再開可能に。`aggregate` で `summary.{jsonl,csv,md}`（マニフェスト全行に 1 行、未着手は `pending`、派生行は別表・別集計（`derived_from`、`dataset_ref_issues_whole_repo` は派生行では空）、`walls_accepted`（accept 数）と `walls_lowered`（lowered リンクを持つ壁数）は別列、`residual_net` の隣に `residual_confirmed` / `residual_unlowerable`（分割前に作った row は空欄）、`accepted_tier_T1/T2/T3/none`、`outcome_reason`、`versions_match`（`yes` / `no` / `plan unversioned`）— 添削 M6 / M11 / C7 + FW 別の集計: カタログ行の命中数、アンカー数、confirmed / proposed / accepted。FW 表は明示 preset を優先し、import / 基底クラスの証拠がスコア 20 未満なら `(none)`。leave-one-out 表のセルは「accept 壁数 / dry-run リンク数（redirector）」に pyre 付きなら「[実 links_lowered; A→B]」を添え、plan と一致しない軸は `stale` 列で示す） | `subset_extractor`, `TaintP2X/run_download_and_check.py` の 1200 秒・再開パターン |
| 10 | テスト | `test_engine_walls.py`（pyre 不要。`r_min/` に AutoGPT・lc_real・sk_real・データセット OpenManus・vanna の in-repo 抜粋をコミット）: AutoGPT は 1 行だけ（277:21 unresolved / T1）、lc_real は `resolved_dispatch`（S3）、vanna は `resolved_stub`（S2）、`method_wall` は already_resolved で草案に出ない。`run_bench.py --engine`。`test_anchoring.py`。S1/S2/S3/anchoring を 1 つずつ外した leave-one-out 報告（正直さの成果物）。添削項目の固定（件数は書かない）: `test_engine_walls.py` は residual の相対パス鍵（同じ basename で別ディレクトリの links.json は net しない — C1）と S2 stub 方針（lc_0_0_131 の `agent.py:176/194` が unlowerable、`_validate_tools` 3 箇所が resolved、合成 fixture で abstract / empty の分類 — C5）、`test_registration.py` (G) は links 側の inline 受け手 idiom（`self.tools[k].run` / `getattr(o, k).m` / `(a or b).m` → method_call — M1）、`test_benchmark.py` は run_ablation.sh を stub pyre で 1 回 end to end に通す cond_B timeout の門（M5）と ablate の done / `--force` 契約（C3） | `bench/`, `test_registration.py` |

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
  多段（`stages`）や複数 group が同じ壁ファイルを順に書き換える場合も、後段の `wall_positions` / `reject_walls`
  は **cond_A の行**で書く（添削 M3）: `pipeline` は初段前のスナップショットからの行写像（lowering は挿入しか
  しないので元の行は順序を保って残る）で pin を現テキストへ写し、記録（`links.json` の `line`、ガード行の
  `wall=<file>:<line>` タグ）を cond_A 行へ戻す。pin の行が元の行でない（前段が挿入したブロック内、または
  前段後の行番号で書いた）場合は on_line フォールバックに落とさず `unmatched_position`（`walls_unmatched`）
  にする。pin 無しの detect 段は前段の壁を再検出して再度 lowering する（bench `stages_idempotent`）が、
  その記録も同じ写像で cond_A 行に戻す。最終テキストでの壁の行は `lowered_line` だけが持つ。生成ブロック内の
  位置は元の行を持たないので写像されず、書き換え後の座標のまま残る（壁としては扱わない）。
- **候補側は依然ヒューリスティック**（デコレータ調査 × プリセット、override-graph × カタログ、
  アンカー）: fan-out の性質は変わらない。ドライランで壁ごとの fan-out と phantom / no_args を
  人が受理する前に見せる。レガシー AutoGPT spec との sink 5 組一致を検証門にする。
- **Pysa 版への結合**: 未解決理由の一覧は 0.9.25 で経験的に作る。未知の理由は `other`、
  `taint-metadata.json` の版で管理。データセット同梱の graph は理由を持たないので count-only。
- **カタログの陳腐化・過適合**: 行数を最小にし、木ごとに `catalog.check`。命中数を毎行に出す。
  評価対象で較正した過適合リスクは修論に明記。
- **環境が支配的**: cond_A が完走しなければ発見も動かない。`env_failed` を独立した outcome に。
- **入れ子 def の対象**（vanna の `run_sql_*`）: `importable=False` の候補として名指しのみ（リンクは `phantom`、
  行の outcome はコードの語彙では `no_candidates` / `outcome_reason: phantom_majority`）。hoist 前処理は
  「壁ファイル以外は差分なし」の不変条件を壊すので本計画から外す（否定的結果として記録）。

## 検証の門
- 門 0（pyre 追加なし）: `/tmp/f_inline/cond_A` から AutoGPT の 1 行だけが accept される。fixture の
  cond_A 木で `run_bench.py --engine` が全壁を期待理由で発見し、`method_wall` は already_resolved。
  `lc_real/cond_A/r` で 1398 / 1549 が `resolved_dispatch`、`sk_real` で 2103 が boolop +
  `boolop_member`。データセット同梱の旧スキーマ graph（AutoGPT classic、OpenManus、vanna）で
  期待の位置と状態。
- 門 1（AutoGPT）: `DRAFT=1` → `PLAN_JSON` で両 emit とも `EXPECT_A=0 EXPECT_SINKS_B=5`（レガシー
  spec と同じ (sink 種別, 第一呼び出し先) 5 組。`EXPECT_SINKS_B` はこの旧鍵 `SINK_FIRST_HOPS` を門にする。
  `row.json` の鍵 (sink 種別, issue callable) では同じ実行が 2 組（再計測 2026-08-31・版 8092345c: EXPECT_SINKS_B=5 は通過、現行鍵の sink 組は 2・新規 2・消失 0））。
- 門 2（2〜3 件の Benchmark）: OpenManus（アンカー `tool_map` + カタログ）、langchain 1 版（S3）、
  vanna 1 版（S2 + 入れ子 def の `importable=False` 候補 → `no_candidates` / `phantom_majority`）で draft → review → condB を通し、`row.json` と
  `summary.md` が出ること。レビュー分数を記録して見積りを較正する。
- **最終版での門の再確認（再計測 2026-08-31・版 8092345c）**: AutoGPT ゲート 0→7（`EXPECT_SINKS_B=5` 通過、現行鍵 2 組）、
  SK ゲート 1 の回帰 0→1（code 5001）、`bench --pyre --engine` は 31 fixture × 2 emit で全 PASS（エンジン期待値も一致）。門 2 の
  3 対象は下のフェーズ B / C の値に一致し、全 26 行が 1 つの `tool_version` に揃った（summary の全行 `versions_match: yes`、脚注の
  異常リストは全て「(none)」）。

## 修論での位置づけ
IccTA は「どこを計装するか」を外部のリンク解析（IC3/Epicc の DB、または設定ファイル）が名指した文を
小さな固定カタログ（`IPCMethods.txt`、約 30 = 非コメント行。34 行は行数）で限定して決め、リンク解決と
計装は汎用、FlowDroid は無改変で走る（添削 M8: FlowDroid の call graph は使っていない）。本設計はその
Python / Pysa 版だが、Android ICC が API レベルの現象なのに対し Python の動的ディスパッチは言語レベル
で、外部のリンク解析も無いので、**一次カタログはエンジン自身の解決結果**になる — ここが IccTA との
最大の違いであり、本手法の独自性でもある。壁を「無改変エンジンが (i) 呼び出し先を名指しできない、
または (ii) 名指しはするが taint を本体まで運べない（stub / obscure / 高階パラメータ経由の dispatch
メソッド）in-repo の呼び出し位置」と操作的に定義し（到達条件は含めない、添削 M7）、未解決理由 → idiom →
spec キーの対応表と少数の dispatch 行が `IPCMethods.txt` の役を担う（小さく、版管理され、命中数で監査できる）。
レジストリ・アンカリングは explicit Intent 相当のロングテール補完であり、値解析ではない。

## 参考（今回の検証で確認した事実）
- `cond_A/r/call-graph.json` は JSON lines。AutoGPT の壁は
  `"277:21-277:51": {"call": {"unresolved": ["BypassingDecorators", ["UnknownIdentifierCallee"]]}}`。
- 型消去版 LangChain（`lc_real/cond_A_notype/r`）の壁 1398:26-1404:13 は `UnknownBaseType` で未解決。
- `higher-order-call-graph.json` の `langchain_core.tools.base.BaseTool.run` 1066:27-1066:76 に
  `contextvars.Context.run` の `higher_order_parameters` として `Overrides{BaseTool._run}` が記録
  されている（S3 の根拠）。

---

## 実装状況と門 0 の結果（2026-08-29）

**コンポーネント 3 実装済み**: `taintp2x_extension/engine_walls.py`。
`scan <cond>` / `dataset-scan <call-graph.json>` / `residual <cond_B> --links` / `extract <cond> --out r_min/<name> --files …`。
API は `scan() -> ScanResult(walls: [EngineWall], env, counts, sites_by_file)`、`ScanResult.status_at(file, line)`
（AST 側が壁と見た位置のエンジン状態 — `already_resolved` の判定用）、`render_md()` / `write_outputs()`
（`engine_walls.json` / `env_report.json` / `walls.md`）。テストは `test_engine_walls.py`（`r_min/` 抜粋、pyre 不要。
項目数は増え続けるので本文に書かない — 全件 pass（コマンドで確認））、`test_pipeline.py`、`bench/run_bench.py --engine`。

| 門 0 の項目 | 結果 |
|---|---|
| AutoGPT `/tmp/f_inline/cond_A` から 1 行だけ accept | ○ 150 サイト / 未解決 96 → 壁 1 行（277:21、T1）。コミット済み cond_A（別マシンで解析）でも同じ |
| fixture の cond_A 木で全壁を期待理由で発見 | ○ 6 件（subscript / getattr → `UnknownCallCallee`、higher_order / boolop → `UnknownIdentifierCallee`、method_wall → `UnknownBaseType`） |
| `method_wall` は already_resolved | **設計の誤り**: 現 fixture は実行時登録で真の壁。型付き dict の `typed_registry_resolved` fixture を追加し、`--engine` で `resolved`（草案に出ない）を固定 |
| lc_real 1398 / 1549 が `resolved_dispatch` | ○ 型付き木で `resolved_dispatch:BaseTool.run/arun`。ただし **proposed**（下記） |
| sk_real 2103 が boolop | ○（open BoolOp、T2）。`boolop_member` 候補はコンポーネント 1 |
| データセット旧スキーマで期待の位置と状態 | △ 理由なし（`unresolved: true`）の count-only。位置は出るが状態は分からない |

**設計からの修正点**（詳細は RESEARCH_DIRECTION.md 追記11）:
- S3 の確信度: カタログ一致でも、`override-graph.json` で impl（`_run`）に override があり
  `higher-order-call-graph.json` がそれを辿っている（型付き木）なら **proposed**。lc_real 型付きは cond_A で
  既に issue が出る。S3 が壁になるのは型消去時か本体が Obscure のとき。
- `UnknownBaseType` は受け手が subscript / getattr / BoolOp で選ばれたときだけ壁 — 先行する文での束縛
  （`t = REG[k]; t.run()`）も、呼び出し位置での直接選択（`self.tools[k].run()`、`REG[k].m()`、`getattr(o, k).m()`、
  `(a or b).m()`、レビュー M1）も同じ。呼び出し・属性チェーン・仮引数・ループ変数で束縛された受け手は「型の穴」
  として `env_report` へ（M1 修正後の再計算: AutoGPT 53/53、lc_real 843/918。残り 75 行は壁行、うち confirmed 12。
  束縛規則はその後も変わったが（27 サイトの `loop` 誤帰属の修正など）版 8092345c で確定し、`r_min/m1_bindings` と
  `test_engine_walls`（全件 pass）が lc_real / AutoGPT のエンジン状態を固定する — 上の値は最終版の r_min 木で記録したもの
  （再計測 2026-08-31・版 8092345c））。
  束縛は呼び出し位置より前の文から決め、内包表記は独自スコープなので、後続の `[t.name for t in xs]` が先行する
  束縛を上書きしない（M1 再修正、`r_min/m1_bindings` で固定）。
- `param_call` / `loop_call` / `call_call` は proposed（候補は呼び出し側 → anchoring）。`loop_call` はタプル展開
  `for k, v in REG.items(): v(x)` と内包表記の generator 変数（内包表記の**内側**の呼び出しだけ）も含む（M1）。
  束縛が全く見えない Name callee（lambda の仮引数など）で理由が dispatch 種（`UnknownIdentifierCallee`）の行は
  env に落とさず proposed 行として残す。
- higher-order 証拠は `Overrides{…}` 先に限定（コールバックを受け取るだけの関数を S3 にしない）。
- `@overload` スタブは本体でない（実装 def を優先）。コピーした結果は cond 相対パス全体の接尾辞一致でのみ in-repo。

残り: 1・2（`wall_positions` / `reject_walls`）→ 6（`draft.py`）→ 8（`run_ablation.sh`）→ 4・5 → 9。

### フェーズ A（コンポーネント 1・2・6・7・8）実装済み（2026-08-29 夜）
- **1 `links.py`**: `WallRecord` に col / resolver / key_expr / engine_status / engine_reason / engine_tier / origin /
  confidence、`Candidate` に evidence / importable、`LoweringStats` に walls_rejected / walls_unmatched /
  walls_by_engine_status / walls_by_origin。BoolOp の def 解決メンバーを `boolop_member` 候補（level 1、
  `PRIMARY = default_handler` の別名は 1 ホップ追う）。`reject_walls` と `accept: false` は `rejected_by_review`。
  入れ子 def（`importable=False`）へのリンクは `phantom`。resolver / key は `engine_walls.describe_call` と同じ語彙。
- **2 `dispatch_lowering.py`**: spec に `wall_positions`（文字列 `path:line[:col]` または
  `{"at", "callee", "end", "accept", "match_level", origin/engine_*}`）、`reject_walls`、`wall_files`、`exclude_paths`。
  `find_walls_ex` は位置指定があれば**その Call だけ**（start+end → callee 文字列 → 同位置の最外 Call → 行 + 一般検出 →
  行の先頭 Call の順で照合、無ければ `unmatched_position`）。`describe_walls_ex`、`_index_defs`（クラスメソッド + module-level def
  のみ。入れ子 def は `anchoring.py` の `importable=False` 候補 → リンクは `phantom`）。
- **6 `draft.py`**: `engine_walls.scan` → `derive_spec`（`_provenance` 付き）→ `run_spec(write=False)` のドライラン →
  `plan.json`（ファイルごとの group、`wall_positions` に accept）+ `walls.md` / `report.md` / `spec.draft.json` /
  `wall_files.txt` / `candidates.draft.json` / `links.draft.json` / `env_report.json`。fan-out > 16 で narrowing 無しの
  行は proposed に降格。BoolOp 壁は `match_level: 1`。stage 2 の可能性・候補ゼロ・phantom・fan-out・unlowerable（木内実装の無い
  abstract stub、候補 0）・環境の穴をヒントに。
- **7 `pipeline.run_plan`**: group ごとに `run_spec`（`stages` があれば多段）、共有 `RedirectModuleBuilder`、
  id `G<i>W..` / `G<i>S<j>L..`、`--plan`、`--walls` 任意。候補回収の全木走査は memo 化（lc_real 113 群で 16 秒）。
- **8 `run_ablation.sh` / `ablation_helpers.py`**: `DRAFT=1`（cond_A → pyre → draft → 停止、exit = outcome）、
  `PLAN_JSON=`、`ACCEPT_DRAFT=1`、pyre 秒の記録、table にエンジン状態別 / origin 別 / 却下 / 残差、`row.json`。
- テスト: `test_draft.py`（全件 pass、コマンドで確認）、bench に `pinned_position` / `rejected_wall` / `boolop_member` / `two_walls_before_stub`（添削 C1）fixture（計 31、2026-08-30）。
- 門 1 の結果:
  - SK 1.39.3: 草案 stage 1（BoolOp 壁、`boolop_member` 1 件）+ 解析者固定 stage 2 → `pipeline.py --plan` → pyre 67 s →
    **0→1（5001）**、sink 組は既知の cond_B と同一。stage 1 に `insert_before` / `candidate_import_module` は不要。
  - AutoGPT v0.5.0: `DRAFT=1` → `PLAN_JSON`（inline / redirector）→ `ACCEPT_DRAFT=1` の全経路で **0→7、sink 5 組、
    regression OK**（`EXPECT_SINKS_B` は旧鍵の 5 組。現行鍵では 2 組・新規 2・消失 0（再計測 2026-08-31・版 8092345c: この行は
    `AutoGPT-classic-subset`、EXPECT_SINKS_B=5 は通過））、`row.json` outcome=delta_pos、
    residual net 0、無人実行（レビュー未実施。旧記述の「手直し 0」は `plan.draft.json` が無く観測不能だった — 添削 C7）。
    pyre は `PYRE_SEARCH_VENV=0` で 5〜6 秒（venv 入りは 325 秒）。→ **門 1 通過**。

### フェーズ B（コンポーネント 4・5）実装済み（2026-08-29 深夜）
- **4 `anchoring.py`**: アンカー = 値が def / class に解決する dict / list リテラル、`self.<attr> = <def>`（vanna の
  `run_sql_*`、入れ子 def は `importable=False`）、`x.register(fn)` / `add_tool(fn)`、`self.attr[k] = fn`。
  **closed の定義は実装が保証する条件だけ**（添削 C6）: アンカーは定義モジュールで修飾して鍵付け（`pkg.mod.REGISTRY` /
  `pkg.mod.Cls.attr`。別モジュールの同名レジストリは別アンカー、同名属性を持つ無関係なクラスは結合しない）。closed は
  (a) 全メンバーが可視の def / class / インスタンス、(b) 名前がモジュールレベルで 1 回だけ束縛され、どのスコープでも
  変更されない（`NAME[k] = v`、`del`、`.update / .pop / …`、`+=` / `|=`、`global NAME` + 代入。import や
  モジュールレベルの別名経由も含む — 別名 `ALIAS = NAME` 自体が open 理由）、(c) `Cls.attr` ではさらに `self.attr = <実行時値>`
  （仮引数・呼び出し・None・空リテラル…）が無く、クラス本体や木内の基底に同名の宣言（`Field(...)` / `PrivateAttr` / 注釈）が
  無く、サブクラスがそれを束縛しない、のとき。サブクラスからの `self.attr` 読みは **inherited 読み**（`binding: inherited`、
  `anchor_closed: false`）= 候補追加のみで narrowing も confirmed もしない。木の外のオブジェクトへの登録（`os.environ`、
  `loguru.logger`）はアンカーでない。読み出し（`A[k](..)`、`A.get(k)(..)`、`t = A[k]; t.run(x)`、
  `for t in A: t.run(x)` / `t(x)`、`self.attr(..)`）をエンジン行に結合: エンジン壁 + closed アンカー → メンバーを
  level-1 候補にし narrowing、エンジンが resolved の読み出し（型付きレジストリ）や site 無しは proposed（off）。
  文字列の map はアンカーにしない。関数ローカルの dict もアンカーにしない。`--reject-anchor <anchors.json の修飾名>`（短名も可）。
  `anchors.json` に根拠行（`name` は修飾名、`short` が表示名、読みに `binding` / `anchor_closed`）。限界（記録）:
  メソッド経由で `self.<attr>` に格納する登録は属性に結び付けない、仮引数を回す内包表記のメンバーは不明、inherited 読みは
  決して narrowing しない（vanna 型の「基底で代入した属性をサブクラスが読む」は proposed のまま）、クラス本体の宣言が
  基底にあると保守的に open（llama_index の `AnthropicProvider.*`、OpenManus の `Bash._session`）、src_root 外のモジュールに
  住むレジストリは木内で埋められても見えない。`test_anchoring.py` は C6 の負例（無関係な同名属性、別モジュール同名レジストリ、
  setter 再束縛、`+=`/`|=`、別名、相対 import）を含む — 全件 pass（コマンドで確認）。
- **5 `spec.presets.json` + `catalog.py`**: 各プリセットに `match`（imports / base_classes / decorators）と
  `dispatch` 行（計 17 行: langchain 4、semantic_kernel 2、openmanus 2、llama_index 5、fastmcp 2、openai_agents 1、superagi 1）。
  `match.imports` は dotted 接頭辞（from-import は import 名も）で、相対 import は数えない。openmanus は `app.tool` / `app.agent`
  （+ 基底 `ToolCallAgent`）、openai_agents は `agents.tool` / `agents.run` / `agents.function_tool` / `agents.Runner` /
  `agents.RunContextWrapper` に一致。種プリセット（`catalog.top_preset`）は import か検出プリセット間で一意な基底クラスの
  証拠が要り、デコレータ単独の命中（click の `@command`）では種にならない → litellm は `(none)`、SuperAGI は `superagi`（添削 M4）。
  行は `{"api", "impl", "base"}` で、`base` が候補の基底クラス（`ToolCollection.execute` → `BaseTool` の `execute`。
  門 2 の OpenManus で `ToolCollection` を基底と誤導出して候補 0 になった修正）。草案は `catalog.detect` で
  最上位に検出したプリセットの回収キー（base classes / register methods / wrappers）を、木から導けなかった
  ときの既定として使う（provenance に「preset X (detected)」）。
  `engine_walls` はこのファイルを既定のカタログにする。`catalog.detect` で木の使用 FW を採点（相対 import は数えない）、
  `top_preset` が spec の種になるプリセット（import か判別力のある基底クラスの証拠。デコレータ単独では選ばない）、
  `framework_of` が表に載せる帰属 FW（種プリセットのスコアが `match.min_score`、既定 `FW_MIN_SCORE`=20 以上のときだけ。
  未満は `(none)`。`plan.catalog.framework` / `row.json` の `draft_framework` / summary.md の by framework 表で共通）。
  草案が何も accept せず、帰属 FW の dispatch API が**木の中**（`env_report.json` の `catalog_status`: `functions.json`
  の名前のうちモジュールが in-repo ファイルに対応する callable）に 1 つも無いなら `catalog_stale`（exit 3）。解析
  search path（venv）にだけある行は `catalog_status_search_path` に分けて記録し「on the analysis search path only」と
  明示する。閾値未満の偶発 import（MetaGPT の semantic_kernel 9 件）は帰属も stale 判定も起こさない（添削 M4）。
- **10（前倒し）**: `--disable S1,S2,S3,anchoring`（engine_walls / draft）で leave-one-out、`row.json` に記録。
- **精度レバー追加（門 2 の lc_real 全木で必要になった）**: `x.m(...)` の壁に対し、クラスメソッド候補は名前が `m` か
  カタログの impl 対応（`run → _run` 等、spec `dispatch_impl_map`、草案がカタログから導出）に一致するものだけを
  残す（`unreasonable`、メソッド名版の `UnreasonableLinksRemover`）。関数候補・アンカー・BoolOp・明示候補は対象外。
  `self._validate_tools()` のような stub 壁に `BaseTool._run` 13 件が付く問題を消す。`dispatch_impl_map` は **active な FW
  （木が import する FW + 明示 `--preset` + 検出した top preset）のカタログ行**から作り、空でも書く
  （`LoweringSpec.impl_map_source = "spec"`）。`DEFAULT_IMPL_MAP` はキーの無い手書き spec でだけ生きる（`"default"`）。
  「検出 FW のみ」でも「全 FW の合体」でもない（添削 M10）。偶発 import（langchain-0.0.131 は 4 ファイルで llama_index を
  import）でその FW の行が入るのでレビューでキーを剪定してよい。`benchmark_out` の plan.json は合体 map のままで再草案待ち。
- **S2 の限定（門 2 の vanna で必要になった）**: `resolved_stub` / `resolved_obscure` は受け手が動的なとき
  （`self.x()`、変数のメソッド）だけ壁にする。自分の静的な名前で呼ばれる stub（`error_deprecation()` のような
  raise するだけの関数、`super().m()`）は「関数が raise するから taint が失われる」のであって
  ディスパッチではない → `resolved`（note 付き）。vanna の 45 accept → 11 に。
- 門 2 の結果（RESEARCH_DIRECTION.md 追記13）:
  - langchain（lc_real 型消去、全木・無人）: 219 行 → accept 102、52 壁 / 553 リンク lowering、pyre 56 s →
    **3 issue / 3 sink 組**（基準 1 組 + REPL 系 `_run` 2 組）、residual net 0。
  - OpenManus（`app/`、無人）: 1 回目はカタログ行の候補基底誤りで候補 0 → `no_walls`（正直に記録）。`base` 修正後、
    20 壁中 12 accept、30 リンク、pyre 379 s → **0→12 issue / 12 sink 組**（RCE 4・FileSystem 4・SSRF 4）、residual net 0。
  - vanna 0.6.2: S2 壁 11 行、アンカー `VannaBase.run_sql`（closed、入れ子 def 11 本）→ **77 リンク全 phantom**、
    3→3、`no_walls`（設計どおりの否定的結果: 入れ子 def は名指しのみ）。
  → **門 2 通過**（3 件とも無人実行 = レビュー未実施。修正は 2 件ともシステム側。旧記述の「手直し 0」は観測不能だった値 —
  添削 C7）。

### フェーズ C（コンポーネント 9・10）実装（2026-08-30）
- **9 `run_benchmark.py` + `benchmark.json`**: 26 行のマニフェスト（TaintP2X の 23 対象 + 派生 3 行 `derived: true`、
  `derived_from` = 親対象 — 添削 M11。fetch = git tag / pypi sdist / path、`pkg_root`、
  `flatten`、**手動の** `pysa_models`（`benchmark_models/`）、`dataset_dir`、preset、`search_venv`、`pyre_timeout`）。
  `fetch → env（src 組立 + dataset-scan の事前確認 + 参照 issue 数）→ draft（`DRAFT=1`、cond_A の pyre 1 回）→
  レビュー門（`review.minutes` が null なら `--accept-draft` 無しでは condB を拒否）→ condB（`REUSE_COND_A=1`、
  cond_A の pyre 再実行なし）→ row` を `state.json` で再開可能に。`aggregate` で `summary.{jsonl,csv,md}`
  （マニフェスト全行に 1 行 — 未着手は `pending`、派生行は別表・別 outcome 行 — + FW 別: カタログ命中・アンカー・
  confirmed / proposed / accepted・outcome 分布 + leave-one-out 表。`walls_lowered` は lowered リンクを持つ壁数、accept 数は
  `walls_accepted` — 添削 M6）。
  `--stage ablate` は `--disable` 各軸の草案（pyre なし）、`--ablate-pyre` で軸ごとの cond_B。
- `run_ablation.sh` に `PYRE_TIMEOUT`（既定 1200 s、TaintP2X の予算）と `REUSE_COND_A=1`。
- **10**: `run_bench.py --record` で全 fixture の AST 壁に対するエンジン状態を採取し `engine` 期待値を埋める。
- **leave-one-out が見つけた 2 つの規則（langchain 0.0.131）**: (i) S2（stub / abstract メソッド）壁の実行時 callee は
  オーバーライドであり、関数はメソッドをオーバーライドできない → レジストリ / tool-list 由来の**関数候補は S2 壁では
  unreasonable**（アンカー・明示候補は除外しない）。full 草案で `registry_vars` の関数 19 件が `AgentOutputParser.parse`
  に流れ込み fan-out 上限で落ちていたのが −S1 で露見した。(ii) S2 壁の候補は**エンジン自身の `override-graph.json`**
  （`BaseCache.lookup → InMemoryCache / RedisCache / SQLAlchemyCache`、`Agent._validate_tools → 3 agent`）から取る
  （`dispatch_targets`、草案では closed アンカー相当の level-1 候補）。**宛先集合 = 受け手の静的型で絞ったクラス階層（CHA）**
  （添削 C5。当初は宣言クラスの全 override を取っており、`Agent._validate_tools` の受け手 ChatAgent / ConversationalAgent /
  ConversationalChatAgent（サブクラスに override 無し）に型上不可能な 9 リンクを足していた）: `call-graph.json` の
  `receiver_class` とその推移的サブクラス（`override-graph.json` + 木内 `ClassDef` の基底で CHA）に属する override だけ。
  受け手のサブクラスが何も override しなければ `s2_reason: receiver_subclass_no_overrides` で、stub の種別で分かれる（方針決定
  2026-08-30、添削後）: **empty** stub（`pass` / docstring のみ / `...` / NotImplementedError 以外の raise）を具象の葉の受け手で
  呼ぶなら `resolved`（壁でない。`cls._validate_tools`（本体 `pass`）の兄弟 3 箇所）、**abstract** stub（`@abstractmethod` /
  `abc.abstractmethod` / `abstractproperty`、または `NotImplementedError` を raise）を owner 自身か非実装サブクラスの受け手で呼び、
  受け手から到達できる木内 override が無いなら **unlowerable な壁**として残す（`resolved_stub`、候補 0、confidence proposed、
  accept false、note `unlowerable: no in-tree implementation of <owner>.<m>`、`residual_unlowerable` に数える。
  `agents/agent.py:176/194` の `self.output_parser.parse` = `AgentOutputParser.parse`）。理由: 壁の定義（エンジンが名指しは
  するが taint を運べない位置）ではこの抽象呼び出しも壁であり、木内にリンク先が無いからといって隠すと残差を過小に見せる。
  未決の縁: NotImplementedError 以外の例外を raise するだけの本体は empty 扱い。受け手の型が無い
  （`typing.Protocol` 受け手を含む）なら `receiver_unknown` で候補はデコレータ / アンカー回収から（unlowerable 規則はここへは
  広げない）。`row.json` / walls.md に
  `receiver_class` / `target_form` / `s2_reason`。`r_min/lc_0_0_131` に固定。「`skipped_overrides` が理由」は 0.0.131 では
  成立しない（`type.__init__` / `object.__init__` のみ）。
- **サブセット（環境側の手作業の半自動化）**: マニフェストの `subset: {"pkg", "entries"}` で、入口ファイルからの
  import 閉包だけを残し（他のモジュールは削除）、外部依存は `subset_extractor` の deps_iso（symlink）/ stubs_min で隔離、
  `PYRE_EXTRA_SEARCH` で search_path に加える（venv は外す）。langchain 0.0.327 / 0.2.5 は全体では 1200 秒で打ち切られる
  ので、`langchain/agents/agent.py` を入口にした `*-agents-subset` 行を追加。**サブセット行と全体行は対照になっていない**
  （添削 M9）: AutoGPT 全体 vs `AutoGPT-classic-subset`、langchain-0.0.327 全体 vs subset は fetch / pkg_root / search_venv /
  `.pysa` の名前付け / deps_iso が同時に違う。サブセット + `.pysa` では delta_pos、全体 + generic では no_sources / env_failed
  という事実だけを書き、venv 除外とサブセット化を同時に適用したため要因は分離していない。
- **バッチで見つかった規則の穴 3 つ（修正済み）**: (i) カタログ行の接尾辞衝突（`BaseTool.__call__` が OpenManus と
  llama_index に当たる）→ 行に FW 固有のモジュール接頭辞、presets を組み込み既定より優先。(ii) `x = f() or {}` の
  BoolOp 受け手（呼び出し・リテラルの代替）は選択ではない → closed で Name のみの BoolOp に限定。(iii) `row.json` の
  outcome: 草案の判定を優先、lowering 済みで cond_B 無しは `env_failed`。
- **SuperAGI で見つかった規則 3 つ（修正済み、追記14）**: impl メソッド候補は dispatch API / `__call__` 経由の壁にのみ、
  名前で有界化された method 壁は fan-out 上限の対象外、`dispatch_impl_map` は active FW（import + 明示 preset + 検出 top）の
  行のみ（添削 M10 で「検出 FW のみ」から改めた）。
- **添削ワークフローの確認済み指摘 1 件目（修正済み）**: サブセット閉包の `__init__` 再エクスポート・相対 import の扱い。

---

## 添削の反映と限界（2026-08-30、添削レポート C1〜C7 / M1〜M11）

添削（2 名の検証者）で反証された定義・数値を上で書き換えた。修論に載せる前提として次を明記する。

**定義（実装通り）**
- 壁 = 無改変エンジンが (i) 名指しできない、または (ii) 名指しはするが taint を本体へ運べない in-repo 呼び出し位置。到達条件なし、T1/T2/T3 は報告のみ（M7）。
- sink 組 = (sink 種別, issue callable)。旧鍵 (sink 種別, 第一呼び出し先) は `first_hops` 診断のみ、`EXPECT_SINKS_B` はその旧鍵を門にする（C2）。
- outcome = env_failed | no_sources | no_surface | catalog_stale | no_walls | no_candidates | drafted | delta_pos（new>0, lost==0）| delta_mixed | delta_neg | delta0（C2 / M5）。`run_benchmark._table_outcome` は環境判定（no_sources / no_surface / catalog_stale）を空虚な `0 → 0` の delta0 より優先する: cond_B が走っても草案の環境判定どおり空なら、表は delta0 でなくその環境判定を残す（AutoGPT 全木は cond_B が `0 → 0` でも表は `no_sources`）。
- residual = 生成ブロック・生成 redirector を除き、cond_B の行を cond_A に逆写像した後の、cond_B に残るエンジン未解決（T1/T2）in-repo 呼び出し位置。proposed 行も含む（C1）。net は `residual_confirmed`（confirmed 行）と `residual_unlowerable`（木内実装の無い abstract stub）に分割し、`row.json` `residual.confirmed / unlowerable`・`summary.md` の同名列に出す（C5 方針、2026-08-30）。
- closed アンカー = 上の (a)(b)(c) を実装が確認できたものだけ。inherited 読みは narrowing しない（C6）。
- S2 候補集合 = 受け手の静的型で絞った CHA の宛先集合（C5）。宛先が空なら stub の種別で分かれる: abstract → unlowerable な壁（候補 0、proposed、off、`residual_unlowerable`）、empty → resolved（2026-08-30 決定）。Protocol 受け手は `receiver_unknown` のまま。
- catalog_stale = 帰属 FW の dispatch API が in-repo callable に無い（venv のみの存在は別途報告、stale のまま）（M4）。
- impl map = active FW（import + 明示 preset + 検出 top）のカタログ行。`DEFAULT_IMPL_MAP` は手書き spec の既定のみ（M10）。
- マニフェスト = TaintP2X の 23 対象 + 派生 3 行（M11）。

**限界（修論に書く）**
1. **較正と評価の分離が無い**: 規則（S2 の受け手限定、BoolOp 受け手、メソッド名フィルタ、fan-out 上限の例外 …）とカタログ行は評価対象を見ながら反復して較正した。held-out の対象は無い。
2. **「レビュー手直し 0」は「無人実行（レビュー未実施）」の意味**であり「草案に手直しが不要だった」ではない。手直し数は `plan.draft.json` との diff で初めて観測可能になった（C7）。`benchmark_out` の既存 row は原本が無く「観測不能」。
3. **数値の出所の一本化**: plan / row / ablation / state の全てに `tool_version`（追跡ファイルの sha256）を刻み、summary は不一致行を `versions_match: no` / `plan unversioned` で示す。**全 26 行を版 8092345c で再実行済み（2026-08-31）**（`run_benchmark.py --stage all --from draft --force --keep-cond-a --accept-draft` → `--stage ablate --ablate-pyre --force --only AutoGPT-classic-subset langchain-0.0.131 OpenManus` → `--stage aggregate`）: residual / links_lowered / sink 組 / outcome / leave-one-out は 1 つの `tool_version` に揃い、summary の全行が `versions_match: yes`、脚注の異常リストは全て「(none)」。**較正は同じ対象で行った（held-out なし）点は限界 1 として残る。**
4. **receiver_unknown の accept**: `typing.Protocol` 受け手（langchain-0.0.131 の `LoadingCallable.__call__` 3 壁など）は候補集合がデコレータ / アンカー回収由来で、48 リンクを lowering しても新規 issue は無かった。accept を続けるかは**未決のまま**（2026-08-30 の方針決定は unlowerable 規則を `receiver_unknown` へ広げていない: Protocol 受け手は事前 accept を続ける）。
5. **（決定済み 2026-08-30）受け手が抽象基底そのもので木に override が無い abstract stub**（langchain-0.0.131 `agents/agent.py:176/194` の `self.output_parser.parse`）は「木内に宛先が無い taint 消失点」として空の候補集合の壁に留める（`resolved_stub`、proposed、off、`residual_unlowerable`）。empty stub（`pass` など）は従来どおり `receiver_subclass_no_overrides` = 壁でない。理由は壁の定義（エンジンが名指しはするが taint を運べない位置）— 隠すと残差を過小に見せる。残る縁: NotImplementedError 以外を raise するだけの本体は empty 扱い。
6. （決定済み 2026-08-30）residual は proposed 行（定数キーの inline subscript 受け手）も数える。accepted-only 相当は `residual_confirmed`（confirmed 行の net 残差）が答え、`residual_unlowerable` と合わせて `row.json` / `summary.md` に出す。
7. `_line_map` は挿入専用の貪欲整列。in-tree の pre_pass は挿入しかしないので正確だが、行を書き換える pass を加えると後段 pin が unmatched に落ちうる。
8. `index_registries` の重複排除は realpath と内容ハッシュ**だけ**（相対パスでは飛ばさない）。同一内容の複製が 2 つの走査ルート越しに見えても 1 束縛、同じ相対パスで内容が違う twin（cand_dir に壁ファイルの**別リビジョン**）は 2 定義（untrusted）— ファイルルートとして渡した twin と同じ判定（C4 の注意、2026-08-30 決定）。相対パスで飛ばすと先に見た木のリテラルを黙って信頼してしまう。レジストリ名は依然 bare name で鍵付け（モジュール修飾なし。2 モジュールが同名を束縛すれば定義が一致しても untrusted）。
9. 同名 `type_to_loader_dict` の 2 アンカー化や AnthropicProvider の open 化のように、C6 の修正は closed 数を下げる（llama_index 34 → 28、openmanus 4 → 2 は src 木上の値）。再現率より健全性を取った。

**再計測（完了、2026-08-31・版 8092345c）**: かつて `benchmark_out` は全 `abl/cond_B/links.json` が basename 鍵の旧形式（`legacy_links`）、全 plan.json が version 1（合体 impl map、旧アンカー名、`tool_version` 無し）、一部の `ablation.json` が plan 由来を記録しない旧形式だった。全 26 行を版 8092345c で再走し（`--stage all --from draft --force --keep-cond-a --accept-draft` → `--stage ablate --ablate-pyre --force` → `aggregate`）、plan / row / ablation / links.json は現行形式（src_root 相対鍵、version 2 plan、`tool_version` 8092345c）に揃った。`summary.md` の全行が `versions_match: yes`、脚注の異常リスト（版不一致・plan 未版・pre-C1 links.json・旧鍵・旧 impl map）は全て「(none)」。
