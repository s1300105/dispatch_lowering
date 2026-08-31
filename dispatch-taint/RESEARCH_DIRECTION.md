# 研究の方向性 — 整理（2026-06-05）

今日の議論で、研究の焦点と sink の扱いについて重要な決定をした。後で見返せる
よう記録する。

## 決定1: sink は「技術的 sink」に絞る（第一の選択）

これまで AgentDojo の 4 スイート（banking/workspace/travel/slack）の **ドメイン
sink**（send_money, send_email, reserve_hotel 等）を対象にしてきた。しかし:

- ドメイン sink は「操作自体は正当な業務機能で、攻撃者に誘発されたときだけ
  危険」= 文脈依存。従来の静的解析論文は、こうした文脈依存 sink を扱わず、
  **技術的 sink**（os.system, exec, SQL, ファイル書き込み等＝機能自体が危険）
  だけを対象にしてきた。
- 文脈依存 sink を静的解析で扱うのは原理的に難しく、現状は「どのツールが
  危険 sink か」を個別宣言に頼っていた（特化の懸念）。

→ 研究を従来の静的解析の確立された枠（技術的 sink）に収める。これにより
   「sink を自前宣言している」「文脈依存 sink は静的解析で無理では」という
   懸念が解消する。

## 決定2: 研究の核は「制御依存の検出」、技術的 sink の多段追跡はエンジンの役割

今日、NIST フォークの workspace_plus/terminal 環境（run_bash_command =
コマンド実行という技術的 sink）で検証を試み、重要なことが分かった:

- 技術的 sink の **認識** はできる（sandbox.exec を sink 定義に追加。これは
  「サンドボックス系の .exec() はコマンド実行」という汎用パターンで、特定
  フレームワーク特化ではない）。
- しかし、本物の `run_bash_command`（ツール関数）→ `Terminal.run_bash_command`
  （メソッド）→ `sandbox.exec`（実際の sink）という **多段の間接** を自前の
  classifier で追うのは重い。

ここで TaintP2X（ICSE 2026）の実装を調査して決定的なことが分かった:

- **TaintP2X は Pysa（Meta 製の Python テイント解析エンジン）の上に構築**
  されている。多段の間接・関数をまたぐ伝播は、自前実装せず Pysa に任せている。
- TaintP2X も sink/source は宣言している（`.pysa` ファイル: rce_sink.pysa,
  llms_sources.pysa 等）。→ **sink/source を宣言することは、この分野の標準手法**。
  自前宣言への懸念は杞憂だった。
- そして **TaintP2X でさえ「制御依存」は扱っていない**。Pysa はデータ依存
  （値の流れ）を追うエンジン。TaintP2X は「LLM 出力が値として sink に流れる」
  データフローを追うだけ。「攻撃者データが LLM の判断を変えて、どのツールを
  呼ぶかを操る」という制御依存は、Pysa にもできず TaintP2X もやっていない。

→ 多段の技術的 sink 追跡は、テイント解析エンジン一般の能力の問題であり、
   本研究の新規性（制御依存）とは別。ここを自前で作り込むのは本質でない。
   **研究の核は「制御依存の検出（動的ディスパッチ解決＝ツール選択の追跡）」**
   に絞り、技術的 sink の認識は直接呼び出しレベルに留める。多段ラッパー越しの
   追跡は「将来、Pysa 等の成熟エンジンに乗せれば解決する」と位置づける。

## 差別化（TaintP2X に対して）

実装の構造レベルで差別化が裏づけられた:

| | TaintP2X | 本研究 |
|---|---|---|
| 追う依存 | データ依存（値が sink に流れる） | 制御依存（LLM の判断でツールが選ばれる） |
| エンジン | Pysa（既存）に乗る | 自前（動的ディスパッチ解決が核） |
| sink | 技術的 sink を宣言（標準） | 技術的 sink を宣言（同じ標準手法に揃える） |
| 動的ディスパッチ | 扱わない | **解決する（研究の核）** |

本研究の核心は「動的ディスパッチで選ばれるツールを静的に解決し、攻撃者データが
LLM の判断を介してそのツール選択を操る制御依存を追う」点。TaintP2X のデータ依存
追跡とは別の側面で、TaintP2X も Pysa も扱っていない。

## 検証の現状と今後

- 本物 AgentDojo（ethz-spylab）: ドメイン sink。壁検出・解決・採点まで動いた
  （banking recall 100%）。ただし第一の選択ではドメイン sink は主対象から外れる。
- NIST フォック workspace_plus/terminal: 技術的 sink（コマンド実行）と RCE
  注入タスクを持つ。技術的 sink の認識はできた。経路全体の成立には、ツール
  関数→メソッド→sandbox.exec の多段追跡が要るが、これはエンジンの役割。
- 今後の主軸候補: 制御依存（動的ディスパッチ解決）の効果を、技術的 sink を
  持つ環境で、直接呼び出しレベルで示す。多段ラッパーは将来課題。

## 残った設計上の宿題（将来課題として正直に記載する）

1. 技術的 sink の多段ラッパー越しの追跡（エンジンの役割。Pysa 統合等）。
2. ソース/シンクの実装からの自動判定（現状は一部宣言依存）。
3. ガードの考慮（防御機構ありで検出が変わるかの検証）。
4. 複数フレームワークでの本物検証（現状 AgentDojo のみ本物検証）。

---

## 追記（2026-06-05 後半）: 技術的 sink 検証の実証と本物 NIST フォークの位置づけ

### 技術的 sink fixture での 4 段階実証（達成）

技術的 sink（コマンド実行・SSRF・ファイル書き込み）を持つ動的ディスパッチ
エージェント（`fixtures/technical_dispatch_full.py`、LangChain create_react_agent
ベース＝実在の汎用フレームワーク）で、研究の核を技術的 sink で実証した。固定母数 24:

| ステージ | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| S1 古典的（壁のまま） | 0 | 0 | — | — | — | 0%（壁で全見逃し） |
| S2 解決＋ソース展開 | 18 | 6 | 0 | 0 | 75% | 100% |
| S3 ＋ロール枝刈り | 18 | 0 | 0 | 6 | **100%** | **100%** |

- **制御依存の検出**: 古典的解析は動的ディスパッチの壁で止まり技術的 sink への
  経路を見逃す（recall 0%）→ 解決で全経路を検出（recall 100%）。
- **過剰警告の削減**: recall-first 展開で trusted-readonly ソース由来の過剰警告
  6 件 → ロール枝刈りで全て TN に移し precision 75%→100%、recall 100% 維持。

### 重要: ソースのロール判定を「宣言」から「実装からの汎用判定」へ格上げ

技術的 sink fixture では、ソースの role（attacker-influenced / trusted-readonly）
を AgentDojo のようなメタデータ宣言ではなく、**ソース関数の実装から汎用ルールで
判定**する（classify.py に実装）:
- 引数が読み取り先（URL/パス）を制御する → attacker-influenced
  （攻撃者が読み取り先を攻撃者データに向けられる）
- 読み取り先が固定の内部リソース（自社 config パス、内部 URL） → trusted-readonly

fixture の 5 ソース（attacker 3 / trusted 2）すべて正しく判定。これは従来の弱点
「ソース/sink を自前宣言しているだけ（特化の懸念）」に対する実装レベルの答えで、
宣言ではなくコード構造から汎用判定する形に格上げした。

### 本物 NIST フォーク（workspace_plus/terminal）の位置づけ → 将来課題

本物の NIST フォーク（usnistgov/agentdojo-inspect）の terminal 環境は、コマンド
実行（run_bash_command → sandbox.exec）という本物の技術的 sink と RCE 注入タスク
を持つ。技術的 sink の **認識**（sandbox.exec を汎用パターンで sink 化）はできた。
しかし本物を完全に解析するには、本研究のプロトタイプに無い 3 つの汎用構文対応が
必要:

1. 依存性注入経由のソース認識（`Annotated[Inbox, Depends("inbox")]` を受け、
   `return inbox.get_unread()` のような状態読み取りをソースと判定）。
2. スプレッド＋ドット参照のツール登録解決（`TOOLS = [*workspace.TOOLS,
   terminal.run_bash_command]`）。
3. 多段ラッパー越しの sink 追跡（ツール関数 → メソッド → sandbox.exec）。

これらは「制御依存の検出」という本研究の核とは別の、**テイント解析エンジン一般が
担う汎用構文対応**である（TaintP2X が Pysa に乗ることで得ていた部分そのもの）。
本研究の核は技術的 sink fixture で実証済みのため、本物 NIST フォークの完全解析は
「成熟エンジン（Pysa 等）への統合を要する将来課題」と位置づける。

---

## 追記2（2026-06-05 後半）: Pysa への役割分担を厳密化（一つ目の選択）

### 決定: 本物検証は Pysa 経路に一本化。ツール列挙・source/sink 宣言は .pysa で行う

前回 `_delegate_methods`（多段の関数間追跡）を自前 classifier に実装したが、これは
「多段はテイント解析エンジン（Pysa）の役割」という切り分けへの越権だった。指摘を受け、
今セッションで自前 classifier に足した本物フレームワーク向けの変更をすべて撤回:
- `_delegate_methods`（ツール関数→メソッド→sandbox.exec の多段追跡）
- `_has_depends_param` / DI ソース判定（依存性注入ツールの列挙・ソース判定）
- ソースの attacker/trusted-readonly をソース実装から判定する精緻化

classify.py はセッション開始時の状態に戻し、全テスト pass。役割分担:
- データ層（多段・関数間の source→sink 伝播、source/sink 宣言、ツール列挙）= Pysa（.pysa + taint.config、`pyre analyze`）
- 制御依存層（動的ディスパッチ解決、LLM-join、§4.5 枝刈り、§4.6 triage）= 自前 ctaudit（研究の新規性）

### Pysa が実環境で動作することを確認

pyre-check をインストールし、既存デモ pysa/projects/hybrid_demo で pyre analyze 実行 →
関数間データフローを不動点反復で追跡し 1 件検出。postprocess.py で ctaudit finding に
変換され、ToolOutput → <llm-node> → execute_shell（exec, CWE-1426）の多段経路が出た。

### 位置づけの変更（重要）

- 技術的 sink fixture の「過剰警告削減（precision 75%→100%）」は自前 classifier の
  ソースロール判定に依存していた。一つ目の選択により、ソースロール判定は Pysa の
  .pysa で宣言することになる。この実証は「自前で実証」から「Pysa 経路で再現（今後）」に
  位置づけが変わる。
- 本物 NIST フォークの多段技術的 sink（run_bash_command → sandbox.exec）は、自前で
  追わず、.pysa で sandbox.exec を CodeExecution sink、メール/ファイル読み取りを
  ToolOutput source と宣言し Pysa に追わせる。これが次の作業。

### 次の作業

本物 NIST フォーク workspace_plus を Pysa プロジェクト（.pysa + taint.config +
.pyre_configuration）として設定し、pyre analyze → postprocess で、メール/ファイル
読み取り（source）→ LLM → run_bash_command → sandbox.exec（CodeExecution sink）の
制御依存フローを検出する。既存 hybrid_demo と同じ構造で組める。

---

## 追記3（2026-06-05 終盤）: 本物 NIST フォークの Pysa 解析基盤を構築

一つ目の選択（本物検証は Pysa 経路）に沿い、本物 NIST フォーク（agentdojo-inspect）の
分散リポジトリ全体を Pysa で解析する基盤を構築した。

### 達成（基盤構築）

1. Pysa が本物の分散ツリー全体で完走: src/agentdojo（コア）＋
   examples/inspect/workspace_plus（terminal 環境）の両方を source_directories に
   指定し、pyre analyze がクラッシュせず完走（run_function の壁も解析対象）。
2. typeshed 配線で型解決クラッシュを解消: 当初 Untracked("dict") でクラッシュしたのは
   typeshed 未配線が原因。/usr/local/lib/pyre_check/typeshed を指定して解消。
3. 本物コードに対応する .pysa モデルが検証を通過: source（get_unread_emails /
   search_emails）、LLM-join（in-repo の chat_completion_request の messages を
   TaintInTaintOut[Via[llm_node]]）、壁の解決（run_function の kwargs を CodeExecution
   sink ＝ ctaudit の動的ディスパッチ解決結果を Pysa モデルに反映）、sink
   （terminal.run_bash_command / Terminal.run_bash_command）を、本物の正確な
   モジュールパスで宣言し、モデル検証エラー 0。

### Pysa ↔ ctaudit 協調の設計（本物で具体化）

本物の壁 FunctionsRuntime.run_function は f = self.functions[function]（辞書引き）。
Pysa はこの辞書引きの先を静的に追えない＝ここでデータフローが切れる。この一点こそ
ctaudit の動的ディスパッチ解決が埋める部分。協調は: Pysa が source→LLM→壁まで追い、
ctaudit が「壁は run_bash_command（CodeExecution sink）を呼ぶ」と解決し、その結果を
Pysa モデルとして反映して接合する。データフロー解析（Pysa）の限界点が、まさに制御
依存（ctaudit）の出番であることが、本物のコードで具体的に確認された。

### 残課題（連鎖を 1 本に通す）

source→LLM→壁→sink の各要素は宣言・検証できたが、本物のパイプラインは Pydantic
詰め替え・パイプライン要素間（planner→llm→tool_execution）の受け渡しを介するため、
Pysa の伝播が途切れ、source→sink の完全な連鎖がまだ通っていない（Found 0 issues）。
連鎖を通すには途切れる各箇所を Pysa モデルで補強する反復が必要。これが次の作業。

### 位置づけ

「本物を Pysa で解析する」基盤（環境・型解決・モデル検証）は完成。fixture でも構造
再現でもなく、実在の NIST フォークの実コードに対する解析基盤である。残るは本物特有の
複雑なデータ受け渡しでの伝播補強で、基盤が整った今、反復作業として着手できる。

---

## 追記4（2026-06-06）: TaintP2X 検証データセット（dataset.7z）の調査結果

TaintP2X が論文で使った検証データ（79MB, 12949エントリ）を調査した。

### 構造
- dataset/Benchmark/（23プロジェクト）: AutoGPT, MetaGPT, OpenManus, devika,
  langchain（4版）, langchain-experimental, litellm, llama_index（4版）, pandas-ai
  （2版）, SuperAGI, quivr, vanna（4版）。各プロジェクトは Pysa 結果のみ
  （pysa-runs*/taint-output.json 等）。元ソースコード(.py)は含まれない。
- dataset/real world/（12718エントリ）: ds_source（リポジトリごとの解析結果）、
  log_ds4〜16（バッチログ）、zhipu_debug（LLM判定デバッグ）。

### ground truth が含まれる（重要）
real world/ds_source/<repo>/<n>/ に:
- analysis_results.json: Pysa の完全な taint path（trace_chain: source→sink、各ステップの
  関数・ファイル・行・コード内容）。source 例は openai...chat.completions.create（LLM出力）、
  sink は SSRF 等の技術的 sink。
- response_output.json: TaintP2X の LLM 支援検証の最終判定 ＝ ground truth
  （is_vulnerability: true/false, vulnerability_types: ["SSRF"] 等）。

### あなたのシステムで使える形か（結論）
- 自分の postprocess.py で Pysa 結果を読めることは確認済み（langchain-0.0.131 で 601 issue
  をパース）。ただし issue コードは TaintP2X 独自（5000/6000番台）で ctaudit の cross-tool
  ルール（9001-9005）でなく、llm_node 特徴も付かない → そのまま再解析には使えない
  （元コードが無く ctaudit のルール/特徴で解析し直せない）。
- ground truth・比較対象としては使える: 各 taint path の脆弱性判定と場所があるので採点・
  比較に使える。

### 重要な留意点（データ依存 vs 制御依存）
trace_chain の source は LLM 出力、sink は技術的 sink で、これは TaintP2X のデータ依存パス
（LLM 出力が値として sink に流れる）。本研究の制御依存（LLM の判断でツールが選ばれる）とは
種類が違う。この ground truth は「データ依存脆弱性」の正解であり、本研究独自の制御依存の
正解とは限らない。「本手法が TaintP2X 相当のデータ依存も検出できるか」には使えるが、
「本手法独自の制御依存」の検証には別 GT が要る可能性。

### 完全活用の道
Benchmark の対象は公開フレームワークのバージョン指定版。PyPI/GitHub タグから元コードを取得し、
今日構築した Pysa 基盤（llm_node・cross-tool ルール）で解析し直せば、同梱の TaintP2X 結果と
同一対象・同一エンジンで直接比較できる。これが最も価値の高い使い方。

### 利用上の注意
TaintP2X の研究成果物のため利用時は論文を引用し出典明記。real world のリポジトリ名・第三者
コード断片を含むため配布元のライセンス条件を確認すること。

---

## 追記5（2026-06-06）: TaintP2X 拡張アプローチの設計

研究方針を「TaintP2X に、自分の動的ディスパッチ解決モジュールのみを追加して拡張する」形に
定めた。TaintP2X リポジトリを調査して設計。

### 前提確認
- ライセンス: Apache 2.0（寛容）。改変・拡張・研究利用・論文化が可能（出典明記・ライセンス
  表示は必要）。
- TaintP2X は Pysa 上に完成基盤を持つ: Taint_Propagation/taint/ に source 宣言
  （llms_sources.pysa = LLM 出力 97個）と技術的 sink 宣言（rce_sink, sqlite3_sinks,
  filesystem_sinks, http_server, email_sinks, django_sinks, pandasai 等）、taint.config
  （source: LLMControlled / FromUrlLLMControlled、sink: RemoteCodeExecution, ExecImportSink,
  ExecArgSink, EmailSend 等）。stubs/ に各フレームワーク型スタブ。

### 役割分担（確定）
- TaintP2X（既存・流用）: source 特定、技術的 sink 定義、データフロー伝播、LLM 支援検証、
  ground truth、評価パイプライン。→ 自前 classifier の認識は不要に。
- 本研究（新規・追加）: 動的ディスパッチ解決のみ。動的ディスパッチ（self.functions[name] 等）で
  Pysa のデータフローが切れる箇所（本物 NIST フォークで run_function の辞書引きで切れることを
  実証済み）の制御依存経路を解決して繋ぐ。

### 差し込み方式（採用: Pysa モデル生成方式）
本研究のモジュールを「動的ディスパッチを解決して .pysa モデルを自動生成する拡張」として実装:
1. 解析対象から動的ディスパッチの壁を検出（既存 DispatchSpec）。
2. 壁が呼びうる登録ツールを解決（既存 dispatch_resolution.py）。
3. 解決した各ツールのうち技術的 sink について「壁の引数 → そのツール(sink)」の伝播を
   TaintP2X の .pysa 形式で生成（def ...run_function(..., kwargs: TaintSink[RemoteCodeExecution]): ...）。
4. 生成 .pysa を TaintP2X の taint/ に加えて pyre analyze → source→LLM→壁→sink が 1 本に繋がる。

今日 NIST フォークで手で書いた .pysa 行を、本モジュールが動的ディスパッチ解決の結果として
自動生成する、が拡張の核心。手書きを研究の新規性で自動化する。

### 評価
TaintP2X のデータセット・評価パイプラインをそのまま使い、本モジュール有り/無しで ablation。
「動的ディスパッチで切れていた経路を何件繋げ、新たにどの技術的 sink 到達を検出できたか」を示す。
同一基盤の拡張前後比較で貢献の効果が純粋に測れる。

### 留意点
- 修論の規模として「1 モジュール追加」が十分かは指導教員と確認。見せ方は「データ依存解析が
  原理的に追えない制御依存という新問題を、既存基盤を活用して解いた」。
- TaintP2X の ground truth はデータ依存脆弱性の正解。本モジュールの効果は「壁で切れていた経路を
  繋いだ数・新規到達 sink」という自分の基準で示す必要。

### 次の作業
TaintP2X の run_download_and_check.py（Benchmark 元コード取得方法と推定）と評価パイプラインを
確認し、本モジュール（動的ディスパッチ解決→.pysa 生成）の差し込み実装を始める。

---

## 追記6（2026-06-06）: TaintP2X 拡張の最小実証（PoC）成功

「TaintP2X + 動的ディスパッチ解決モジュール」が動的ディスパッチの壁を越えて source→sink を
繋ぐことを最小ケースで実証した。

### PoC 構成（/tmp/poc）
- minimal.py: source(read_webpage) → llm_decide(LLM-join, TITO[llm_node]) →
  REGISTRY[name](**args)（辞書ディスパッチの壁）→ ExecuteShell.execute（RemoteCodeExecution sink）。
- TaintP2X 相当の設定: taint.config（source ToolOutput / sink RemoteCodeExecution / rule 9001）、
  base.pysa（source・sink・LLM-join 宣言）、TaintP2X の stubs/ を search_path に流用。

### 結果（同一基盤・モジュール有無のみ差）
- 拡張前（Pysa/TaintP2X 単体、壁未解決）: Found 0 issues（辞書ディスパッチでデータフローが切れる）
- 拡張後（動的ディスパッチ解決モジュール適用）: Found 1 issue（code 9001, callable run_agent、
  source→LLM→sink が1本に繋がる）

### モジュールの実装方式（確定）
dispatch_lowering.py: 動的ディスパッチの壁を解決し、解決先への直接呼び出しに lower（変換）する。
- REGISTRY = {"key": Class.method} を解析しレジストリ解決（ctaudit の既存 dispatch_resolution と同能力）。
- 壁 REGISTRY[name](**args) を検出し、直後に解決先の直接呼び出し Class.method(**args) を if False:
  ガード付きで挿入（実行時の動作は不変、Pysa の静的解析だけがこのエッジを読む）。
- → Pysa が辞書引きを越えて args(source-taint)→ sink を追える。

当初 .pysa モデルで壁の伝播を宣言しようとしたが、辞書 __getitem__ の型などモデル文法の制約で
表現しづらかった。「動的ディスパッチ → 静的直接呼び出しへの lowering」方式の方が Pysa と素直に
噛み合うと判明。これは「動的ディスパッチを静的に解決する」という本研究の本質そのものをコード変換
として実装したもの。

### 位置づけ
同一の Pysa 基盤・同一の source/sink 宣言で、本モジュールの有無だけが検出を分けた（0→1）。
TaintP2X が原理的に越えられない動的ディスパッチの壁を本モジュールが越えることを最小実証。
評価は今後 TaintP2X データセットで「モジュール有無の ablation」として規模拡大する。

### 次の作業
1. lowering を ctaudit 本体（dispatch_resolution.py）と接続し、対応する全レジストリ形状を扱う。
2. TaintP2X の公開フレームワーク1つ（langchain 等）の元コードを取得し、同じ lowering→Pysa で壁越えを実証。
3. TaintP2X 評価パイプラインに乗せ、モジュール有無の ablation を出す。

---

## 追記7（2026-06-06）: lowering を ctaudit 本体と接続（健全性ゲート付き）

PoC の簡易レジストリ解決を、ctaudit の dispatch_resolution._index_registries に接続した。

### 格上げ内容
- 健全性ゲート: lower する前に ctaudit の _index_registries で「静的 dict リテラルで後から変更
  されていない（信頼できる）」レジストリかを判定。信頼できるものだけ lower し、変更・動的構築
  されるレジストリは lower しない（recall-first、unsound なエッジを作らない）。コード生成用の
  完全 dotted 名は lowering 側で取得。
- 役割分担: 健全性判定 = ctaudit の堅牢なロジック / コード生成 = lowering。

### 結果
健全性ゲートを通した上で minimal.py の壁を lower → Pysa が Found 1 issue。PoC と同じ検出を
健全性担保つきで再現。

### 実装上の注意（本物適用時）
ctaudit の _index_registries は絶対パスで呼ぶ必要がある（相対パスだと空を返す）。lowering は
解析対象を絶対パス化してから渡す。

### 次
TaintP2X の公開フレームワーク1つ（langchain 等）の元コードを取得し、同じ lowering→Pysa で
壁越えを実証 → TaintP2X 評価パイプラインで ablation。

---

## 追記8（2026-06-06）: 本物 AutoGPT で壁越えを実証（lowering 有無の ablation）

本物 AutoGPT（autogpt-platform-beta-v0.5.0、Benchmark 対象版）で動的ディスパッチの壁越えを
Pysa 上で実証した。

### 対象の壁（本物）
- 壁: agents/agent.py の _execute_tool: command = self._get_command(tool_call.name) →
  result = command(**tool_call.arguments)（LLM が選んだ名前でコマンドを線形探索して動的に呼ぶ）。
- 解決先: code_executor.py の @command メソッド4つ（execute_python_code/file/shell/shell_popen）、
  内部で subprocess.run/Popen（技術的 sink, RCE）。壁と解決先は別ファイル・別クラス。

### 結果（同一基盤・lowering 有無のみ差）
- ベースライン（lowering 無し）: Found 0 issues（線形探索＋Command 経由でデータフローが切れる）。
- lowering 後: Found 3 issues（code 9001, callable agent.Agent._execute_tool）。
  source(tool_call)→ 動的ディスパッチ壁 → lowering 解決 → execute 系コマンド → subprocess が繋がる。

### lowering の本物対応
1. クロスファイル: 全ツリーから @command メソッドを収集し、別ファイルの壁 command(**args) に
   解決先への直接呼び出しを挿入。
2. シグネチャ認識: dict 展開でなく各コマンドの名前付き仮引数すべてに壁の taint 引数を渡す。
3. if False ガードで実行時不変。

### 本物適用で判明した必須条件
- モジュールパス一致: 解決先を import パス通りの階層に置かないと Pysa が挿入呼び出しを実体メソッドに
  結びつけられず 0 のまま。平置き不可。
- typeshed 配線＋ --no-verify（TaintP2X 方式）で重い依存でも完走。

### 位置づけ
PoC → ctaudit 接続（健全性ゲート）→ 本物 AutoGPT で壁越え実証、と段階到達。同一 Pysa 基盤で
lowering 有無だけが検出を分けた（0→3）。TaintP2X が越えられない動的ディスパッチの壁を本研究の
モジュールが実在エージェントで越えることを実証。

### 次
TaintP2X 評価パイプライン／データセットで複数フレームワークの ablation を集計し、壁越えで新規検出した
経路数・到達 sink を定量化する。

---

## 追記9（2026-08-29）: IccTA の設計を取り込んだ再構成

IccTA（Li et al., ICSE 2015）が Android の ICC（Intent 経由の実行時解決される間接呼び出し）を
「Epicc/IC3 でリンク解決 → `IpcSC.redirectorN` を生成 → Jimple を計装 → 無改変の FlowDroid」で
解くのが本研究と同型であることに気づき、設計を対応づけて再構成した（対応表は README.md）。ただし
「どこを計装するか」の決め方は同型ではない: IccTA は外部のリンク解析（IC3/Epicc）が名指した文を
`IPCMethods.txt`（約 30 署名 = 非コメント行）で限定して計装し、FlowDroid は無改変で走る。本手法は外部解析を
持たず、エンジン自身の未解決記録を一次カタログにする（下の「対応が完全でない点」1 と添削 M8）。

### 取り込んだもの
1. **リンク IR**（`ICCLink` 相当）: `links.DispatchLink`。壁×候補の各リンクに判定（lowered /
   filtered_registry / filtered_level / unreasonable / no_args / phantom）と根拠を記録し
   `links.json` に永続化。解決と生成を分離。
2. **プロバイダ**（Epicc / configfile 相当）: 自動解決と手書き `links.json`。SK の Stage 2 のように
   解析者が固定するリンク（`forward` で転送引数も明示）を同じ計装器で扱える。
3. **精度レバー**: レジストリ／BoolOp のメンバー所属による絞り込み（`narrow`）と、実引数と
   ターゲット・シグネチャの不整合による不成立判定（`filter_unreasonable`＝`UnreasonableLinksRemover`
   相当）、`match_level`。原則は `DefaultMatchAlgo` の "we can give up some links, but we had better
   not introduce false positives" を共有する。**ただし対応は完全ではない**（後述）。
4. **リダイレクタ**（`IpcSC.redirectorN` 相当）: `emit=redirector` で合成モジュール
   `__ctaudit_redirect.py` に 1 リンク 1 関数を生成。壁側は 1 行/リンク。多段でも 1 つの
   モジュールに集約し、同名別モジュールの候補は別名 import で区別する。
5. **レシーバ構築**: クラス候補は `Cls.__new__(Cls)` でインスタンスを作り bound で呼ぶ
   （inline / redirector 共通）。`await`、`return`/複合文・`elif` 連鎖の前への自動配置。
6. **位置タグ・統計**（`JimpleIndexNumberTag` / `InfoStatistic` 相当）: `wall=<src_root 相対パス>:<cond_A 行>` と
   `# <link id>`（多段では `S<i>L<n>` で links.json と一致）、`lowered_line`（書き換え後ファイルでの行。壁とリンクの両方が持つ）、
   `LoweringStats`（`stats.json`、ablation の表）。
7. **パス構造**（`updateJimpleForICC` 相当）: `pipeline.py`（pre-pass → provider → 計装 → post-pass）。
8. **マイクロベンチ**（DroidBench ICC スイート相当。IccTA ツリーの `TestApps/` は起動器で、
   `pipeline.py` がその役）: `bench/`（壁イディオム・精度機構別の fixture、`--pyre` で
   cond_A=0 を確認したうえで Pysa 検証）。

### 再構成の過程で判明したこと（重要・正直に記録）
- **git HEAD のコードは AutoGPT で 0→2 しか出ていなかった**。README の「0→7」は旧 `if False`
  時代のシグネチャ対応マッピング（`execute_python_file(filename=args, args=args)`）の結果で、その後
  スコープ変数ダンプ方式に変わって 2 に落ちていたが、committed `cond_B` が古いため気づかなかった。
- **HEAD のコードでは SK の手順（VERIFICATION_REPORT Q4）が構文エラー**になる（汎用検出器が
  `vector.py` の別の `f = g(...); f.m(...)` も壁として拾い、複数行呼び出しの途中に挿入）。
- 引数の転送規則を **「`**d` splat は候補の各仮引数へキーワードで割り当て（受け付けるなら `**d` も）、
  実引数は名前が一致する範囲で転送、スコープダンプは最後の手段」** に戻し・整理した。
  これで AutoGPT は 0→**5** issue、到達した sink の組は **5 組で旧 7 件と同一**
  （旧 7 は execute_python_file の 2 つの汚染引数を別 issue として二重計上していた）。
  回帰判定は生 issue 数に加えて sink 到達の組数（`EXPECT_SINKS_B`）で行う。
  （訂正・添削 C2: ここで「(sink 種別, sink メソッド)」と書いていた組の鍵は、実装では (sink 種別, 発見 callable からの
  第一呼び出し先 = backward trace 根の `resolves_to[0]`) だった。現行の **sink 組 = (sink 種別, issue callable)**
  （`row.json` / summary の鍵）では同じ実行が 2 組。`EXPECT_SINKS_B=5` は旧鍵 `SINK_FIRST_HOPS` を門にしたまま
  （再計測 2026-08-31・版 8092345c: `AutoGPT-classic-subset` は現行鍵 2 組・新規 2・消失 0、EXPECT_SINKS_B=5 通過）。）
- BoolOp 壁を `detect_boolop` として `detect_higher_order` から分離。挿入位置は呼び出し行でなく
  **文**の開始/終了行に。

### 対応が完全でない点（修論に正直に書く）

多エージェントによる添削で以下が確認された。いずれも README「Where the analogy stops」と
「Scope and honest limits」に明記済み:

1. **リンクの作られ方（と計装位置の決め方）が違う**。IccTA の `ICCLink` は IC3/Epicc という外部の値解析が Intent を
   解決した結果で、1 リンク = 解決済みの (呼び出し位置 → コンポーネント)。計装位置もその外部解析が名指した文を
   `IPCMethods.txt`（約 30 署名 = 非コメント行。`soot-infoflow-android-iccta-master/res/IPCMethods.txt` は 34 行中 30 行）で
   限定して決め、FlowDroid の call graph は使わない（添削 M8）。本手法は外部解析を持たず、エンジン自身の未解決記録を
   一次カタログにし、`build_links` はディスパッチキー自体を解析せず、壁×候補を列挙して 2 つのフィルタで刈る。
   絞り込みが効かない壁（AutoGPT の `self._get_command(name)` 等）は候補全件に fan-out する。
   → 「IccTA と同じ精度源を持つ」とは書けない。「同じ形の IR を、列挙＋刈り込みで作る」と書く。README の対応表でも
   「where to instrument」の行は「違い」側に置く。
2. **`match_level` は `INTENT_MATCH_LEVEL` と別物**。IccTA の水準は intent-filter との照合の
   深さ（action/category < +mime < +data）で、どれも解決済みリンクの話。本手法の水準は候補の
   由来がどれだけ投機的か。共有しているのは「リンクを捨てても FP は入れない」という原則だけ。
3. **受信側計装は無い**。IccTA は宛先クラスに `<init>(Intent)`・`getIntent()` override・
   `dummyMain` を生成し、Intent 自体がデータ搬送路になる。本手法は呼び出し側のみで、
   `Cls.__new__(Cls)` は `__init__` を走らせないので、レシーバ状態（登録時に設定された
   `self.cmd` 等）経由の伝播は追えない。→「`<init>(Intent)` 相当」とは書かない。
4. **ガードは意味保存ではない**。`__ctaudit_unreachable__` は未定義名なので、lowering 後の
   ファイルを実行すると `NameError` になる。cond_B は IccTA の計装済み Jimple と同じく
   **解析専用のコピー**。元呼び出しを残すのは「実行時意味を保つため」ではなく、Pysa が壁で
   部分的に解決できる分を残すため。
5. **絞り込みの健全性は経験則**。レジストリは「単一 dict リテラルで再束縛・変更・別名化・
   `{**other}` が無い」場合のみ信頼するが、名前はモジュール修飾していない。デコレータ付き
   候補やフレームワークの dispatch メソッド経由の壁ではシグネチャ照合を行わない
   （ラッパが引数を消費するため）。
6. **splat の配布は過大近似**。`command(**d)` は `d` を候補の各仮引数に配る（`filename=d, args=d`）
   ため、`d` の一部のキーしか汚染されていない場合でも全パラメータが汚染扱いになる。

### 検証の到達点（2026-08-29 時点）
- AutoGPT v0.5.0: inline / redirector / 手書き `links.json` の 3 経路すべてで 0→7 issues、到達 sink 5 組、
  旧結果とポート単位で完全一致。
- Semantic Kernel 1.39.3: 2 段 spec で 0→1 issue（code 5001）。
- マイクロベンチ 26 fixture × 2 形式: AST レベルと Pysa の両方で全 PASS。Pysa 判定は
  「lowering 前は 0 issue（壁が本当に Pysa を止める）」かつ「lowering 後に fixture の sink 呼び出し先へ
  到達」で行う。生の issue 数は判定に使わない（TaintP2X の規則では `subprocess.run` に 5001 と 5005 の
  2 種類が付き、1 フロー = 2 issue になるため）。当初 `self.tools = {"shell": ShellTool()}` と書いていた
  `method_wall` は型付き dict を Pysa が解決してしまい lowering なしで 2 issue 出た＝壁でなかったため、
  実行時登録の形に直した（fixture が「壁である」ことを cond_A=0 で証明する仕組みが効いた例）。

### 修論での位置づけ
「データ依存解析が原理的に追えない動的ディスパッチ（制御依存）を、IccTA が ICC に対して行った
"リンク解決＋計装で無改変エンジンに追わせる" 方式の Python/LLM エージェント版として解いた」と
記述できる。ただし上の 1〜6 は差分・限界として明記すること（1 には計装位置の決め方 — 外部リンク解析の
有無 — も含む、添削 M8）。特に「IccTA と同型の設計を採る」のと「IccTA と同じ健全性・精度を得る」のは別であり、
後者は主張しない。

---

## 追記10（2026-08-29）: 複数対象への展開設計

対象ごとの手作業のうち、静的解析に一般に必要な source/sink 宣言と解析環境は手動のまま、
システム固有の spec・`WALL_FILES`・バッチ集計を自動化する設計を `docs/SCALE_OUT_DESIGN.md` に
まとめた（3 案を合議で審査: エンジン駆動 92 / カタログ 81 / AST ランキング 73）。要点:
壁の発見を AST ではなく **Pysa 自身の成果物**（cond_A の `call-graph.json` の未解決記録、
stub / obscure への解決、`higher-order-call-graph.json` の dispatch メソッド）で行い、レジストリ・
アンカリングを補完とし、レビュー対象を `plan.json` 1 つに集約する。壁の定義を「AST が壁に見える」
から「エンジンがそこで taint を失う」へ改める（`method_wall` fixture が型付き dict のせいで
lowering なしでも検出されていた件が、AST 定義の誤りを示す実例）。次の作業はこの設計の
コンポーネント 1〜3 + 6 + 8（単一対象の draft → review → run）。

---

## 追記11（2026-08-29）: エンジン駆動の壁発見（engine_walls.py）を実装

設計書（`docs/SCALE_OUT_DESIGN.md`）のコンポーネント 3 を `taintp2x_extension/engine_walls.py` として実装した。
cond_A の `r/`（`call-graph.json`・`higher-order-call-graph.json`・`taint-output.json`・`modules.json`・
`functions.json`・`decorator-counts.json`・`override-graph.json`・`taint-metadata.json`・`errors.json`）を
読むだけで、pyre の追加実行は無い。1 対象 1〜5 秒（AutoGPT の venv 込み 156 MB の call graph でも 1.5 秒）。

### 出すもの
- 壁の行（`EngineWall`）: `file:line:col`、callee、idiom（subscript / getattr / boolop / higher_order /
  method_call / attr_call / param_call / loop_call / call_call）、resolver と key 式
  （`self._get_command[tool_call.name]`、`name_to_tool_map[agent_action.tool]`）、受け手の束縛元、BoolOp の
  メンバーと open フラグ、エンジン状態（`unresolved:<理由>` / `resolved_stub` / `resolved_obscure` /
  `resolved_dispatch:<API>`）、エンジンが辿った先、taint 階層（T1/T2/T3）、confirmed / proposed、accept 案、
  文の範囲、`taint_args`。
- `env_report.json`: Pysa 版、in-repo の未解決理由別件数、環境の穴（`CannotResolveExports` 等と「呼び出しで
  束縛された受け手」）、モデル検証エラー、source を持つモデル数、in-repo デコレータ、カタログ命中と有無、
  outcome（ok / no_sources / no_surface / no_walls）。
- `residual`（cond_B）、`dataset-scan`（データセット同梱の旧スキーマ graph の件数）、`extract`（テスト用の最小 `r/`）。

### 門 0 の結果（pyre 追加なし）
- **AutoGPT**: fresh 木 `/tmp/f_inline/cond_A`（`r_min/autogpt` の抜粋元）は in-repo 150 サイト、未解決 96
  （UnknownBaseType 53 / CannotResolveExports 32 / CannotFindParentClass 10 / UnknownIdentifierCallee 1）、
  残り 95 は環境の穴として `env_report` へ。別マシンで解析してコピーしたコミット済み
  `taintp2x_m2_verification/cond_A` は同じ 150 サイトだが未解決 101 / 環境の穴 100（CannotResolveExports が
  32 → 37、他の理由は同数。差は解析環境の違いによる import 解決の穴で、壁の行には影響しない）。壁の行は
  どちらの木でも **277:21 の 1 行だけ**（T1、`self._get_command[tool_call.name]`、accept）。cond_B の residual は
  raw 1 / net 0。
- **lc_real 型消去**: 1398 / 1549 が `unresolved:UnknownBaseType`、受け手が `name_to_tool_map[agent_action.tool]`
  （subscript）→ confirmed。**型付き**: 同じ位置が `resolved_dispatch:BaseTool.run`（カタログ一致）だが、
  `higher-order-call-graph.json` で `Context.run(self._run)` が `Overrides{BaseTool._run}`（木の中に 7 override）に
  解決されている → proposed。型付き cond_A の `errors.json` に既に 5001 が 1 件あることと整合する
  （以前 notype 木を作った理由そのもの）。
- **sk_real**: 2103 が boolop（`filter_update_function or default_dynamic_filter_function`、仮引数を含む open
  BoolOp）T2 confirmed。2130 `string_mapper(...)` は param_call（proposed）。997 `self.definition.deserialize` は
  Protocol の `__call__`（本体 `...`）に解決 = S2 `resolved_stub`。2107 `self.search(...)` は `@overload` 2 本の後の
  実装 def に解決しており stub ではない（当初 overload のスタブを本体と誤認していた → 実装 def を優先するよう修正）。
- **fixture 6 件**: 理由の対応表は subscript / getattr → `UnknownCallCallee`、`f = resolve(k); f(...)` と BoolOp →
  `UnknownIdentifierCallee`、`t = self.tools[k]; t.run(...)` → `UnknownBaseType`。
- **データセット同梱の旧スキーマ**（`singleton` / `compound` 包み、`unresolved: true` のみで理由なし）:
  AutoGPT classic 10057 / 18931 呼び出し、OpenManus 770 / 2547、vanna 1070 / 2140 → count-only の
  「面があるか」の事前確認にしか使えない（設計どおり）。

### 実装して判明したこと（設計書からの修正、正直に記録）
1. **S3 は型付きの木では壁でないことがある。** エンジンは `BaseTool.run → Context.run(self._run) →
   Overrides{BaseTool._run}` と override 集合を辿れる（recall は満たし、精度だけが落ちる）。S3 が壁になるのは
   型消去時か、フレームワーク本体が木に無く Obscure のとき。よってカタログ一致でも override を辿れている行は
   proposed とし、ablation（delta）に判断を委ねる。
2. **`UnknownBaseType` の大半は型の穴でディスパッチではない。** AutoGPT 53/53、lc_real 843/918（型付き cond_A。
   レビュー M1 修正後に再計算した値。旧値 895/918 は `self.x[k].m()` 形の inline 受け手を attr_call として env に
   落としていた版の数字。束縛規則はその後も変わったが（タプル展開・内包表記の generator、
   `loop` 誤帰属 27 サイトの修正）版 8092345c で確定し、`r_min/m1_bindings` と `test_engine_walls`（全件 pass）が固定する
   — 上の値は最終版の r_min 木で記録したもの（再計測 2026-08-31・版 8092345c））が `logger = logging.getLogger(__name__)`・`client = docker.from_env()` のような
   「呼び出しで束縛された受け手」か属性チェーン・仮引数・ループ変数（lc_real の内訳: 呼び出し 334 / 属性 281 /
   ループ変数 132 / 仮引数 68 / その他 28）。受け手が subscript / getattr / BoolOp で**選ばれた**ときだけ壁
   （`tool = name_to_tool_map[k]; tool.run(...)`）。先行する文での束縛も、呼び出し位置での直接選択
   （`self.tools[k].run(...)`、`REG[k].m()`、`getattr(o, k).m()`、`(a or b).m()`、M1）も同じ扱い。束縛は呼び出し
   位置より**前**の文から決め、内包表記は独自スコープなので、後続の `names = [t.name for t in xs]` が先行する
   `t = REG[k]; t.run()` の束縛を上書きすることはない（M1 再修正、`r_min/m1_bindings` で固定）。lc_real の
   残り 75 行は壁行（subscript 受け手 61 = confirmed 12 + 定数キー proposed 49、open BoolOp proposed 14。版 8092345c で
   `test_engine_walls` に固定（再計測 2026-08-31・版 8092345c））。
   定数キー（`REG['x']`、`__name__`）は選択でないので off。
3. **`param_call`（`fn(args)` の fn が仮引数）は多い**（SK 60 件）。壁ではあるが候補は呼び出し側にあるので、
   anchoring（コンポーネント 4）まで proposed。`loop_call`・`call_call` も同様。
4. **設計書の「`method_wall` は already_resolved」は旧 fixture の話。** 現 fixture は実行時登録で真の壁
   （`UnknownBaseType`）。型付き dict の版を `typed_registry_resolved` fixture として追加し、エンジンが
   `resolved` と言う＝草案に出ない、を `run_bench.py --engine` で固定する。
5. higher-order 証拠は `Overrides{…}` 先に限定した。`pydantic.Field(default_factory=…)` や `RunnableLambda(func)`
   のような「コールバックを受け取るだけ」の関数を S3 にしないため。
6. コピーした結果ディレクトリ（`filename: "*"` で絶対パスが別マシン）は、cond 相対パス全体の接尾辞一致でだけ
   in-repo と認める。basename だけの一致だと site-packages の `agents/agent.py` が対象の `agent.py` に化ける。

### テスト
`test_engine_walls.py`（pyre 不要。`r_min/` に AutoGPT cond_A / cond_B、lc_real 型付き / 型消去、
sk_real、データセット OpenManus / vanna の in-repo 抜粋）と `bench/run_bench.py --engine`。項目数は添削対応で増え続けて
いるので本文には書かない: 全件 pass（`python3 taintp2x_extension/test_engine_walls.py` で確認）。添削後の固定: residual の
相対パス鍵（同じ basename で別ディレクトリの links.json は net しない — C1）と S2 stub 方針（C5、追記15「方針決定」）。

### 次
コンポーネント 1・2（`WallRecord` / spec の `wall_positions`・`reject_walls`）→ 6（`draft.py`: `plan.json` と
`walls.md`、`run_spec(write=False)` のドライラン）→ 8（`run_ablation.sh` の `DRAFT=1` / `PLAN_JSON`）。

---

## 追記12（2026-08-29 夜）: フェーズ A — 単一対象の draft → review → run

設計書のコンポーネント 1・2・6・7・8 を実装した（詳細は `docs/SCALE_OUT_DESIGN.md` の「フェーズ A 実装済み」）。
対象ごとの入力から `WALL_FILES` と spec の壁検出が消え、`DRAFT=1 ./run_ablation.sh` → `walls.md` / `plan.json` を
レビュー → `PLAN_JSON=… ./run_ablation.sh` の 3 手順になった。無人回帰は `ACCEPT_DRAFT=1`。

### 仕組みの要点
- **壁は位置で固定する**（`wall_positions`）。草案は `detect_*` を全て false にし、エンジンが壁と言った位置だけを
  Call として名指しする（col がずれても callee 文字列 → 一般検出 → 行の先頭 Call の順で照合し、無ければ
  `unmatched_position` として記録）。追記9 の vector.py 構文エラー（汎用検出の拾いすぎ）はこれで再発しない。
- **却下は消さずに残す**（`accept: false` / `reject_walls` → `rejected_by_review`）。統計に「レビューで落とした壁」が
  残る。レビュー手直し数（`review_edits`: accept 反転・spec キー編集）は、`draft.py` が書く読み取り専用の原本
  `plan.draft.json`（mode 0444）と cond_B の構築に使った plan の diff として `row.json` に出す（添削 C7: 以前は
  同じファイルを in-place 編集して複製していたため構造的に 0 にしかならなかった。原本の無い旧 bundle は
  `draft_source` にその旨が出て、0 は「観測不能」を意味する）。
- **BoolOp 壁は自分の宛先集合を名指ししている**（explicit Intent 相当）。def に解決するメンバーを `boolop_member`
  候補（level 1）にし、草案はその壁の `match_level` を 1 に絞る。SK の `update_func = filter_update_function or
  default_dynamic_filter_function` は、`@kernel_function` 48 件が候補にあっても `default_dynamic_filter_function`
  1 件に落ちる（49 リンク中 48 が `filtered_level`）。
- **fan-out の上限**: narrowing 無しで 16 を超える行は proposed に降格し、降格行のリンクは `plan["dry_run"]` / stats から
  除く（回帰は `test_draft.py` の自足 fixture: stub 壁に `@kernel_function` メソッド 17 件 → 17 fan-out → proposed。fixture の
  大きさは固定で `FANOUT_MAX == 16` を assert する）。追記時点で挙げていた SK の `self.definition.<Protocol>` stub 行
  （vector.py 997/998/1015/1016）は現行では上限の例ではない: メソッド名フィルタで名前の合わない候補が `unreasonable`
  になり（抜粋では候補 0、全木では 40 件超が unreasonable）accept/confirmed のまま。`dispatch_impl_map` で候補が
  dispatch API の impl に限られる method/attr 壁は上限の対象外（追記の SuperAGI 規則 (ii)）。level 2（登録済みツール
  集合）の 13（lc_real の `_run`/`_arun`）は正直な fan-out として通す。
- 候補回収の全木走査は memo 化（lc_real 113 群のドライランが 16 秒）。

### 門 1 の結果
- **Semantic Kernel 1.39.3**: 草案の vector.py 群（stage 1 = BoolOp 壁 2103、候補 `boolop_member` 1 件）に
  `spec.sk_real.json` の stage 2（`self.search` → `InMemoryCollection._parse_and_validate_filter`、解析者固定）を
  `stages` として付け、`pipeline.py --plan` → pyre 67 秒 → **0→1 issue（code 5001）、sink 組も既知の cond_B と同一**。
  stage 1 の `insert_before` / `candidate_import_module` は不要だった（メンバーは vector.py が既に import しており、
  writeback `inner_options.filter = __ctaudit_ret` は `match` 文の前に入る）。
- **AutoGPT v0.5.0**: 草案 → plan → lowering の結果は、レガシー spec（`tool_decorator: command`）の cond_B と
  **リンク id 以外バイト一致**（AST レベル）。pyre でも `DRAFT=1`（草案 exit 0、壁 1 行 accept）→
  `PLAN_JSON=draft/plan.json`（inline / redirector）→ `ACCEPT_DRAFT=1`（無人）の全経路で
  **cond_A 0 → cond_B 7 issue、sink 5 組（旧鍵 (種別, 第一呼び出し先)。現行鍵 (種別, issue callable) では 2 組・新規 2・消失 0
  （再計測 2026-08-31・版 8092345c: `AutoGPT-classic-subset`、EXPECT_SINKS_B=5 通過））、`EXPECT_A=0 EXPECT_B=7 EXPECT_SINKS_B=5` の regression OK**。
  `row.json`: outcome=delta_pos、residual raw 1 / net 0（残るのは元の呼び出しのみ）、無人実行（レビュー未実施。
  旧記述の「手直し 0（accept 反転 0・spec 編集 0）」は `plan.draft.json` が無く観測不能だった値 — 添削 C7
  （再計測 2026-08-31・版 8092345c: 現行の再走では `plan.draft.json` があり review_edits は観測可能。`--accept-draft` の無人実行なので diff は 0））、in-repo 未解決 101（UnknownBaseType 53 / CannotResolveExports 37 /
  CannotFindParentClass 10 / UnknownIdentifierCallee 1）、環境の穴 100。
- **解析時間の落とし穴**: `ablation_helpers.py config` は `VIRTUAL_ENV` があると venv の site-packages を
  `search_path` に入れる。AutoGPT はそれで pyre 325 秒 / call graph 156 MB、外すと **5〜6 秒 / 44 KB** で結果は
  同じ（6 月のコミット済み検証はこの環境）。`PYRE_SEARCH_VENV=0` で明示的に外せるようにした。依存を vendoring
  しない対象では常にこれを使う。
- 修論の記述: 「AutoGPT ではレビュー無しの草案がレガシー spec と同じ結果に到達した（無人実行）。SK では BoolOp の
  メンバー候補が第 1 段を自動化し、第 2 段（`self.search` → `_parse_and_validate_filter`）は IccTA の設定ファイル
  プロバイダに相当する解析者固定のまま」と書ける。

---

## 追記13（2026-08-29 深夜）: フェーズ B — アンカリング・カタログと門 2

コンポーネント 4（`anchoring.py`）・5（`spec.presets.json` の `match` / `dispatch` 行 + `catalog.py`）を実装し、
leave-one-out 用の `--disable S1,S2,S3,anchoring` を前倒しで入れた（詳細は `docs/SCALE_OUT_DESIGN.md`「フェーズ B」）。

### 仕組みの要点
- **アンカー = 呼び出し位置が自分の宛先集合を名指ししている**（IccTA の explicit Intent）: 値が def / class に解決する
  dict / list リテラル、`self.<attr> = <def>`（vanna の `run_sql_*` 6 本。入れ子 def なので `importable=False`）、
  `x.register(fn)` / `add_tool(fn)`、`self.attr[k] = fn`。文字列の map（provider 表）や関数ローカルの dict は
  アンカーにしない。読み出しをエンジン行に結合し、エンジン壁 + closed アンカー → メンバーを level-1 候補にして
  narrowing、エンジンが resolved の読み出し（型付きレジストリ）は proposed（off）。
  **closed の定義（添削 C6 後、実装が保証する条件だけ）**: アンカーは定義モジュールで修飾して鍵付け（`pkg.mod.REGISTRY` /
  `pkg.mod.Cls.attr` — `anchors.json` の `name` は修飾名、`short` が表示名）。closed = 全メンバーが可視の def / class /
  インスタンス、かつ名前がモジュールレベルで 1 回だけ束縛され、どのスコープでも `NAME[k] = v` / `del` / `.update/.pop` /
  `+=`・`|=` / `global` + 代入 / 別名（`ALIAS = NAME` 自体が open）で変更されず、`Cls.attr` ならさらに `self.attr = <実行時値>`
  が無く、クラス本体・木内基底に同名宣言が無く、サブクラスが束縛しない。サブクラスからの `self.attr` 読みは inherited
  読み（`binding: inherited`、`anchor_closed: false`）で候補追加のみ、narrowing も confirmed もしない。無関係な同名属性の
  クラスは結合しない（旧実装は `*.attr` フォールバックで最初のアンカーに結合し、llama_index-0.9.28 で 14 件の誤った
  confirmed を出していた）。`--reject-anchor <修飾名>`（短名も可）。
- **カタログは 1 ファイル 17 行**（langchain 4 / semantic_kernel 2 / openmanus 2 / llama_index 5 / fastmcp 2 /
  openai_agents 1 / superagi 1。追記時点では 14 行だった）。`catalog.detect` で木の FW を採点し、草案が何も accept しないとき
  **帰属 FW の dispatch API が in-repo の callable に 1 つも無い**（search path = venv にだけある行は
  `catalog_status_search_path` に分けて報告し、stale のまま — 添削 M4。以前は venv 込みの `functions.json` で判定していたので
  venv に FW がある限り `catalog_stale` は発火しなかった）を `catalog_stale`（exit 3）として `no_surface`（exit 2）から区別する。
- **メソッド名の不合理リンク除去**（門 2 の lc_real 全木で必要になった）: `x.m(...)` の壁に対し、クラスメソッド候補は
  名前が `m` かカタログの impl 対応（`run → _run`）に一致するものだけ。`self._validate_tools()`（docstring-only の
  stub）に `BaseTool._run` 13 件が付く問題を消す。関数候補・アンカー・BoolOp・明示候補は対象外。

### 門 2 の結果
- **langchain（lc_real 型消去、全木・無人）**: 壁 219 行 → 草案 accept 102（却下 117）。lowering 52 壁 / 553 リンク
  （unreasonable 650、レジストリ除外 130）、32 ファイル変更、pyre 56 秒 → **3 issue / sink 3 組**
  （既存 cond_B_notype の 1 組 `BaseTool.run` + `PythonAstREPLTool._run` + `PythonREPLTool._run`）、residual net 0。
  agent.py の 2 壁だけに絞った plan では 2 issue（REPL 2 組）。型付き lc_real は cond_A で既に 1 issue（追記11）。
  → 無人草案でも基準を下回らず、新規到達 sink は本物の RCE 経路（REPL ツール）。（sink 組は旧鍵。この lc_real 型消去の全木は
  benchmark の langchain 行とは別木の手動ゲートで、版 8092345c での確定値は追記16 の langchain benchmark 行が持つ — 再計測 2026-08-31・版 8092345c）アンカーは
  `AGENT_TO_CLASS`（3 行）と `_MSG_CHUNK_MAP`（1 行）で新規行を追加したが sink には寄与せず。
- **OpenManus（GitHub main、2026-08-29 時点、`app/` 48 ファイル、source は `LLM.ask_tool` / `LLM.ask` の戻り値、
  sink は TaintP2X 標準）**: cond_A 0 issue（pyre 345 秒、venv 入り）。無人草案 1 回目は主壁
  `tool_collection.py:32:27`（`await tool(**tool_input)`、S1 `UnknownIdentifierCallee`、T3）を accept したが
  **候補 0**（カタログ行 `ToolCollection.execute` から候補基底を `ToolCollection` と誤導出）→ 0→0、`row.json` は
  `no_walls` として正直に記録された。カタログ行に `base: BaseTool` を持たせ、検出プリセットの回収キーを既定に
  する修正後、同じ cond_A から草案を作り直すと `execute` 候補 10 件（PythonExecute / Bash / WebSearch / …）→
  20 壁中 12 accept（却下 8）、30 リンク lowering（90 が名前で unreasonable）、3 ファイル変更、pyre 379 秒 →
  **0 → 12 issue / sink 12 組**（RemoteCodeExecution ×4、FileSystem_ReadWrite ×4、SSRFSink ×4 —
  `ReActAgent.step` / `ToolCallAgent.act` / `PlanningFlow._execute_step` / `_finalize_plan` から Bash・PythonExecute・
  ファイル操作・WebSearch へ）、residual net 0。無人実行（レビュー未実施。修正はカタログ側 — 添削 C7）。
  → OpenManus は「エンジン壁 + カタログの impl 対応」で決まり、アンカー（`tool_map` は内包表記で open）は不要だった。
- **vanna 0.6.2（sdist、source は `submit_prompt` の戻り値、sink は `VannaBase.run_sql(sql)`）**: cond_A **3 issue**
  （sink が `run_sql` 自身なので `self.run_sql(sql)` の解決先 = base の stub で流れが閉じる: 5001 ×1（`get_plotly_figure`
  の exec）、5008 ×2）。草案: S2 壁 11 行（`self.run_sql(sql)` 7 箇所は T1〜T3）、アンカー `VannaBase.run_sql`
  （closed、入れ子 def 11 本: `run_sql_sqlite` … `run_sql_hive`）がメンバーを名指しするが、**77 リンク全て phantom**
  （入れ子 def は import 不能）→ lowering 出力なし → cond_B 3 issue、delta 0、`row.json` は `no_walls`（現行語彙では `no_candidates`）、residual 8（旧定義。版 8092345c では residual net 9（confirmed 5）— 再計測 2026-08-31・版 8092345c）。
  無人 1 回目は `error_deprecation()`（raise するだけの関数を名前で呼ぶ）34 行を S2 として accept していた →
  S2 を「受け手が動的なとき」に限定（`name_call` / `super().m()` は壁でない）して 45 → 11 行に。
  → 設計書が予告した否定的結果（「入れ子 def の対象は not_importable として名指しのみ、hoist 前処理は本計画から外す」）
  がそのまま出た。修論には「vanna 型（backend を入れ子 def で差し替える）は本手法の対象外で、壁とその宛先は
  正確に名指しできるが計装できない」と書く。

### 門 2 のまとめ（これらは `tool_version` 無しの手動ゲート運転の値: 各行の sink 組は旧鍵、outcome は旧 6 値語彙 — vanna は現行では
`no_candidates` / `phantom_majority`。版 8092345c での benchmark 行の確定値は追記16 — 再計測 2026-08-31・版 8092345c）
| 対象 | 草案 | lowering | cond_A → cond_B | outcome |
|---|---|---|---|---|
| langchain（lc_real 型消去、全木） | 219 行 / accept 102 | 52 壁・553 リンク・32 ファイル | 0 → 3 issue（3 sink 組、うち REPL `_run` 2 組が新規） | delta_pos |
| OpenManus（`app/`） | 20 行 / accept 12 | 3 壁・30 リンク・3 ファイル | 0 → 12 issue（RCE 4・FileSystem 4・SSRF 4） | delta_pos |
| vanna 0.6.2 | 13 行 / accept 11 | 0（77 phantom） | 3 → 3 | no_walls（設計上の否定的結果） |

いずれも無人実行（レビュー未実施。修正は 2 件ともシステム側: カタログ行の `base`、S2 の受け手限定。旧記述の
「手直し 0」は `plan.draft.json` が無く観測不能だった — 添削 C7）。手作業は方針どおり
`.pysa`（各 3〜5 行）と環境（OpenManus / vanna は venv 入りで pyre 345〜380 秒）だけ。

### 今回判明したこと（設計への修正）
1. **カタログ行には候補の基底クラスが要る**（`ToolCollection.execute` → `BaseTool.execute`）。API のクラスと候補の
   クラスは別物。`base` を追加し、検出したプリセットの回収キーを草案の既定にした。
2. **メソッド名の不合理リンク除去**が全木規模では必須（lc_real: `self._validate_tools()` に `_run` 13 件が付く）。
3. **S2 は受け手が動的なときだけ**（vanna の `error_deprecation()` 34 行）。
4. アンカーが効いたのは vanna（宛先の名指し）だけで、lc_real の `AGENT_TO_CLASS` 等は sink に寄与せず、OpenManus の
   `tool_map` は内包表記で open。「アンカーは explicit Intent 相当のロングテール補完」という位置づけどおり。

### 次
9（`run_benchmark.py` + `benchmark.json`、23 対象 + 派生 3 行のバッチ）、10（残り fixture の `--engine` 期待値、leave-one-out の
表）、その後は各対象の `.pysa` と環境（手作業）。

---

## 追記14（2026-08-30）: フェーズ C — バッチランナーと fixture のエンジン期待値

### コンポーネント 9: `run_benchmark.py` + `benchmark.json`
- マニフェスト 26 行 = TaintP2X Benchmark と同じ 23 対象・版 + 派生 3 行（`derived: true`、`derived_from` に親対象。
  TaintP2X の対象ではない: コミット済み AutoGPT M2 subset の `AutoGPT-classic-subset`（手動 `.pysa`）と、全体では
  1200 秒に収まらない langchain 2 版の import 閉包 subset `*-agents-subset`。派生行は別の木で草案・レビュー・cond_B は
  独立、`dataset_dir` の参照 issue 数は親行にだけ出す — 添削 M11）: fetch は git tag（AutoGPT、MetaGPT、OpenManus、SuperAGI、
  quivr、llama_index 0.11）か pypi sdist（langchain ×6、litellm、llama-index ×3、pandasai ×2、vanna ×4）、`pkg_root`
  （quivr は `backend/` を `flatten`）、**手動の** `pysa_models`（`benchmark_models/` — OpenManus と vanna の 2 本。
  他は TaintP2X の LLM SDK source モデルのみ）、`dataset_dir`（同梱 pysa-runs の count-only 事前確認と参照 issue 数）、
  preset。カテゴリは同梱データの `base_server/<CAT>` に従う。
- 段: `fetch → env → draft（cond_A + pyre 1 回、`DRAFT=1`）→ レビュー門 → condB（`REUSE_COND_A=1`）→ row`。
  `state.json` で再開、`PYRE_TIMEOUT=1200`（TaintP2X の予算）で打ち切り→ `env_failed`。`review.minutes` が null の plan は
  `--accept-draft` 無しでは lowering を拒否（無人回帰と人のレビューを区別）。`aggregate` で `summary.{jsonl,csv,md}`
  （マニフェスト全 26 行に 1 行 — 未着手は `pending`、派生 3 行は別表・別 outcome 行 —、FW 別集計、outcome 分布、
  leave-one-out 表。`walls_accepted`（lowering 時点の accept 数）と `walls_lowered`（`cond_B/links.json` で lowered リンクを
  1 本以上持つ壁数）は別列 — 添削 M6 / M11）。`--stage ablate` は `--disable` 各軸の草案（pyre 無し、
  `--ablate-pyre` で軸ごとの cond_B）。
- `test_benchmark.py`（ネットワーク・実 pyre 不要。run_ablation.sh を stub pyre で 1 回 end to end に通し、cond_B timeout の門 — 添削 M5 —
  と ablate の done / `--force` 契約 — 添削 C3 — を固定）と `test_ablation_helpers.py`（`row.json` の書き手: sink 組の鍵、net の outcome、
  `plan.draft.json` との review_edits）— 項目数は本文に書かない（全件 pass、コマンドで確認）。スモーク: OpenManus を `--stage all --accept-draft` で
  fetch（GitHub）→ env → draft → condB → row まで無人で完走（結果は下）。

### コンポーネント 10: fixture のエンジン期待値
- `run_bench.py --record` で全 fixture の AST 壁に Pysa が何を記録するかを採取し、`engine` 期待値を書き込んだ
  （`phantom_target` / `rejected_wall` は Pysa 検証対象外。fixture は 2026-08-30 時点で 31、添削 C1 の `two_walls_before_stub` を
  含む。per-line の `engine` dict に無い壁が検出されれば fixture 失敗）。対応表: subscript / getattr → `UnknownCallCallee`、
  BoolOp / `f = resolve(k); f(..)` → `UnknownIdentifierCallee`、`t = self.tools[k]; t.run(..)` → `UnknownBaseType`、
  `fn(args)`（仮引数）→ `UnknownIdentifierCallee` だが accept off、`o.fn(args)`（callable 属性を持つ引数）→
  `UnknownBaseType` で受け手が仮引数 = 環境の穴（草案に出ない）、型付き dict → `resolved`。
  `run_bench.py --pyre --engine`（Pysa 実行）で **全 fixture × 2 形式 PASS**（2026-08-30、31 fixture）。

### バッチの最初の結果（ランナー経由、無人）

> **本節（追記14）の対象別数値は、添削で反証された定義（residual の basename 同定、sink 組の第一呼び出し先鍵、6 値の outcome、
> CAND_DIR 二重走査、S2 の宣言クラス CHA、合体 impl map）と複数のコード版・カタログ版が混ざった旧 `benchmark_out` の値である。
> 文は消さず、影響する数値には版 8092345c の確定値を併記した（再計測 2026-08-31・版 8092345c）。全 26 行を 1 つの `tool_version` に
> 揃えた最終値のまとめは追記16。**
- **OpenManus**（GitHub main 3309bf4e、`app/` 71 ファイル）: fetch → env → draft（cond_A pyre 375 秒）→ condB（392 秒）→ row
  を無人で完走。**0 → 12 issue / sink 12 組**、residual net 0、outcome delta_pos（門 2 の手動実行と同じ結果）。
  同梱データセットの参照 issue 数は 2（TaintP2X 論文時点の環境）。
- **leave-one-out（草案レベル、OpenManus）**: full 12 壁 / 30 リンク、−S1 → 1 / 10、−S2 → 12 / 30、−S3 → 11 / 20、
  −anchoring → 12 / 30。OpenManus では S1（`tool(**tool_input)` 等の未解決）がほぼ全てを担い、S3（カタログの
  `ToolCollection.execute`）が 10 リンク分を足す。S2 とアンカーは寄与なし（`tool_map` は内包表記で open）。
  軸ごとの cond_B（`--ablate-pyre`）は実行中。
- **AutoGPT（データセットと同じ版、`forge` + `autogpt` 全体 133 ファイル、venv 入り、手動 `.pysa` なし）**: cond_A pyre
  467 秒（予算内）→ 草案 30 壁 / accept 8 だが **`no_sources`**（in-repo に source を持つ callable が 0: TaintP2X の
  LLM SDK source は AutoGPT の `tool_call` 経路に届かない）→ condB スキップ、outcome `no_sources`。
  → 「source 宣言は手作業」という方針の帰結がそのまま行になる。手動 `.pysa` を付けた **AutoGPT-classic-subset**
  （コミット済み M2 サブセット + `autogpt_v05.pysa`、venv 抜き）はランナー経由で **0 → 7 / sink 5 組（旧鍵。現行鍵では 2 組・新規 2・消失 0
  （再計測 2026-08-31・版 8092345c））、pyre 9 + 7 秒**、delta_pos。（添削 M9 で書き換え）事実は「サブセット + `.pysa` では delta_pos、
  全体 + generic モデルでは no_sources」であり、両行は fetch / pkg_root / search_venv / `.pysa` の名前付け（subset の
  `agent.Agent._execute_tool` は全体木では `autogpt.agents.agent.Agent._execute_tool`）が同時に違う。venv 除外とサブセット化を
  同時に適用したため、`.pysa` の有無だけが要因とは言えない（全体木 + `.pysa` + search_venv=0 の行は未試行）。
  なお 1 回目は `row.json` の outcome 判定が「cond_B 無し = env_failed」と誤っていたので、草案の判定
  （no_sources / no_surface / catalog_stale / no_walls）を優先するよう直した。
- **devika（GitHub main、`src/` 69 ファイル、venv 入り）**: cond_A pyre 472 秒。in-repo に source を持つ callable 23
  （TaintP2X の LLM SDK モデルが届く）。壁行 20 だが **accept 0 → `no_walls`**: `method_call` 13 行は
  `self.agents["planner"].execute(...)` のような**定数キー**でのレジストリ読み出し（実行時選択ではない）、`param_call`
  7 行は retry / logger ラッパの仮引数呼び出し（anchoring 待ち）。カタログ一致なし、アンカー 0。
  → 「面はあるが動的ディスパッチではない」対象の実例（再計測 2026-08-31・版 8092345c: 現行コードの再草案は 28 壁 / accept 3、
  links_lowered 0 なので outcome は `no_candidates`（issue 5 → 5、sink 組 4 → 4、residual 2）。旧 `no_walls` から変わった）。
- **vanna 0.6.2（ランナー経由、pypi sdist、手動 `.pysa` あり）**: cond_A 3 → cond_B 3、草案 13 壁 / accept 11、
  リンク 77 全 phantom、residual 8（旧定義。版 8092345c の再走では 31 壁 / accept 15 / links_lowered 0 / residual 9（confirmed 5）— 再計測 2026-08-31・版 8092345c）、outcome `no_walls`（旧語彙。現行では accept > 0 かつ
  links_lowered 0 なので `no_candidates` / `outcome_reason: phantom_majority` — 添削 C2）（門 2 の手動実行と同じ。同梱データの
  参照 issue 数 6）。pyre 439 + 444 秒。→ ランナーは OpenManus（delta_pos）・vanna（現行語彙 no_candidates）・
  AutoGPT サブセット（delta_pos）・AutoGPT 全体（no_sources）・devika（no_walls）を無人で記録した。outcome の語彙は
  添削 C2 / M5 で 11 値（env_failed | no_sources | no_surface | catalog_stale | no_walls | no_candidates | drafted |
  delta_pos | delta_mixed | delta_neg | delta0）に改めた: delta_pos は net（新規 > 0 かつ消失 0）、`no_walls` は草案 accept 0
  だけ、cond_B の pyre timeout は `env_failed`。
- **langchain 0.0.131（pypi sdist、`langchain/` 404 ファイル、venv 入り、手動 `.pysa` なし）**: cond_A **358** issue
  （TaintP2X の LLM SDK source が届く。同梱データの参照値は 601 — 論文時点の環境差）、pyre 439 秒。草案 168 壁 /
  accept 10（BoolOp 2、抽象 stub 4、`DEFAULT_FORMATTER_MAPPING[k]` 4 — アンカーは open だがメンバー 1）、
  104 リンク lowering（352 が名前で unreasonable。初回草案の値。C4 = 草案の dry-run と実走 cond_B で CAND_DIR が違い、
  実走では registry narrowing が外れていた。版 8092345c の確定は下の「再実行」項と追記16: 210 壁 / accept 15 / links_lowered 100
  — 再計測 2026-08-31・版 8092345c）、cond_B **406（+48）、sink 組 157 → 165（+8、`LLMChain.predict` /
  `combine_docs` 系の RemoteCodeExecution）**（旧鍵・初回草案。版 8092345c では 358 → 508、sink 組 221 → 308（新規 87・消失 0）
  — 再計測 2026-08-31・版 8092345c）、residual net 27
  （**旧定義の値**: lowering が生成した guard ブロック内の呼び出しと、ブロック挿入で行がずれた lowering 済み壁を残差に
  数えていた。版 8092345c では residual net 11 = confirmed 2 + unlowerable 2 — 再計測 2026-08-31・版 8092345c）、outcome delta_pos、pyre 407 秒。
  → 大きな木でも無人草案が基準を壊さず（cond_A の 358 はそのまま）、追加分だけが乗る。（訂正: 以前ここに「残差 27 は
  accept されなかった proposed 行」と書いたのは誤り。residual は cond_B に残った taint 到達（T1/T2）の未解決・stub・obscure
  呼び出しで、草案の accept とは独立に数える。`row.json` の `residual_rows` がその位置一覧。）
- **ランナーの不具合（修正済み）**: `--stage ablate --ablate-pyre` が軸ごとの作業ディレクトリに `cond_A` を symlink で
  置いていたため、`run_ablation.sh` の `cp -r cond_A cond_B; rm -rf cond_B/r` が実体を書き換え・削除し、軸別 cond_B が
  全て 0 issue になった（OpenManus）。実体コピーに変更し、OpenManus は cond_A から作り直して再実行。
- **langchain 0.0.194（765 ファイル）**: cond_A 1039 issue（参照値 2709）、pyre 509 秒。草案 180 壁 / accept 13、182 リンク
  lowering（904 が unreasonable。初回草案の値。版 8092345c では 294 壁 / accept 18 / links_lowered 119 — 再計測 2026-08-31・版 8092345c）、cond_B **1039（delta 0）**、sink 組 541 → 539（旧鍵。row.json の
  値は 539 で、以前ここに書いた 536 は誤り）（版 8092345c では 1039 → 1052（+13）、sink 組 567 → 579（新規 12・消失 0）、outcome delta_pos
  — 再計測 2026-08-31・版 8092345c）、residual net 57（旧定義。
  S2 規則後の再走の row.json では raw 62 / net 60、C1 修正後の `residual()` を同じ cond_B に読み取り専用で再計測すると
  raw 17 / net 11 だった。版 8092345c の再走では **residual net 16 = confirmed 2 + unlowerable 4** — 再計測 2026-08-31・版 8092345c）、
  pyre 881 秒（予算内）。
  → 旧鍵では「lowering が新しい sink に届かない」delta0 に見えたが、現行鍵では新規 12 の delta_pos。（訂正・添削 C2）旧鍵で sink 組が減ったのは、issue 集合は不変で
  (種別, callable) の組が付け替わったため。原因未確認（widening / 固定点の変化を原因と断定する根拠は無い: 同一 cond_A の
  2 回実行も、消失組と lowering 位置の対応付けも benchmark_out に無い）。現行鍵 (種別, issue callable) では同じ row が
  567 → 573（新規 6・消失 0）で delta_pos になる（S2 規則後の cond_B の再生成 row）。
- **leave-one-out（Pysa 付き、OpenManus、cond_A を作り直した後）**: full 0→12 / −S1 → **0→8**（残るのはカタログの
  S3 壁 `available_tools.execute(...)` 1 行・10 リンクだけで、それでも 12 組中 8 組に届く）/ −S2 → 12 / −S3 → 12
  （S1 の `tool(**tool_input)` が S3 の到達先を包含）/ −anchoring → 12。
  → OpenManus では S1 と S3 が互いに冗長（どちらか一方で 8〜12 組）、S2・アンカーは寄与なし。修論の ablation 表の 1 行目。
- **langchain 0.0.232（912 ファイル）**: cond_A 1289（参照値 886）、pyre 763 秒。草案 224 壁 / accept 17、204 リンク
  lowering（1644 unreasonable。初回草案の値。版 8092345c では 366 壁 / accept 24 / links_lowered 159 — 再計測 2026-08-31・版 8092345c）、cond_B **1516（+227）、sink 組 657 → 754（+97、`AgentExecutor._atake_next_step` 等の
  ExecImportSink）**（旧鍵・初回草案。版 8092345c では 1289 → 1536（+247）、sink 組 676 → 809（新規 133・消失 0）— 再計測 2026-08-31・版 8092345c）、residual net 56（旧定義。この cond_B は S2 規則後の
  再走が 1200 秒打ち切り env_failed だったが、それは負荷起因の timeout で、版 8092345c の再走では完走し **residual net 13 = confirmed 2 + unlowerable 0** — 再計測 2026-08-31・版 8092345c）、pyre 855 秒、delta_pos。
- **leave-one-out（Pysa 付き）追加 2 件**:
  - AutoGPT-classic-subset: full 0→7 / −S1 → accept 0（lowering 無し、S1 だけが全て）/ −S2・−S3・−anchoring → 7。
  - langchain 0.0.131（版 8092345c で再実行済み — 再計測 2026-08-31・版 8092345c。以下は当時の旧草案の記録）: この
    leave-one-out（`ablation.json` 01:11）は **S2 オーバーライド規則より前の
    旧草案**（none = accept 10 / dry-run 14 リンク）のもので、現行 plan.json（accept 18 / 22）とは一致しなかった（aggregate は
    `stale` と表示）。旧草案では full +48（sink +8）/ −S1 → +48（accept は 10 → 12 に増える非単調: fan-out 降格の副作用）/
    −S2 → **0** / −S3 → +48 / −anchoring → +48。（訂正・添削 C3）−anchoring の説明は逆だった: −anchoring では
    `DEFAULT_FORMATTER_MAPPING` の 4 壁が唯一の候補（`jinja2_formatter` の level-1 リンク 4 本）を失い 14 → 10 リンク、
    issue は 406 で不変、sink +2（165 → 167）は同一 issue 数での組の入れ替え（原因未確認）。narrowing（filtered_registry 90）は
    両軸とも `links.index_registries` の辞書リテラル由来でアンカーとは無関係（アンカー自体は open / 1 member）。
    **版 8092345c の同一版 leave-one-out（stale なし）**: full 15 壁 / 100 リンク、−S1 6/17 [358→508]、−S2 10/45 [**358→358**]、
    −S3 15/100 [358→508]、−anchoring 13/78 [358→508]。**−S2 = 358→358 で S2 が +150 全部を担う**（再計測 2026-08-31・版 8092345c）。
  → 3 対象で寄与する機構が異なる（OpenManus: −S1 のみで 0→8 に落ちる、AutoGPT: S1、langchain 0.0.131: −S2 が +150 全部を担う）。
    「S1 だけでは足りない」という設計書のリスク項目（再現率）は 3 件で裏付けられた。
- **leave-one-out が見つけた 2 つの規則**（設計書「フェーズ C」にも記載）: (i) S2 壁（stub / abstract メソッド）に
  レジストリ由来の**関数**候補は付けない（関数はメソッドをオーバーライドできない）。full 草案で `AgentOutputParser.parse`
  に `DEFAULT_FORMATTER_MAPPING` の関数 19 件が流れ込み fan-out 上限で落ちていた。(ii) S2 壁の候補は**エンジン自身の
  `override-graph.json`** から取る: `BaseCache.lookup → InMemoryCache / RedisCache / SQLAlchemyCache`（受け手 BaseCache）。
  （訂正・添削 C5）候補集合は**受け手の静的型で絞ったクラス階層（CHA）の宛先集合**: `call-graph.json` の `receiver_class` と
  その推移的サブクラスに属する override だけを取る。追記時点の「`Agent._validate_tools → ZeroShotAgent / ReActDocstoreAgent /
  SelfAskWithSearchAgent`」は宣言クラス単位の CHA で、受け手が ChatAgent / ConversationalAgent / ConversationalChatAgent
  （サブクラスに override 無し）の 3 壁に型上不可能な 9 リンクを足していた — 現行規則ではこれらは壁でない
  （`s2_reason: receiver_subclass_no_overrides`。`_validate_tools` は本体 `pass` の empty stub）（版 8092345c ではこの型上不可能な 9 リンクは除かれた
  上で 358 → 508 / +150 — 再計測 2026-08-31・版 8092345c）。「エンジンが base に解決した理由が受け手の静的型でも
  `skipped_overrides` でも」と書いたうち後者は 0.0.131 では成立しない（`type.__init__` / `object.__init__` のみ）。
  `AgentOutputParser.parse` は木に override 実装が無く候補 0 — abstract stub（`@abstractmethod`）なので **unlowerable な壁**として
  残す（`resolved_stub`、候補 0、proposed、off、`residual_unlowerable`。方針決定 2026-08-30、追記15「方針決定」1。決定前は
  「壁扱いしない」だった）。`r_min/lc_0_0_131` にテストを固定（`test_draft.py` / `test_engine_walls.py` 全件 pass、コマンドで確認）。
  この草案で langchain 0.0.131 の cond_B を再実行した（結果は下。確定値は版 8092345c、追記16）。
- **langchain 0.0.327（sdist、`langchain/` 約 1,000 ファイル超、venv 入り）**: cond_A の pyre が **1200 秒の予算で打ち切り**
  → outcome `env_failed`（TaintP2X と同じ予算。同梱データの参照値 7 issue は論文側の環境で完走している）。
  → 「環境が支配的」というリスク項目の実例。`subset_extractor` で入口ファイルからの部分木にするのが次の手（手作業の環境側）。
- **langchain 0.0.131 再実行（S2 のオーバーライド候補 + 関数候補除外）**: 草案 accept 10 → 18、lowering リンク 104 → 112
  （C4: 草案の dry-run は 22 リンクで、cond_B の 112 は CAND_DIR=TARGET_SRC の二重走査で
  `DEFAULT_FORMATTER_MAPPING` の narrowing が外れた `prompts/base.py:48` の 91 ターゲット（G49W0）を含んでいた。0.0.194 の 211、
  0.0.232 の 251、0.0.327-subset の 674 も同じ。版 8092345c で narrowing を復し型上不可能な 9 リンクを除いた確定は
  **210 壁 / accept 15 / links_lowered 100** — 再計測 2026-08-31・版 8092345c）（stub 壁は `_validate_tools` 3 箇所 × 3 agent（C5: 受け手の
  型上不可能な 9 リンクは版 8092345c で除去済み）、`BaseCache.lookup` 4、`update` 3）。cond_B **406 → 508（delta +48 → +150）**
  （版 8092345c では **358 → 508（+150）**、+150 は型上不可能な 9 リンクを除いた後も維持 — 再計測 2026-08-31・版 8092345c）、
  **sink 組 165 → 205（+8 → +48、`AgentExecutor._take_next_step` 等への EmailSend / RCE）**（旧鍵。現行鍵では
  **221 → 308（新規 87・消失 0）** — 再計測 2026-08-31・版 8092345c）、
  residual net 27 → 23（旧定義。版 8092345c では **residual net 11 = confirmed 2 + unlowerable 2**。旧 23 は lowering の副産物で
  約 8 倍に膨れていた（C1） — 再計測 2026-08-31・版 8092345c）、pyre 431 秒。→ 同じ対象の delta が大きく増えたが、その内訳には
  narrowing の欠落分（C4）と型上不可能な辺（C5）が含まれていた。（訂正・添削 C3）「leave-one-out の −S2 = 0 と合わせ S2 が
  寄与の全て」は旧草案（01:11）の −S2 を新草案の +150 に当てた主張だったが、版 8092345c の同一版 leave-one-out で
  **−S2 = 358 → 358（+150 全部が S2）** が裏付けられた（上の leave-one-out 追加 2 件を参照）。
- **residual の再計測（添削 C1、2026-08-30）**: 旧 residual は壁を `(basename, 行)` でしか同定せず、lowering の副産物を
  残差に数えていた。langchain 0.0.131 の旧 net 23 のうち 18 行は lowering が `prompts/base.py:48`
  （`DEFAULT_FORMATTER_MAPPING[k]`、91 ターゲット）の直後に生成した `if __ctaudit_unreachable__:` ブロック（cond_B の
  49〜235 行）内の `__ctaudit_obj._run(template)`（`_run` は抽象メソッド → resolved_stub）、3 行は insert_before で行がずれた
  lowering 済みの壁（few_shot.py 119→116、few_shot_with_templates.py 143→140、conversational_retrieval/base.py 99→96）。
  修正後（壁の同定を src_root 相対パス + 行 + 列に、生成ブロック内と生成 redirector モジュール内の位置を `generated` として
  除外、cond_B の行をブロック範囲から cond_A の行へ逆写像）の `engine_walls.residual()` を **同じ cond_B（01:23 の Pysa 出力、
  links.json は basename 鍵の旧形式 → legacy fallback、`legacy_links: true`）** に適用すると **raw 15 / net 10**
  （lowered 壁 11、生成ブロック内の除外 199、行ずれ再写像 3）。残る 10 は全て `unresolved:UnknownBaseType` /
  `UnknownIdentifierCallee` の T1/T2 サイト（`llm_summarization_checker/base.py:118/129`、`llms/openai.py:646/678`、
  `agents/load_tools.py:293/300`、`vectorstores/milvus.py:157`、`vectorstores/deeplake.py:146/155/156`）で、lowering の
  副産物ではない。添削レポートが「真の residual 3」に挙げた `agents/agent.py:176/194` の `output_parser.parse` は、この読み取り
  時点の C5（受け手クラスの CHA）では resolved（stub を override する実装が木に無い）で壁でなかった。その後の方針決定（2026-08-30、
  追記15「方針決定」1）で abstract stub は unlowerable な壁として残すことにしたので、現行コードではこの 2 行は residual に戻り
  `residual_unlowerable` に数える（`test_lc_0_0_131_receiver_class` が固定。本段落の数値は決定前の読み取り値。版 8092345c の再走では
  **residual raw 20 / net 11 = confirmed 2 + unlowerable 2**、176/194 の 2 行が unlowerable に戻った — 再計測 2026-08-31・版 8092345c）。`row.json`（abl/ と最上位）は
  現行コードで再生成し（residual raw 15 / net 10 / `legacy_links: true`、sink 組は (種別, issue callable) 鍵で 221 → 308、
  新規 87・消失 0、outcome delta_pos）、`summary.md` は aggregate で作り直した（`residual_net` 10、脚注に「pre-C1 links.json
  で netted」の印）。cond_B 自体は再走していないので、相対パス鍵の links.json で確認するには condB → row の再走が要る。
  他対象の residual（本節の 57 / 56 / 60 / 25 / 22 / 19 / 12 / 8 など）も旧定義の値で、当時は row.json / summary.md 未更新
  だった（C1 修正後の読み取り専用の再計測: 0.0.194 raw 17 / net 11、0.9.28.post2 raw 95 / net 36、0.7.13 raw 25 / net 9、
  0.10.25 raw 39 / net 38、0.11.23 raw 48 / net 47、0.0.327-subset raw 28 / net 16、litellm raw 9 / net 9、vanna raw 9 / net 9、
  SuperAGI raw 5 / net 4、pandas-ai raw 1 / net 1 — raw の増減には C1 以外の規則変更分も含まれる）。**版 8092345c の全対象再走での
  residual net（confirmed / unlowerable）**は追記16 の表: 0.0.131 net 11（2/2）、0.0.194 net 16（2/4）、0.0.232 net 13（2/0）、
  0.7.13 net 9（6/0）、0.9.28.post2 net 38（9/0）、0.10.25 net 48（13/10）、0.11.23 net 53（16/6）、0.0.327-subset net 24（8/0）、
  litellm net 9（2/0）、vanna 0.6.2 net 9（5/0）、SuperAGI net 4（0/0）、pandas-ai net 1（1/0）、quivr net 4（2/0）（再計測 2026-08-31・版 8092345c）。
- **langchain 0.2.5（pypi sdist `langchain/`）**: 同じく 1200 秒で打ち切り → `env_failed`。0.0.327 以降の langchain 本体は
  予算内で完走しない（サブセット化が前提）。
- **langchain-experimental 0.0.61**: cond_A 完走したが **`no_sources`** — LLM 呼び出しが `langchain_core` の抽象
  （`BaseLanguageModel.predict` 等）経由で、TaintP2X の openai SDK source モデルが届かない。手動 `.pysa`（例:
  `BaseLanguageModel.predict` の戻り値を source に）を付けるまで行は `no_sources`。
- **litellm 1.40.12**: pypi の sdist が取得できず `fetch_failed` → git tag `v1.40.12` に切り替えて再実行。
- **S2 規則後の再実行**: langchain 0.0.194 は accept 13 → 23（stub 壁 3 箇所に override 候補。版 8092345c では 294 壁 / accept 18 —
  再計測 2026-08-31・版 8092345c）、cond_B 1039 → **1045
  （delta 0 → +6）**（版 8092345c では 1039 → 1052（+13、新規 12）— 再計測 2026-08-31・版 8092345c）、delta_pos。langchain 0.0.232 は
  lowering が 204 → 251 リンク（版 8092345c では links_lowered 159 — 再計測 2026-08-31・版 8092345c）に増え、当時は他ジョブと同時実行の負荷も
  あって cond_B が 1200 秒で打ち切り → `env_failed`（`row.json` の判定を「lowering 済みで cond_B 無し = env_failed」に
  修正。以前は no_walls と誤記していた）が、版 8092345c の再走では完走し **1289 → 1536（+247、新規 133）の delta_pos**（負荷起因の timeout だった — 再計測 2026-08-31・版 8092345c）。
- **llama_index 0.7.13（pypi sdist、408 ファイル）**: cond_A 48（参照値 3）、pyre 486 秒。草案 103 壁 / accept 58
  （S1 89 行のうち accept 多数、S2 obscure 6、S3 `BaseTool.__call__` 1）だが **lowering はわずか 7 リンク** → cond_B 48、
  **delta 0**、residual 12（旧カタログ版の plan の値。C7 / C1: `tool_impl_methods: ["execute"]` の OpenManus 衝突で候補 0 → 旧 delta0 に
  なっていた。版 8092345c ではカタログを FW 固有化した上で **48 → 57（+9）、sink 組 36 → 45（新規 9・消失 0）、147 壁 / accept 62 /
  walls_lowered 26 / links_lowered 89、residual net 9（confirmed 6）、delta_pos** — 再計測 2026-08-31・版 8092345c）。accept された壁の大半に候補が無い（llama_index 0.7 のツール基底 `BaseTool` / `FunctionTool`
  の impl 名がカタログ行（`call` / `_fn`）と合わない、レジストリ由来の候補も無い）→ 「壁は正しく名指しできるが
  候補側が空」の対象。レビューで候補を pin するか、カタログ行を 0.7 系に合わせる必要がある（カタログの版依存）。
- **カタログ行の衝突（llama_index 0.7.13 で発覚）**: dispatch 行は dotted 接尾辞で照合するため、`BaseTool.__call__` が
  OpenManus 行（impl `execute`）にも llama_index にも当たり、llama_index の草案に `tool_impl_methods: [execute]` が
  入って候補 0 になっていた。行にモジュール接頭辞を付けて FW 固有にし（`app.tool.base.BaseTool.__call__`、
  `llama_index.tools.types.BaseTool.__call__ → __call__ / _fn`）、presets の行を組み込み既定より優先するよう修正。
  再草案では accept 57 行のうち 57 行に候補、71 リンク（`FunctionTool.__call__` 等 4 ツール × 各壁 — recall-first の
  fan-out）（当時「57/57 に候補」は scratchpad の草案。版 8092345c の再草案は **147 壁 / accept 62 / walls_lowered 26 /
  links_lowered 89**、cond_B は 48 → 57（+9）の delta_pos — 再計測 2026-08-31・版 8092345c）。
- **litellm 1.40.12（git tag、`litellm/` 162 ファイル）**: cond_A **0 issue**（TaintP2X の openai source モデルは
  litellm 自身の provider 呼び出しに届かず、in-repo の source 保持 callable が無い）。草案 387 壁 / accept 164（`provider`
  文字列での getattr / dict 分岐が大量）だが候補はほぼ無く lowering 0 → cond_B 0、outcome `no_walls`（旧語彙。現行では
  accept 164 > 0 かつ links_lowered 0 なので `no_candidates` / `outcome_reason: no_links`、`walls_lowered` 0 — 添削 C2 / M6）
  （pyre 555 + 503 秒）。→ 「面は広いが宛先集合を名指しする構造（ツール登録）が無い」対象。参照値 9。
  （版 8092345c の再走: **689 壁 / accept 119 / links_lowered 0、issue 0 → 0、outcome `no_candidates`（`no_links`）、
  residual net 9（confirmed 2）**、帰属 FW は現行 detect で `(none)` — 再計測 2026-08-31・版 8092345c）。
- **litellm が露わにした規則の穴**: `x = kwargs.get('metadata') or {}; x.get(...)` の受け手は「呼び出しとリテラルの
  BoolOp」で束縛されており、名前付き callable の選択ではない。受け手が BoolOp で束縛された壁は、代替が全て Name
  （closed）のときだけ accept するよう修正 → litellm の accept 164 → 58（残りは `custom_prompt_dict[model]` のような
  subscript 受け手と `param_call`）（58 は当時の scratchpad 草案。版 8092345c の確定は 689 壁 / accept 119 — 再計測 2026-08-31・版 8092345c）。
  lowering に影響なし（候補 0 のまま、現行語彙では `no_candidates`）。
- **サブセット行（`subset` オプション、venv 抜き・deps_iso 隔離）**:
  - langchain 0.0.327-agents-subset: `agents/agent.py` からの import 閉包が 923 / 1210 ファイル（0.0.327 は密結合）だが
    pyre は **248 + 244 秒で完走**（全体では 1200 秒超過）。初回は cond_A 657 → cond_B 662（+5）、294 壁 / accept 25 / 674 リンク
    （初回草案の値。版 8092345c では **457 壁 / accept 21 / links_lowered 140** — 再計測 2026-08-31・版 8092345c）、residual 25
    （旧定義。版 8092345c では **residual net 24（confirmed 8）** — 再計測 2026-08-31・版 8092345c）、delta_pos。sink 組は 489 → 483 と 6 減（旧鍵）。
    （訂正・添削 C2）「delta_pos（弱い）」という定義外の修飾は廃止。現行鍵で 763 → 662 / sink 組 416 → 365（新規 5・消失 56）の
    delta_mixed に見えていたのは、その cond_B が C4 の二重走査アーティファクトだったため。**正典 cond_A は 763（164 秒）**で、旧 657（248 秒）は
    修正前のサブセット閉包で作った**別の木**の値。版 8092345c では **cond_A 763 → cond_B 768（+5）、sink 組 416 → 421（新規 5・消失 0）の delta_pos**、
    同一木での pyre 再実行は issue 多重集合が完全一致（763 = 763）— 決定性を実測（再計測 2026-08-31・版 8092345c）。（添削 M9）全体行（venv 574 MB を search_path、1200 秒超）とこの subset 行（deps_iso 73 MB、
    search_venv=0、ファイル −24%）は解析環境が同時に違い、env_gaps も subset 5229 vs 全体 0.0.131 1007 と解決結果自体が変わる
    ので、全体と subset の数値は比較不能。全体木 + search_venv=0 は未試行。
  - langchain 0.2.5-agents-subset: 閉包 135 ファイル（langchain_core 等は deps_iso で型のみ）。cond_A 66 → 66、
    33 壁 / accept 3 / 29 リンク、**sink 組 72 → 60（新規 6・消失 18）**（旧鍵）。0.0.327 サブセットも新規 7・消失 13、
    0.0.131 は新規 53・消失 5（`BaseConversationalRetrievalChain._acall` 系）。
  → （訂正・添削 C2）旧鍵の「消失」は lowering が flow を消した証拠ではない。0.2.5-subset は (callable, code, line) の多重集合が
  cond_A と cond_B で完全一致し、消失 18 = 6 種別 × {<direct>, RunnableBindingBase.batch, RunnableRetry.batch}、新規 6 = 同じ
  6 種別 × RouterRunnable.batch — 同一 call site の `resolves_to` が縮んで組が付け替わっただけ。**issue 集合は不変で
  (種別, callable) の組が付け替わった。原因未確認**（固定点 / trace 上限の変化を原因と断定する根拠は無い）。現行鍵
  (種別, issue callable) では 0.2.5-subset 18 → 18、llama_index 0.10.25 98 → 98、0.11.23 61 → 61 でいずれも delta0
  （版 8092345c で確定 — 再計測 2026-08-31・版 8092345c）。`row.json` と summary の `sinks_lost` は現行鍵で残し、消失があれば `delta_mixed` / `delta_neg` に出す。
- **llama_index 0.9.28.post2（pypi sdist、701 ファイル、venv 入り）**: cond_A 259（参照値 928）、pyre 469 秒。草案 272 壁 /
  accept 125、149 リンク lowering（118 unreasonable）、カタログ `llama_index.tools.types.BaseTool.__call__` 4 命中
  （FW 固有化後の行）。cond_B **637（+378）、sink 組 137 → 280（新規 147・消失 4）**（この cond_B
  は旧 anchoring の `*.attr` フォールバックで `AnthropicProvider.messages_to_prompt / completion_to_prompt` に無関係な 18 クラスの
  読みが結合し 14 件が confirmed で accept、`llms/vllm.py:226-229` 等に `messages_to_anthropic_prompt(messages)` の誤った辺が
  挿入された状態の値。C6 修正後は同アンカーの読みは 0（クラス本体宣言で open）。版 8092345c ではその誤った wildcard アンカー辺を除いた上で
  **259 → 632（+373）、sink 組 174 → 214（新規 40・消失 0）、382 壁 / accept 150 / walls_lowered 70 / links_lowered 132、delta_pos** — 再計測 2026-08-31・版 8092345c）、
  residual 60（旧定義。C1 修正後の読み取り専用の再計測は raw 95 / net 36。版 8092345c では **residual net 38（confirmed 9）** — 再計測 2026-08-31・版 8092345c）、pyre 340 秒、delta_pos。
  新規は `ReActAgent.chat` / 各 LLM `complete` 経由の ExecDeserializationSink 等。→ 0.7.13（旧カタログ版で候補 0 / delta 0）と
  対照的に見えるが、両行はカタログ版もコード版も違った。版 8092345c で両者を揃えると 0.7.13 も 48 → 57 の delta_pos になり、
  「カタログ行が版に合うと到達する」が同一版で確認できた（再計測 2026-08-31・版 8092345c）。
- **llama_index-core 0.10.25（pypi sdist、457 ファイル）**: cond_A 117、pyre 337 秒。草案 174 壁 / accept 91、85 リンク
  （256 unreasonable）、カタログ命中 0（0.10 系の `core.tools.types.BaseTool.call` に解決する in-repo 呼び出しが無い）。
  cond_B 117（issue 数は同じ）、**sink 組 82 → 85（新規 6: `ContextChatEngine.chat` 等の RCE / deserialization、消失 3）**
  （旧鍵。現行鍵では 98 → 98、delta0 — 再計測 2026-08-31・版 8092345c）、residual 22（旧定義。版 8092345c では **residual net 48
  （confirmed 13 / unlowerable 10）** — 再計測 2026-08-31・版 8092345c）、outcome は旧鍵で delta_pos、
  現行の net 定義では delta0。→ 旧鍵では「issue 数だけ見ると delta 0 に見える例」としていたが、組の付け替えだった。
- **llama_index 0.11.23（git tag、core のみ 508 ファイル）**: cond_A 75、pyre 370 秒。草案 203 壁 / accept 107、129 リンク
  （272 unreasonable）、カタログ命中 0。cond_B 75、**sink 組 54 → 55（新規 2・消失 1）**（旧鍵。現行鍵では 61 → 61、delta0
  — 再計測 2026-08-31・版 8092345c）、residual 19（旧定義。版 8092345c では **residual net 53（confirmed 16 / unlowerable 6）** — 再計測 2026-08-31・版 8092345c）、pyre 363 秒。
  → 0.10 / 0.11 の core は ReAct/agent の dispatch が `llama_index.core.agent` 側にあり、ツール呼び出し `tool.call(...)` の
  in-repo 呼び出し元がほぼ無い（integration 側）。カタログ行（`core.tools.types.BaseTool.call`）は存在するが命中しない。
- **MetaGPT 0.6.3（git tag v0.6.3、`metagpt/` 170 ファイル）**: cond_A 完走（pyre 380 秒）、草案 84 壁 / accept 51、
  アンカー 15（closed 13、読み出し 0）、カタログは semantic_kernel / langchain の base class 名が誤検出（import 無し。
  現行 detect では帰属 `(none)` — 添削 M4。種プリセットの回収キーは閾値未満でも semantic_kernel から供給される）。
  候補が付かず lowering 0 → `no_walls`（旧語彙。現行では accept 51 > 0 なので `no_candidates`）（参照値 22）。MetaGPT の role → action ディスパッチ（`self._actions[i].run()`）は
  リストの index 参照で、ツール登録の慣用句ではない。
- **pandas-ai 0.8.0 / 0.8.1（pypi、36 ファイル）**: 壁 4 / 3、accept 2 / 2、候補なし → `no_walls`（旧語彙。現行では
  `no_candidates`。版 8092345c の再走では 14 / 13 壁 / accept 12・12 / links_lowered 0 / issue 5 → 5 / sink 組 2 → 2 /
  residual 1（confirmed 1）、outcome `no_candidates` — 再計測 2026-08-31・版 8092345c）（参照値 8 / 8、
  pyre 約 330 秒 × 2）。LLM が生成したコードを `exec` する経路は sink 側の話で、動的ディスパッチの面が無い。
- **添削（多エージェント検証）で確認された不具合 1 件目・修正済み**: `run_benchmark.py` のサブセット閉包が、保持ファイルの
  パッケージ `__init__.py` を閉包ループの後に追加していたため、その再エクスポート（`from .x import y`）が辿られず
  参照先が削除される（0.0.327 サブセットで 41 箇所、0.2.5 で 4 箇所の壊れた import）。さらに相対 import の解決が
  パッケージ直下の `__init__.py` に吸われていた。検証者の測定では壁行への影響は小さい（0.2.5 サブセットの S1 18 行中
  5 行と env gap 6 件が `module_import.py` 削除に起因、lowering・cond_B には影響なし）が、「入口からの import 閉包」
  という記述が正確でなくなるため修正: `__init__` を閉包内で辿る固定点反復、相対 import を実ファイル基準で解決、
  剪定後に残る壊れた import 数を `state.json` に記録（`broken_imports`）。サブセット 2 行は版 8092345c で再実行済み
  （0.0.327-subset 763 → 768 の delta_pos、0.2.5-subset 66 → 66 の delta0。追記16）。
- **SuperAGI 0.0.14（git tag、`superagi/` 267 ファイル）**: cond_A 4（参照値 2）、pyre 319 秒。草案 21 壁 / accept 13、
  主壁は `tool_executor.py:39` の `tools[tool_name]._execute(...)`（subscript 受け手）と `tool_builder.py:80` の
  `getattr(module, tool.class_name)`（動的クラス読込）だが**候補 0** → `no_walls`（旧語彙。現行では `no_candidates`）。原因はカタログに SuperAGI の行が
  無いこと（独自 `BaseTool.execute → _execute`、langchain 行の `_run` と impl 名が違う）。1 行のプリセット
  （`superagi.tools.base_tool.BaseTool.execute → _execute`、base `BaseTool`）を追加して再草案（結果は下）。
- **SuperAGI の再草案が露わにした規則 3 つ（修正済み）**: (i) `base_class` 由来の impl メソッド候補（`_execute` 36 件）が
  `Session()` のような裸の名前呼び出しの壁にも付いていた → impl メソッドは dispatch API（またはカタログの `__call__`
  行）経由でしか到達しないので、裸の呼び出しでは unreasonable。(ii) fan-out 上限（16）が本物のレジストリ壁
  `tool.execute(...)`（36 ツール）を落としていた → メソッド名フィルタで候補が dispatch API の impl に限定される
  method/attr 壁は上限の対象外（fan-out = 登録ツール集合）。(iii) `dispatch_impl_map` を全 FW の行から作っていたため
  OpenManus の `__call__ → execute` が他 FW にも効いていた → active FW（木が import する FW + 明示 preset + 検出 top）の行だけ
  から作る（添削 M10 で「検出 FW のみ」から改めた。空でも書き、`DEFAULT_IMPL_MAP` は手書き spec の既定のみ）。
  再草案: accept 13 のうち `tool_executor.py:39:30` だけが 36 リンク、他は候補 0（`Session()` 等は正しく 0）。
  cond_B を再実行した（結果は下。版 8092345c で確定）。
- **SuperAGI 再実行（新規則の草案）**: `tool_executor.py:39:30` に 36 リンク lowering → cond_B 4 → 4、sink 組 3 → 3、
  **delta 0**（pyre 380 秒）。壁の taint 階層は **none**（囲む `ToolExecutor.execute` に source 由来のフレームが無く、
  BFS でも到達しない）で、LLM 由来の taint が `tool.execute(parsed_args)` の
  引数に届いていない（SuperAGI は LLM 応答を DB 経由で受け渡し、TaintP2X の source モデルが届く経路が in-repo に無い）
  → 「壁と宛先集合は正確に名指しできたが source が届かない」= 手動 `.pysa`（DB 読み出しを source に）の領域。
- **quivr 0.0.236（git tag、`backend/` を flatten、258 ファイル）**: 当初は cond_A の pyre が 1200 秒で打ち切り → `env_failed`
  （FastAPI / supabase / langchain 等の依存を venv 込みで解析、かつ再実行チェーンと同時実行）。版 8092345c ではマニフェストに
  `pyre_timeout: 3000` を与えて再走し、cond_A 749 / sink 組 416、cond_B も完走して **749 → 749、sink 組 416 → 416、
  17 壁 / accept 5 / walls_lowered 3 / links_lowered 59、residual net 4（confirmed 2）、delta0** — 再計測 2026-08-31・版 8092345c
  （`_ablation_env` が `PYRE_TIMEOUT` 環境変数を `t.spec.get("pyre_timeout", 1200)` で上書きするため、行ごとに予算を延ばせる）。
- **添削 M6 / M11（2026-08-30、修正済み）**: (i) `summary.md` の `walls_lowered` は `walls_detected − walls_rejected`（= accept 数、
  `draft_accepted` と同値の重複列）だった。`cond_B/links.json` で `status == 'lowered'` のリンクを持つ壁数に改め、accept 数は
  `walls_accepted` 列に分離。再生成後の値: litellm 164 → 0、MetaGPT 51 → 0、vanna 0.6.2 11 → 0（いずれも `no_candidates`）、
  llama_index 0.7.13 41 → 22、OpenManus 12 → 3（`residual.lowered_walls` と一致）（当時は旧 plan（`tool_version` 無し）の
  cond_B からの読み取り専用値。版 8092345c の再走では walls_lowered = litellm 0 / MetaGPT 0 / vanna 0.6.2 0 /
  llama_index 0.7.13 26 / OpenManus 3 — 再計測 2026-08-31・版 8092345c）。(ii) マニフェストは 26 行（TaintP2X の
  23 対象 + 派生 3 行）で、旧 `aggregate` は row.json / state.json の無い対象を落として「24 targets / pending 2」と出していた。
  現行はマニフェスト全行を出し（未着手の vanna 0.3.3 / 0.3.4 は `pending`）、派生行は別表・別 outcome 行（同じプロジェクトを
  全体と subset で二重に数えない）。`benchmark_out` の row.json（abl/ と最上位）と `summary.{md,jsonl,csv}` は現行コードで
  `--stage row --force` → `aggregate` により再生成済み（`test_benchmark.py` の published rows 検査が両定義を固定）。

---

## 追記15（2026-08-30）: 添削の反映 — 定義の実装合わせ、限界、再計測

添削レポート（2 名の検証者、C1〜C7 / M1〜M11 / minor）を受けて、コードは他の担当が修正し、本書・README・
`docs/SCALE_OUT_DESIGN.md` の定義と主張を実装に合わせて書き換えた。反証された数値・主張は消さず、暫定であることを印で示した。
確定値は**全対象を同一版で再実行**して出す方針で、その再実行は 2026-08-31 に完了した（下の追記16、版 8092345c）。

### 定義（実装通り。修論の用語はこれに揃える）
- **壁** = in-repo の呼び出し位置のうち、無改変エンジンが (i) 呼び出し先を名指しできない（S1）、または (ii) 名指しはするが
  本体へ taint を運べない（S2 stub / obscure、S3 dispatch メソッド）位置。**到達条件は含めない**（M7）。T1/T2/T3 は報告のみ
  で門ではなく、`none` は別の壁の背後や generic モデル下の位置を含む。accept は engine_status / idiom だけで決まる。
- **S2 の候補集合** = 受け手の静的型（`call-graph.json` の `receiver_class`）とその推移的サブクラスに限定したクラス階層（CHA）
  の宛先集合（C5）。「IccTA の宛先集合に最も近い形」とは言わない。`receiver_subclass_no_overrides`（受け手から到達できる override
  が無い）は stub の種別で分かれる（方針決定 2026-08-30、下の「方針決定」1）: empty stub なら壁でない、abstract stub なら候補 0 の
  unlowerable な壁（`resolved_stub` / proposed / off / `residual_unlowerable`）。`receiver_unknown`（Protocol 受け手を含む）なら
  候補はデコレータ / アンカー回収から（事前 accept のまま、unlowerable 規則の対象外）。
- **sink 組** = (sink 種別, issue callable)（C2）。旧鍵 (sink 種別, 発見 callable からの第一呼び出し先) は `first_hops` 診断に残し、
  AutoGPT 回帰の `EXPECT_SINKS_B=5` はその旧鍵 `SINK_FIRST_HOPS` を門にしたまま（現行鍵では 2 組）。
- **outcome** = env_failed | no_sources | no_surface | catalog_stale | no_walls（草案 accept 0）| no_candidates（accept > 0 かつ
  links_lowered 0。`outcome_reason` = no_links / phantom_majority / unreasonable_majority / filtered_*_majority /
  no_args_majority / mixed）| drafted | delta_pos（新規 > 0 かつ消失 0）| delta_mixed | delta_neg | delta0（C2 / M5）。
  cond_B の pyre timeout は env_failed。vanna 型の「入れ子 def のみ」は `no_candidates` / `phantom_majority`（`not_importable`
  という outcome は無い）。`run_benchmark._table_outcome` は環境判定（no_sources / no_surface / catalog_stale）を空虚な
  `0 → 0` の delta0 より優先する: cond_B が走っても草案の環境判定どおり空なら表はその環境判定を残す（AutoGPT 全木は cond_B が
  `0 → 0` でも `no_sources`）。
- **residual** = 生成ブロック（`if __ctaudit_unreachable__:`）と生成 redirector モジュール内を除外し、cond_B の行を cond_A の行へ
  逆写像した後で、cond_B に残る T1/T2 のエンジン未解決（unresolved / stub / obscure）in-repo 呼び出し位置。src_root 相対パス
  で同定（C1）。proposed 行（定数キーの inline subscript 受け手）も数える。`residual_raw` / `residual`（net）/ `lowered_walls` /
  `generated_excluded` / `remapped` / `legacy_links`、および net の分割 `residual_confirmed`（confidence が confirmed の net 壁）と
  `residual_unlowerable`（`s2_reason == receiver_subclass_no_overrides` の net 壁 = 木内実装の無い abstract stub）。`row.json` では
  `residual.confirmed` / `residual.unlowerable` と `residual_rows[].confidence`、`summary.md` では `residual_net` の隣の列
  `residual_confirmed` / `residual_unlowerable`（分割前に作った row は空欄）、CLI `residual` は stderr に 1 行要約。読み方:
  `residual_net − residual_unlowerable` = lowering できたはずなのに残った壁、`residual_confirmed` = そのうち confirmed idiom の
  部分集合（C5 方針）。
- **closed アンカー** = 実装が保証する条件だけ: モジュール修飾の鍵、`self.attr` / `NAME[k]` / `global` / AugAssign / 別名による
  再束縛なし、クラス本体・木内基底の宣言なし、サブクラスの束縛なし、wildcard 結合は継承関係に限定し inherited 読みは
  narrowing しない（C6）。
- **catalog_stale** = 帰属 FW の dispatch API が in-repo の callable に無い（search path = venv にだけある行は別途報告、stale
  のまま）（M4）。
- **impl map**（`dispatch_impl_map`）= active FW（木が import する FW + 明示 `--preset` + 検出 top preset）のカタログ行のみ。
  `DEFAULT_IMPL_MAP` は手書き spec でキーが無いときの既定だけ（M10）。
- **マニフェスト** = TaintP2X の 23 対象 + 派生 3 行（`AutoGPT-classic-subset`、`langchain-0.0.327-agents-subset`、
  `langchain-langchain-0.2.5-agents-subset`）（M11）。派生行は別表で、親との比較は対照になっていない（M9）。
- **IccTA との対応**: 計装位置の決め方は同型ではなく違い（M8）。IccTA は外部リンク解析（IC3/Epicc）が名指した文を
  `IPCMethods.txt`（約 30 = 非コメント行。`soot-infoflow-android-iccta-master/res/IPCMethods.txt` は 34 行中 30 行、
  `release/res` の写しは 25 行）で限定して計装し、FlowDroid は無改変。本手法は外部解析を持たず、エンジンの未解決記録が
  一次カタログ。

### 記録の仕組み（C7）
- `draft.py` は読み取り専用の原本 `plan.draft.json`（0444）を書き、`row.json` の `review_edits` はそれと cond_B の plan の
  diff。`draft_source` が原本の有無を示し、原本の無い旧 bundle の 0 は「観測不能」。
- plan（version 2）/ row / ablation / state の全てに `tool_version`（`toolver.py`: engine_walls / links / draft / anchoring /
  catalog / pipeline / dispatch_lowering / spec.presets.json / ablation_helpers / run_ablation.sh の sha256）。summary は
  `versions_match`（yes / no / plan unversioned）で不一致行に印を付け、leave-one-out 表は plan と一致しない軸を `stale` と示す。
- `DRAFT=1` / `ACCEPT_DRAFT=1` の再実行はレビュー済み `plan.json`（原本と異なるもの）を保持、`FORCE_DRAFT=1` でだけ捨てる。
  `PLAN_JSON` に `plan.draft.json` を渡すと preflight が拒否。
- `CAND_DIR` は壁の木 `$WORK/cond_B/src` が既定（C4）。`links.json` の `file` は src_root 相対パス（C1 / K1）、壁にも
  `lowered_line`。`walls.md` に `receiver` 列（受け手クラス、plain|overrides、s2_reason）。

### 限界（修論に書く）
1. **較正と評価の分離が無い**: 規則（S2 の受け手限定、BoolOp 受け手、メソッド名フィルタ、fan-out 上限の例外 …）と
   カタログ行は評価対象を見ながら反復して較正した。held-out の対象は無い。
2. **「レビュー手直し 0」は「無人実行（レビュー未実施）」の意味**で、「草案に手直しが不要だった」ではない。
3. **数値の出所**: 旧 `benchmark_out` は複数の規則版・カタログ版・草案（0.0.131 は 2 つ）から作られ、residual /
   links_lowered / sink 組 / outcome / leave-one-out はそれぞれ別の理由で旧定義だった。2026-08-31 に全 26 行を版 8092345c で
   再走し（追記16）、plan / row / ablation は 1 つの `tool_version` に揃った（summary の全行 `versions_match: yes`、脚注の異常
   リストは全て「(none)」）。
4. `receiver_unknown` の accept（langchain-0.0.131 の `LoadingCallable.__call__` 3 壁、48 リンクで新規 issue 0）を続けるかは
   **未決のまま**（下の「方針決定」は unlowerable 規則を `receiver_unknown` へ広げていない: Protocol 受け手は事前 accept を続ける）。
5. （決定済み 2026-08-30 — 下の「方針決定」1）受け手が抽象基底そのもので木に override が無い abstract stub（`agents/agent.py:176/194`
   の `self.output_parser.parse`）は「木内に宛先が無い taint 消失点」として空候補の壁に残す（unlowerable、`residual_unlowerable`）。
   empty stub は従来どおり壁でない。
6. （決定済み 2026-08-30）residual は proposed 行も数える。accepted-only 相当は `residual_confirmed`（confirmed 行の net 残差）が答える。
7. 版 8092345c での再草案は旧 `benchmark_out` から accept 数を大きく動かした（litellm 164 → 119、llama_index-0.7.13 41 → 62、
   pandas-ai 2 → 12、devika 0 → 3、langchain-0.0.131 18 → 15 / dry-run リンク 100）。これらが summary.md の確定値（追記16）。
8. 種プリセットの供給は閾値で切っていない（MetaGPT は閾値未満でも semantic_kernel の回収キーを受ける）。帰属と stale
   判定だけが閾値を見る。

### 方針決定（2026-08-30, 添削後）
添削の反映後の 2 回目のコード修正で決めた 2 点。上の限界 5 / 6 はこれで決定済み、限界 4（`receiver_unknown`）は未決のまま。
1. **S2 の stub 種別と unlowerable な壁**: stub を abstract（`@abstractmethod` / `abc.abstractmethod` / `abstractproperty`、または本体が
   `NotImplementedError` を raise）と empty（`pass` / docstring のみ / `...` / それ以外の raise）に分ける（`engine_walls._stub_kind`）。
   abstract stub を owner 自身か非実装サブクラスの受け手で呼び、受け手から到達できる木内 override が無い位置は壁のまま残す:
   `resolved_stub`、候補 0、confidence proposed、accept false、note `unlowerable: no in-tree implementation of <owner>.<m>`、
   `residual_unlowerable` に数える（`build_plan` は `--include-proposed` でも accept しない。アンカー読みがメンバーを供給した場合だけ
   例外。`plan.hints` に kind `unlowerable`）。empty stub を具象の葉の受け手（override するサブクラス無し）で呼ぶ位置は `resolved`
   （壁でない、`s2_reason: receiver_subclass_no_overrides`）。Protocol 受け手は `receiver_unknown` のまま。理由: 壁の定義
   （エンジンが名指しはするが taint を運べない位置）ではこの抽象呼び出しも壁であり、木内にリンク先が無いからといって隠すと
   残差を過小に見せる。langchain-0.0.131 では `agents/agent.py:176/194` の `self.output_parser.parse`（`AgentOutputParser.parse`）が
   unlowerable、`cls._validate_tools` の兄弟 3 箇所（本体 `pass`）は resolved。同時に residual の net を `residual_confirmed` /
   `residual_unlowerable` に分割（限界 6 の accepted-only 相当は前者）。未決の縁: NotImplementedError 以外の例外を raise するだけの
   本体は empty 扱い。
2. **レジストリ索引の twin（添削 C4 の注意）**: `links.index_registries` の重複排除は realpath と内容ハッシュ**だけ**で、相対パスでは
   飛ばさない。同一内容の複製が 2 つの走査ルート越しに見えても 1 束縛、同じ相対パスで内容が違うファイルは 2 束縛 → その名前は
   untrusted（ファイルルートとして渡した twin と同じ判定）。理由: 相対パスで飛ばすと先に見た木のリテラルを黙って信頼し、別リビジョン
   のメンバーを取りこぼす。鍵は依然 bare name（モジュール修飾なし）。

### 再計測の手順（コードの最終版が固まった後、ROOT で venv を有効にして）
```
cd dispatch-taint/taintp2x_extension
python3 run_benchmark.py --stage all --from draft --force --keep-cond-a --accept-draft     # 全対象（cond_A 再利用、cond_B は Pysa）
python3 run_benchmark.py --stage ablate --ablate-pyre --force --only AutoGPT-classic-subset langchain-0.0.131 OpenManus
python3 run_benchmark.py --stage aggregate
```
この再実行を 2026-08-31 に完了し、plan / row / ablation は 1 つの `tool_version`（8092345c）に揃った。暫定の印は本パスで
確定値に置き換えた（下の追記16）。本書・README・設計書の対象別数値（追記13〜14、SCALE_OUT_DESIGN のフェーズ結果、
README の AutoGPT sink 組）は、その版の確定値を併記した形になっている。
テスト件数は本文に書かない: `test_engine_walls.py` / `test_draft.py` / `test_anchoring.py` / `test_pipeline.py` /
`test_ablation_helpers.py` / `test_benchmark.py` / `test_registration.py` / `bench/run_bench.py [--pyre --engine]` は全件 pass
（コマンドで確認。件数は添削対応で増え続けている）。添削項目の固定（内容のみ）: `test_benchmark.py` は run_ablation.sh を stub pyre で
1 回 end to end に通して cond_B timeout の門（M5）と ablate の done / `--force` 契約（C3）を、`test_registration.py` (G) は links 側の
inline 受け手 idiom（`self.tools[k].run` / `getattr(o, k).m` / `(a or b).m` → method_call — M1）を、`test_engine_walls.py` は residual の
相対パス鍵（同じ basename で別ディレクトリの links.json は net しない — C1）と S2 stub 方針（lc_0_0_131 の 176/194 が unlowerable、
`_validate_tools` 3 箇所が resolved — C5）を固定する。

---

## 追記16（2026-08-31）: 同一版での再計測（版 8092345c）

追記15 で予告した全対象の同一版再走を実行した。マニフェスト全 26 行（TaintP2X の 23 対象 + 派生 3 行）を
1 つのツール版 **8092345c3e549188** で `run_benchmark.py --stage all --from draft --force --keep-cond-a --accept-draft`
→ `--stage ablate --ablate-pyre --force --only AutoGPT-classic-subset langchain-0.0.131 OpenManus` → `--stage aggregate`
にかけ、追記13〜14 と本設計書に暫定で載せていた数値を確定値に置き換えた。plan / row / ablation / state は全て
同一 `tool_version` を持ち、`summary.md` の全行が `versions_match: yes`、脚注の全異常リスト（版不一致・plan 未版・
pre-C1 links.json・旧鍵・旧 impl map）は**すべて「(none)」**。

### outcome の内訳（全 26 行）
- **TaintP2X 23 対象**: delta_pos 6、delta0 4、no_candidates 9、no_sources 2、env_failed 2。
- **派生 3 行**: delta_pos 2、delta0 1。

主な行（delta_pos、いずれも消失 0）:

| 対象 | issue A→B | sink 組 A→B（新規） | walls / accept / walls_lowered / links_lowered | residual net（conf/unlow） |
|---|---|---|---|---|
| langchain-0.0.131 | 358 → 508（+150） | 221 → 308（+87） | 210 / 15 / 15 / 100 | 11（2/2） |
| langchain-0.0.194 | 1039 → 1052（+13） | 567 → 579（+12） | 294 / 18 / 17 / 119 | 16（2/4） |
| langchain-0.0.232 | 1289 → 1536（+247） | 676 → 809（+133） | 366 / 24 / 23 / 159 | 13（2/0） |
| llama_index-0.7.13 | 48 → 57（+9） | 36 → 45（+9） | 147 / 62 / 26 / 89 | 9（6/0） |
| llama_index-0.9.28.post2 | 259 → 632（+373） | 174 → 214（+40） | 382 / 150 / 70 / 132 | 38（9/0） |
| OpenManus | 0 → 12 | 0 → 9（+9） | 28 / 12 / 3 / 30 | 0（0/0） |
| AutoGPT-classic-subset（派生） | 0 → 7 | 0 → 2（+2） | 1 / 1 / 1 / 4 | 0（0/0） |
| langchain-0.0.327-agents-subset（派生） | 763 → 768（+5） | 416 → 421（+5） | 457 / 21 / 18 / 140 | 24（8/0） |

delta0: llama_index-0.10.25（117→117、sink 98→98、residual 48（13/10））、llama_index-0.11.23（75→75、61→61、
residual 53（16/6））、SuperAGI-0.0.14（4→4、3→3、residual 4）、quivr-0.0.236（749→749、416→416、residual 4（2/0））、
langchain-0.2.5-agents-subset（派生、66→66、18→18、residual 0）。
no_candidates: devika（5/5、sink 4/4、accept 3、residual 2）、litellm-1.40.12（689 壁 / accept 119、residual 9（2/0））、
MetaGPT-0.6.3（accept 51、phantom_majority、residual 2（2/0））、pandas-ai-0.8.0 / 0.8.1（accept 12、residual 1（1/0））、
vanna-0.3.1 / 0.3.3 / 0.3.4（2→2、residual 9（5/0））、vanna-0.6.2（3→3、residual 9（5/0））。
no_sources: AutoGPT 全木、langchain-experimental-0.0.61。env_failed: langchain-0.0.327、langchain-0.2.5（どちらも
cond_A が 1200 秒予算で打ち切り。サブセット行がその版の証拠）。

**vanna 0.3.3 / 0.3.4 の行**は今回初めて走らせた（旧 aggregate では `pending` だった）。4 版とも同じ否定的結果
（入れ子 def の backend、`no_candidates`、links_lowered 0）で、設計どおりの負例。

**`run_benchmark._table_outcome`（環境判定の優先）**: cond_B が走っても草案の環境判定どおり空虚な `0 → 0` なら、表は
delta0 でなくその環境判定（no_sources / no_surface / catalog_stale）を残す。AutoGPT 全木は cond_B を測って `0 → 0`
だったが、表は `no_sources` を保つ（in-repo に source を持つ callable が無いため）。

### leave-one-out（同一版、stale なし）
セルは「accept 壁数 / dry-run リンク数」、pyre 付きは「[cond_A → cond_B]」。

| 対象 | full | −S1 | −S2 | −S3 | −anchoring |
|---|---|---|---|---|---|
| AutoGPT-classic-subset | 1 / 4 | 0 / 0 | 1 / 4 [0→7] | 1 / 4 [0→7] | 1 / 4 [0→7] |
| langchain-0.0.131 | 15 / 100 | 6 / 17 [358→508] | 10 / 45 [**358→358**] | 15 / 100 [358→508] | 13 / 78 [358→508] |
| OpenManus | 12 / 30 | 1 / 10 [**0→8**] | 12 / 30 [0→12] | 11 / 20 [0→12] | 12 / 30 [0→12] |

**最大の所見: langchain-0.0.131 の −S2 = 358 → 358** — S2（stub / abstract メソッド壁のオーバーライド候補）を外すと
+150 が丸ごと消える。この対象の寄与は S2 が全部を担う。OpenManus は逆に −S1 でだけ 0→8 に落ち（S1 が支配）、
−S2 / −S3 / −anchoring は 0→12 のまま。AutoGPT-classic-subset も −S1 で accept 0（lowering 無し）。3 対象で支配的な
エンジンクラスが異なることが、同一版で確認できた。「S1 だけでは足りない」という設計書のリスク項目（再現率）は
langchain-0.0.131 の −S2 で裏付けられた。

### 決定性（同一木での 2 回目の pyre）
`langchain-0.0.327-agents-subset` と `OpenManus` について、byte 単位で同一の cond_A 木に対し pyre をもう一度走らせ、
issue の多重集合を比較した（`determinism/*/compare.json`）: **完全一致**（0.0.327-subset は 763 = 763、sink 組の消失 0 = 0）。
これで「lowering 前後の差は前処理によるもので、Pysa の非決定性ではない」を実測で裏づけた。なお 0.0.327-subset で
以前記録した cond_A 657 と今回の 763 の食い違いは**別の木の値**である: 657 は修正前のサブセット閉包（`__init__`
再エクスポート・相対 import の取りこぼしで参照先が削除された木）から出たもので、閉包を修正した現在の正典木では
cond_A は 763。決定性は同一木でのみ主張する。

### quivr の `pyre_timeout` と delta0
quivr-0.0.236 は当初 cond_A が 1200 秒で打ち切られ env_failed だったが、マニフェスト行に `pyre_timeout: 3000` を与えて
再走した（`run_benchmark._ablation_env` が `PYRE_TIMEOUT` 環境変数を `t.spec.get("pyre_timeout", 1200)` で上書きするので、
行ごとに予算を延ばせる）。結果は cond_A 749 / sink 組 416、cond_B も完走して **749 → 749、sink 組 416 → 416、17 壁 /
accept 5 / walls_lowered 3 / links_lowered 59、residual net 4（confirmed 2）の delta0**。壁とその宛先は名指しできるが、
lowering しても新しい sink には届かない正直な delta0。

### 最終版での門の再確認
- **AutoGPT ゲート**: `AutoGPT-classic-subset` が 0 → 7 issue、`EXPECT_SINKS_B=5`（旧鍵 (種別, 第一呼び出し先) の 5 組、
  第一ホップの回帰門）は通過、現行鍵 (種別, issue callable) では 2 組・新規 2・消失 0。
- **SK ゲート 1**: sk_real で回帰 0 → 1 issue（code 5001）。
- **マイクロベンチ**: `run_bench.py --pyre --engine` が 31 fixture × 2 emit モードで全 PASS（エンジン期待値も一致）。
- テストは全件 pass（`test_engine_walls` / `test_draft` / `test_anchoring` / `test_benchmark` / `test_pipeline` /
  `test_ablation_helpers` / `test_registration` / `bench/run_bench.py`。件数は本文に書かない）。

これで追記13〜14・設計書のフェーズ結果・README の対象別数値は、版 8092345c の確定値に揃った。残る限界は較正と評価の
分離が無い点（同じ対象で規則・カタログを較正した、held-out なし。追記15 限界 1、設計書 限界 1）で、これは再走では
解消しない。
