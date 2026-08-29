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
解くのが本研究と同型であることに気づき、設計を対応づけて再構成した（対応表は README.md）。

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
6. **位置タグ・統計**（`JimpleIndexNumberTag` / `InfoStatistic` 相当）: `wall=<file>:<line>` と
   `# <link id>`（多段では `S<i>L<n>` で links.json と一致）、`lowered_line`、`LoweringStats`
   （`stats.json`、ablation の表）。
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
  これで AutoGPT は 0→**5** issue、到達した (sink 種別, sink メソッド) は **5 組で旧 7 件と同一**
  （旧 7 は execute_python_file の 2 つの汚染引数を別 issue として二重計上していた）。
  回帰判定は生 issue 数に加えて sink 到達の組数（`EXPECT_SINKS_B`）で行う。
- BoolOp 壁を `detect_boolop` として `detect_higher_order` から分離。挿入位置は呼び出し行でなく
  **文**の開始/終了行に。

### 対応が完全でない点（修論に正直に書く）

多エージェントによる添削で以下が確認された。いずれも README「Where the analogy stops」と
「Scope and honest limits」に明記済み:

1. **リンクの作られ方が違う**。IccTA の `ICCLink` は IC3/Epicc という外部の値解析が Intent を
   解決した結果で、1 リンク = 解決済みの (呼び出し位置 → コンポーネント)。本手法の
   `build_links` はディスパッチキー自体を解析せず、壁×候補を列挙して 2 つのフィルタで刈る。
   絞り込みが効かない壁（AutoGPT の `self._get_command(name)` 等）は候補全件に fan-out する。
   → 「IccTA と同じ精度源を持つ」とは書けない。「同じ形の IR を、列挙＋刈り込みで作る」と書く。
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
記述できる。ただし上の 1〜6 は差分・限界として明記すること。特に「IccTA と同型の設計を採る」
のと「IccTA と同じ健全性・精度を得る」のは別であり、後者は主張しない。

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
