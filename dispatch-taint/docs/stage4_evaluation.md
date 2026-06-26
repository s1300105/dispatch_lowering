# ステージ4評価設計：クロスツール暗黙的フローの実リポジトリ評価

> 本書は研究提案書「クロスツール暗黙的フローのデプロイ前静的監査」のステージ4
> （実データでの定量評価）の設計書である。対象リポジトリの選定基準・コーパス・
> 正解ラベリング手順・メトリクス・評価ハーネスへの接続・妥当性への脅威をまとめる。
> 実装状況：検出機構は自作 PoC と Pysa 移植の双方で動作確認済み。本書が定義する
> 実リポジトリ評価のみが未実施であり、これを実行して初めて非循環の数値が得られる。

---

## 0. 前提：静的監査と動的ベンチの橋渡し（最重要）

本研究のツールは **デプロイ前の静的監査** であり、エージェントを実行しない。一方、
公開されている関連ベンチ（AgentDojo / InjecAgent 等）は **動的** で、エージェントを
実際に走らせて攻撃成功率（ASR）を測る。したがって、それらを「正解ラベル付きの
静的解析対象」として使うには、次の読み替えを行う。

- ベンチが提供する **ツール定義の実コード** を静的解析の対象とする。
- ベンチが設計・文書化した **攻撃経路**（どの注入点からどの危険操作へ到達しうるか）を
  **正解ラベル** として用いる。これはモデル非依存に「経路として成立する」ことを示す
  ものであり、特定 LLM の運の良し悪し（あるモデルが何 % 騙されたか）とは独立である。

この読み替えにより、動的ベンチの脅威モデル（攻撃者が influence したツール出力 →
エージェント → 危険操作 = CWE-1426 のクロスツール暗黙的フロー）と、本ツールが検出する
対象が一致する。重要な含意は次の2点である。

1. **手書きパイプライン型**（CTF アプリ等）では source→sink の配線が具体的なので、
   recall と precision の双方が意味を持つ。
2. **汎用エージェント型**（AgentDojo 等、エージェントが任意のツールを呼べる）では、
   静的には「登録済み source ツール × sink ツール」の直積が候補になり、**枝刈り前の
   recall は自明に高く（過近似）、本質的な測定は §4.5 枝刈り + §4.6 トリアージ後の
   precision / 偽陽性**になる。すなわち AgentDojo は RQ2 の主戦場である。

---

## 1. 評価の狙いと RQ

| RQ | 問い | 主指標 | 主な測定対象 |
|----|------|--------|--------------|
| RQ1 | 既知の危険配線を検出できるか | recall（ラベル陽性の被検出率） | CTF 系（手書き配線） |
| RQ2 | 枝刈り・トリアージで精度が上がるか | raw→pruned→triaged の precision、prune 別アブレーション | AgentDojo・全対象 |
| RQ4 | フレームワークごとのコスト・被覆 | 解析時間、モデル化入口数 / 実呼び出し数 | 全対象 |

（RQ3 が提案書で別途定義されている場合は、被覆率や多フレームワーク対応の節として
本表に追加する。）

---

## 2. 対象選定の基準

修論で正当化できるよう、以下をすべて満たすものを選ぶ。

1. ツールが **Python 実装** で静的解析可能（ツールが単なる JSON 仕様でない）。
2. 対象フレームワーク（LangChain / LangGraph・MCP・OpenAI Agents SDK）または LLM の
   直接呼び出しを用いる。
3. 「攻撃者が influence しうるツール出力（source）」と「危険なシンク（sink）」が
   **同一コードベースに共存** する。
4. **正解ラベルを付けられる**（CTF フラグ／ベンチの security test ／文書化された攻撃経路）。
5. 規模・依存が現実的（巨大すぎず、依存が解決可能）。
6. フレームワーク・シンク種別・防御有無の **多様性** を確保する。

---

## 3. 対象コーパス

3 層 + 陰性 + 補助で構成する。各エントリに、リポジトリ・フレームワーク・source/sink の
例・ラベル源・モデル化メモを付す。

### 3.1 第1層 — パイロット（小さく確実な既知陽性）

**ReversecLabs/damn-vulnerable-llm-agent**
`https://github.com/ReversecLabs/damn-vulnerable-llm-agent`

- 概要：LangChain の ReAct エージェントによるサンプル chatbot。WithSecure の
  BSides London 2023 CTF を基にした教育用の脆弱環境。
- source：取引データ等を返すツール（別ユーザの取引が読めてしまう経路が肝）。
- sink：SQL バックエンドへの問い合わせ → **既存の `SQL` 種別にそのまま対応**。
- ラベル源：CTF のフラグ条件（例：別アカウント userId 2 の取引取得）。フラグ＝正解陽性。
- なぜ最初か：小規模・LangChain・既知 TP が複数あり、既存シンクモデルのまま動かせる。
- モデル化メモ：`frameworks.pysa` の LangChain LLM 入口（`BaseChatModel.invoke` 等）が
  そのまま効く。取引取得ツールを `TaintSource[ToolOutput]`、SQL 実行を
  `TaintSink[SQL]` に。

### 3.2 第2層 — 本命のラベル付き大規模スタディ（recall/precision の主測定）

**AgentDojo**（ETH Zurich SpyLab）
`https://agentdojo.spylab.ai/`（`pip install agentdojo`）

- 概要：97 の現実的タスク（メール、e-banking、旅行予約、Slack 等）と 629 の
  セキュリティテストを備えた拡張可能な評価環境。NeurIPS 2024 D&B。
- 脅威：indirect prompt injection。攻撃者がツール出力に紛れ込ませた文章がエージェントに
  不正な関数呼び出しやデータ漏洩をさせる。攻撃者はツール API とシステムプロンプトを
  把握するが、エージェント内部や API 通信は見えない（本ツールの前提と一致）。
- source：未信頼データを返すツール（read_email / read_webpage / read_file /
  get_transactions 等）。
- sink：**アプリ級の危険操作**（send_money / send_email / カレンダ操作 / Slack 投稿等）。
  → OS 級ではないので、これらのツール関数を新しい sink 種別としてモデル化する
  （§5 参照）。
- ラベル源：629 の security test。各テストの (injection endpoint, attacker goal) を
  (source, sink) ペアに写像したものが正解陽性。
- 利点：**防御あり/なしの構成**を選べるため、陽性と陰性を1つのベンチから取得できる。
- 注意：エージェントは任意のツールを呼べるため、静的には source×sink の直積が候補。
  したがって本対象では **pruned/triaged 後の precision・FP が主指標**（RQ2）。

### 3.3 第3層 — MCP 経路・多プロトコル（§4.2 の MCP 配線を踏む）

**opena2a-org/damn-vulnerable-ai-agent**
`https://github.com/opena2a-org/damn-vulnerable-ai-agent`

- 概要：AI エージェント版 DVWA を標榜する、意図的に脆弱なプラットフォーム。
- 特徴：v0.4.0 で MCP の JSON-RPC 2.0 エンドポイントと A2A メッセージ用エンドポイントが
  追加され、3 プロトコル・10 エージェント構成。
- 価値：MCP の `call_tool` / `create_message` 経路（`frameworks.pysa` でモデル済み）を
  実コードで踏める数少ない対象。MCP のツール出力 → ホスト LLM → 危険操作の暗黙的フローを
  測定できる。
- モデル化メモ：`mcp.client.session.ClientSession.call_tool` を source、
  `mcp.server.session.ServerSession.create_message` を LLM ノードとして既存モデルを適用。
  危険操作は各エージェント実装に応じて sink を追加。

### 3.4 陰性（偽陽性測定用）

1. **AgentDojo の防御有効構成** — 本来攻撃が通らない配線で本ツールが沈黙することを
   確認し、FP を測る。`hide()` 相当のガード（データ区切り・ツールフィルタ等）が
   Sanitize として効くかの検証にもなる。
2. **クリーンな公式サンプル** — LangChain の標準テンプレート等で、危険シンクを持たない、
   または参照渡し（hide 相当）でガードしている 1 本。FP=0 の地ならしに使う。

### 3.5 補助 — InjecAgent

`https://github.com/uiuc-kang-lab/InjecAgent`

- 概要：17 のユーザツールと 62 の攻撃者ツールにわたる 1,054 のテストケース。
  単一ターンの模擬シナリオで LLM に1つの敵対的データを直接与える形に焦点。
- 位置づけ：ツールが **仕様（spec）中心で実装コードが薄い**ため、直接の静的解析対象
  よりは「ツール定義・攻撃意図の供給源」として、第1層の脆弱アプリに source/sink を
  増設する材料に向く。脅威タクソノミ（direct harm / data exfiltration）の参照にも使う。

---

## 4. 正解ラベリング手順

### 4.1 ラベル CSV のスキーマ

対象ごとに 1 つの CSV（`labels/<repo>.csv`）を用意する。

| 列 | 意味 |
|----|------|
| `repo` | 対象識別子 |
| `source_tool` | 攻撃者が influence しうる出力を返す関数（完全修飾名） |
| `sink_tool` | 危険な操作の関数/呼び出し（完全修飾名） |
| `sink_category` | `exec` / `sql` / `ssrf` / `fs` / `deser` / `app:money` / `app:email` 等 |
| `label` | `1`=危険配線（陽性）, `0`=安全（陰性） |
| `basis` | 根拠：`ctf-flag` / `agentdojo-test:<id>` / `doc` / `manual` |
| `notes` | 補足（注入点、前提、防御の有無など） |

### 4.2 ベンチ別の導出

- **CTF 系**（damn-vulnerable-*）：フラグ条件・解説に記された攻撃経路を (source, sink) に
  写像し `label=1`。同じ source/sink でも経路として成立しないものは `label=0`。
- **AgentDojo**：各 security test の (injection endpoint, attacker goal) を、コード中の
  (source ツール, sink ツール) に写像。設計上成立する攻撃経路を `label=1`、防御で塞がれた
  もの・あり得ない組合せを `label=0`。`basis=agentdojo-test:<id>` で追跡可能にする。
- **共通原則**：ラベルは **モデル非依存の「経路成立性」** を表す。特定 LLM の ASR は
  ラベル根拠に使わない（再現性・客観性のため）。

### 4.3 ラベラー間一致（任意・推奨）

CTF/AgentDojo の機械的写像で曖昧な箇所は、2 名で独立にラベル付けし Cohen's κ を報告すると
妥当性が増す。最小構成では 1 名でも可（根拠列で追跡可能にしておく）。

---

## 5. 各対象のモデル化（`pysa/frameworks/frameworks.pysa`）

1. **LLM 入口**：`setup_project.py --target <repo>` で実呼び出しを列挙し、`frameworks.pysa`
   の既定（LangChain `invoke/ainvoke/stream/batch`、OpenAI Agents `run/run_sync/run_streamed`、
   MCP `create_message`）でカバーされているか確認。直接 SDK 呼び出しなら該当行のコメントを外す。
2. **source**：`@tool`/`@function_tool` は ModelQuery が総取り。MCP の `call_tool`/
   `read_resource` は既定モデルで source 化。それ以外の未信頼データ取得は明示モデルを追加。
3. **sink（種別の追加）**：AgentDojo のアプリ級操作は新種別が要る。`models/taint.config` に
   例えば `MoneyTransfer` / `EmailSend` 等の sink と、`ToolOutput -> <種別>` の rule
   （新コード 9101…）を追加する。
   OS 級（`subprocess.run`/`os.system` 等）は既存のまま、または Pyre 同梱スタブを利用。
4. **hide()**：参照渡し/秘匿ヘルパを `def <module>.<fn> -> Sanitize: ...` に。

---

## 6. 実行パイプライン（各対象で）

```bash
cd pysa
# 1) 調査と設定生成
python setup_project.py --target /path/to/<repo> --with-bundled-sinks \
    --out /path/to/<repo>/.pyre_configuration
# 2) 対象の依存をインストール（"no module" 解消）
pip install -e /path/to/<repo>     # or its requirements
# 3) frameworks.pysa を §5 に従い調整し、検証
pyre validate-models
# 4) 解析
pyre analyze --no-verify --save-results-to ./pysa-results
# 結果は pysa-results/errors.json (jq で確認)
```

---

## 7. メトリクスの定義

各対象について、(source_tool, sink_tool) ペア集合上で評価する。

- **TP**：ツールが暗黙的フローとして報告し、かつラベル `1` のペア。
- **FP**：報告したがラベル `0`（または陽性集合外）のペア。
- **FN**：ラベル `1` だがツールが報告しなかったペア。
- **precision = TP/(TP+FP)**、**recall = TP/(TP+FN)**、**F1**。
- 段階別に算出：**raw（枝刈り前）→ pruned（§4.5 後）→ triaged（§4.6 後）**。
- **アブレーション**：reachability / schema(channel-capacity) / role / hide を 1 つずつ
  無効化し、各 prune の FP 削減量と（健全性確認のため）TP 喪失の有無を測る。

**読み筋**：CTF 系は recall と precision の双方を、AgentDojo は raw→pruned→triaged の
precision/FP 改善を主に見る（§0 の含意）。陰性対象では FP=0 を目標とする。

---

## 8. 評価ハーネス

評価結果（pysa-results/errors.json）と `labels/<repo>.csv` を `(source_tool, sink_tool)`
で突き合わせて precision/recall/F1・アブレーションを算出する。
`docs/stage4_results.md` に現状の数値を記録している（recall 19/19、AgentDojo 337→161）。

---

## 9. 実施順序とマイルストーン

1. **M1（パイロット）**：damn-vulnerable-llm-agent を clone → `frameworks.pysa` 調整
   （SQL シンクは既存）→ パイプライン疎通 → `labels/dvla.csv` 作成 → 既知フラグを
   TP として検出できることを確認。最小の end-to-end 実証。
2. **M2（本命）**：AgentDojo の 1 スイート（例：banking）で app 級 sink を増設 →
   security test からラベル写像 → raw→pruned→triaged の precision/FP とアブレーションを測定。
   その後、残りのスイートへ拡張。
3. **M3（MCP）**：damn-vulnerable-ai-agent で MCP 経路を測定し、フレームワーク多様性を担保。
4. **M4（陰性）**：AgentDojo 防御構成 + クリーンサンプルで FP を測定。
5. **M5（集計）**：全対象の結果を集計し、RQ1/RQ2/RQ4 の表を作成。

---

## 10. 妥当性への脅威（正直な限界）

- **過近似の性質**：本ツールは「prompt に influence した内容が LLM 経由で応答の任意
  フィールドに載りうる」と保守的に仮定し、LLM の実際の推論（真の制御依存）は解かない。
  事前監査として正しい立場だが、precision は §4.5 枝刈りと §4.6 トリアージに強く依存する。
  この点は結果の解釈で明記する。
- **静的⇄動的の写像誤差**：security test → (source, sink) 写像に解釈の余地があり、
  ラベルにノイズが乗りうる（§4.3 の κ 報告で緩和）。
- **被覆の限界**：モデル化していない LLM 入口・独自ツール・独自 sink は見逃す。
  `setup_project.py` の被覆率（モデル化入口 / 実呼び出し）を必ず併記する。
- **Pysa モデル DSL のバージョン依存**：ModelQuery の述語綴りや stdlib sink 署名は
  バージョンで変わる。各対象で `pyre validate-models` を通し、用いた pyre-check の
  バージョンを記録する。
- **トリアージ LLM の非決定性**：§4.6 を有効化する場合、モデル・温度・プロンプトを固定し、
  triaged 段階の指標は付随情報として扱う（中核の検出・枝刈りは LLM 不要で再現可能）。
- **生成過程の循環性（既存ベンチ）**：自作 `BENCHMARK` は循環。実コーパスの数値のみを
  外部妥当性の根拠として扱い、自作ベンチは機構の単体確認に留める。

---

## 11. 参考文献

- Debenedetti et al., *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection
  Attacks and Defenses for LLM Agents*, NeurIPS 2024 D&B. arXiv:2406.13352.
  Project: https://agentdojo.spylab.ai/
- Zhan et al., *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated
  LLM Agents*, ACL Findings 2024. arXiv:2403.02691.
  Code: https://github.com/uiuc-kang-lab/InjecAgent
- ReversecLabs (WithSecure), *Damn Vulnerable LLM Agent* (LangChain ReAct, BSides
  London 2023 CTF). https://github.com/ReversecLabs/damn-vulnerable-llm-agent
- opena2a-org, *Damn Vulnerable AI Agent* (DVWA-style; MCP + A2A).
  https://github.com/opena2a-org/damn-vulnerable-ai-agent
- CWE-1426: Improper Validation of Generative AI Output.

> 注：上記リポジトリは意図的に脆弱な教育用ターゲット、または学術ベンチである。
> いずれも解析専用であり、実行・公開ネットワークへの曝露は行わない。
