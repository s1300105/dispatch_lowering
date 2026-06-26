# TaintP2X との CVE 比較 (CVE_COMPARISON.md)

## 目的と正直なスコープ

TaintP2X (ICSE'26) は 35 件の P2Xi 脆弱性を **フローレベル**でラベル付けした正解を持つ。ただしその多くは **単発 prompt → LLM → sink**(チェーン/クエリ/Text-to-SQL がモデル出力を exec)であり、**ctaudit の射程外**である。ctaudit が狙うのは別レジーム――**多ツール・エージェント**で、上流ツールの出力がモデルの判断を経由して下流 sink に影響する(cross-tool 暗黙フロー)、特にモデル出力が **どのツールを呼ぶかを選ぶ動的ディスパッチ**(TaintP2X が *限界* と明記した部分)。

そこで本比較は **「多ツール・エージェント/動的ディスパッチ」サブセットに限定**し、単発ケースは「射程外」と明示して **主張しない**。これは「35 件で TaintP2X に勝つ」という主張ではなく、**「ctaudit が狙うレジーム、かつ TaintP2X が苦手とする領域で、フローを検出できる(彼らが取りこぼしたものを含む)」**という相補的価値の主張である。

> **事前登録(honesty)**:`benchmark/cve_cases.py` の `scope`/`in_scope` は **コード確認前の仮説**。ランナーは経験的で、ctaudit が実際に検出したものを報告する。最終的な論文主張は、(a) 脆弱バージョンでの実行結果と (b) メカニズムを確認するコード精査の **後** に確定する。

## サブセット(射程内)

| CVE | repo | 種別 | scope(仮説) | TaintP2X | baseline |
|---|---|---|---|---|---|
| **CVE-2024-1881** | Significant-Gravitas/AutoGPT | code exec | dynamic_dispatch | **N(取りこぼし)** | LLMSmith N, AgentFuzz Y |
| CVE-2024-23750 | geekan/MetaGPT | code exec | cross_tool | Y | LLMSmith N |
| CVE-2025-2733 | FoundationAgents/OpenManus | code exec | dynamic_dispatch | Y | LLMSmith N, AgentFuzz N |
| HUNTR (Superagi) | TransformerOptimus/SuperAGI | file write | cross_tool | Y | AgentFuzz N |
| CVE-2024-5927 | stitionai/devika | file write | cross_tool | Y | AgentFuzz N |
| CVE-2024-5821 | stitionai/devika | file write | cross_tool | Y | AgentFuzz N |
| CVE-2024-6331 | stitionai/devika | file write | cross_tool | Y | AgentFuzz N |

**目玉**:`CVE-2024-1881`(AutoGPT)は TaintP2X が **取りこぼした**。AutoGPT はコマンドレジストリから名前でディスパッチする ―― ctaudit の fusion #4 がまさに対象とする形。これを検出できれば「彼らの限界をこちらが埋める」直接証拠になる。

射程外(単発、`benchmark/cve_cases.py` の `OUT_OF_SCOPE` に透明性のため列挙、**実行しない**):langchain の PAL/LLMMath exec 系、PandasAI、vanna、llama_index のクエリ/SQL、litellm、langchain SSRF など。

## 取得と実行(あなたのマシンで)

実 repo の取得と DeepSeek が必要なので、サンドボックスではなく手元で実行する。

```bash
# 1) 射程内 repo を clone(タグ/コミットは要確認、スクリプト内の NOTE 参照)
bash scripts/fetch_cve_corpus.sh ./cve_corpus

# 2) 各 checkout を確認し、必要なら benchmark/cve_cases.py の repo/ref/src_rel を調整
#    (例:AutoGPT のパッケージが autogpts/autogpt/ 配下なら src_rel を設定)

# 3) 比較を実行
python -m benchmark.cve_bench --corpus ./cve_corpus                  # ヒューリスティック・ツールモデル
python -m benchmark.cve_bench --corpus ./cve_corpus --classifier deepseek   # LLM ツールモデル(推奨)
```

実 repo ではツールイディオムが多様なので、**`--classifier deepseek` を推奨**(ヒューリスティックは取りこぼしうる)。`ANTHROPIC`/`OpenAI` 互換キーは環境変数で渡す既存の仕組みに従う。

## 出力の読み方

各行は `CVE | repo | category | scope | ctaudit | TaintP2X`。

- `ctaudit` 列:`DETECTED`(該当カテゴリのフローを検出)/ `DETECT(G)`(検出したがガード付き)/ `DISPATCH?`(制御テイント付きの未解決ディスパッチ壁=弱い陽性、要精査)/ `missed`。
- `[flows=N walls=M]`:その repo で報告したフロー数と未解決ディスパッチ壁数。
- 末尾2行:**射程内 present に対する recall** と、**{射程内 ∩ TaintP2X 取りこぼし(N)} に対する検出数**(相補的価値の主張)。

判定は「CVE の sink カテゴリ(code_execution/file_write/sql/network)に一致するフローを ctaudit が報告したか」。より厳密にやるなら、報告フローの sink 名が CVE の実シンクに一致するかを手で確認する。

## 妥当性への脅威(論文に明記)

- **バージョンドリフト**:タグ/コミットが脆弱版と一致しているか要確認(スクリプトの NOTE)。
- **手ラベルの粒度**:検出判定をカテゴリ一致で自動化している。最終的には sink 名レベルで人手確認する。
- **部分集合**:エコシステムの無作為標本ではなく、ctaudit のレジームに合致するケースを選んでいる(その旨を明示=cherry-pick 回避)。
- **ツールモデル依存**:検出は構築したツールモデルに依存する(RQ1 が別途その品質を測る)。`--classifier deepseek` 使用時は LLM 非決定性のため複数回実行して安定性を確認する。
- **scope は仮説**:`dynamic_dispatch` などの分類はコード精査で確定する。

## 検証済み(ハーネスのロジック)

実 repo 取得前に、同梱フィクスチャをスタンドインにしてランナーのロジックを検証済み(`tests/test_cve_bench.py`, 5 件):直接 sink の検出、gold モデル下でのディスパッチ検出、カテゴリ不一致の非検出、ガード付き検出、安全フィクスチャの非検出。`main()` の表示(present/absent/recall/相補的価値行)も確認済み。実 repo での結果は手元実行で得る。
