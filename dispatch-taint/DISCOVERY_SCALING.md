# Discovery 一般化(bounded)— DISCOVERY_SCALING.md

## 何を変えたか(範囲を限った2つの修正)

前回、外部フレームワーク(MetaGPT/AutoGPT)で tool discovery が失敗した3要因のうち、**①規模**と**②宣言イディオム**を、青天井の書き直しをせずに叩いた変更です。

1. **規模:`_candidate_files` を「盲目的に先頭8件」から「関連度スコアで順位付け→上位を採用」へ。**
   以前は大規模 repo で 8 ファイル×4KB→計12KB という極小スライスを盲目的に切り出していた(AutoGPT が偶発2ツールになった原因)。いまは各ファイルに **tool 関連度スコア**(tool パス、レジストリ名、`@tool/@command/@ability` 等のマーカー密度、`class X(Tool/Action/Agent/...)` の数)を付け、**上位 14 ファイル**を採用＋それらが import するローカルモジュール最大6件。さらにブロブ上限を **6KB/ファイル・計48KB**へ拡大(いずれも bounded)。→ 1000ファイル超の repo でも tool-dense なファイルが budget を生き残る。
2. **イディオム:認識する規約を拡張(ただし衝突は回避)。**
   - 基底クラス:`Action/BaseAction/BaseAgent/Agent/Toolkit/Skill/Ability/...` を追加(MetaGPT/SuperAGI のクラス階層)。
   - デコレータ:**`register_command/register_ability/agent_action` のみ**追加。**汎用の `command`/`ability` は除外**(Click の `@group.command()` と衝突して `config` 等を誤検出するため)。汎用 `@command` は **LLM discovery 側のマーカー/順位付け**で拾う方針に倒した(ヒューリスティック床では主張しない)。
   - **パラメータ付きデコレータ** `@register_tool('name', ...)`(Call ノード)を unwrap して callee 名で判定するよう修正。
   - discovery マーカー/レジストリファイル名に `@command/CommandRegistry/actions.py/abilities.py/skills.py/...` を追加。

## 健全性(over-fire しないこと)

- `config` 誤検出(termwise で Click の `@cli.command()` を拾っていた)を除去。テストで固定(`test_click_command_decorator_is_not_a_false_positive`)。
- 既存 corpus/fixtures は無回帰(全 134 テスト緑、スキップ0)。
- 追加した汎用基底(`Agent/Action` 等)は `_is_tool_class` の内側でのみ効き、クラスが tool パス配下 *または* tool メソッドを持つ場合に限られる(無条件には発火しない)。

## あなたのマシンで再実行(外部フレームワークで discovery が改善したか)

```bash
cd ~/Project/research/Master_Project/cross_audit_tool2
unzip -o ~/Downloads/cross_tool_audit_system.zip
cd cross_tool_audit && pip install -e .   # 既存の editable を更新

# AutoGPT / MetaGPT で再度モデル駆動列挙(tool 復元が増えたか)
ctaudit-toolmodel ./cve_corpus/AutoGPT --src-root ./cve_corpus/AutoGPT --classifier deepseek --emit enum
ctaudit-toolmodel ./cve_corpus/MetaGPT --src-root ./cve_corpus/MetaGPT --classifier deepseek --emit enum
```

比較は前回の結果(AutoGPT=2 tools/偶発、MetaGPT=1 tool)に対して:
- ツール数が増え、**本来のコマンド群(AutoGPT の `execute_shell`/`execute_python` 等)を拾えたか**を見る。
- 拾えれば「discovery を一般化したら実フレームワークでフロー列挙できた」という**実データの強い前進**。
- それでも乏しければ「discovery は flat-registry エージェント(codecli)には一般化するが、クラス/レジストリ型フレームワークの大規模では **LLM 仕様生成(TaintP2X 流)が必要** ── 今後の課題」という**根拠ある限界**になる。

## 正直な期待値

- これは **discovery がどこまで一般化するかの探索**であって、TaintP2X を倒す変更ではない。
- ②(イディオム)は依然 **いたちごっこ**の性質を持つ(衝突を避けつつ規約を足す)。
- path 精密な検出には別途 **手続き間 Pysa レッグ**＋大規模 repo での pyre 稼働が要る(未着手の難所)。
- 論文の主軸は引き続き **#4 動的ディスパッチ解決＋(D) 統制ベンチ＋RQ1**、codecli を実データの in-idiom フロー事例として置く。

## 残課題(③ grounding)

危険操作が executor/sandbox の奥にある場合(MetaGPT/AutoGPT の実 sink)、ツール本体に認識 I/O が無く grounding が role を落とす(③)。これは **ローカル呼び出しを1段たどる**緩和で改善しうるが、precision とのトレードオフがあり、別途計測が必要(本変更には含めていない)。
