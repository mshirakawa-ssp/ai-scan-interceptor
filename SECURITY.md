# セキュリティポリシー

AI-Scan-Interceptor は、セキュリティを目的としたソフトウェアです。脆弱性の責任ある開示を歓迎します。

## サポートしているバージョン

| バージョン | サポート状況 |
|---|---|
| 最新の main ブランチ | ✅ サポート対象 |
| 直近のメジャーリリース | ✅ サポート対象 |
| それより古いリリース | ❌ サポート対象外 |

## 脆弱性の報告先

**公開の Issue では報告しないでください。** 以下のいずれかで連絡してください：

### 推奨：GitHub Security Advisories

[https://github.com/mshirakawa-ssp/ai-scan-interceptor/security/advisories/new](https://github.com/mshirakawa-ssp/ai-scan-interceptor/security/advisories/new)

GitHub の機能でメンテナとのみ私的にやり取りができます。

### 代替：メール

`security@secscanpro.com` 宛にメールしてください。可能であれば GPG で暗号化してください（公開鍵は後日公開予定）。

## 報告に含めてほしい情報

- 影響範囲（どのコンポーネント、どのバージョン）
- 再現手順（できれば最小再現コード）
- 想定される影響（情報漏洩、権限昇格、サービス停止等）
- 報告者の連絡先（Hall of Fame 掲載希望の場合）

## 対応 SLA

| ステップ | 目安 |
|---|---|
| 初回応答 | 報告から 72 時間以内 |
| 影響評価 | 報告から 7 日以内 |
| 修正計画の共有 | 報告から 30 日以内 |
| パッチリリース | Severity に応じて調整（Critical: 14日、High: 30日、Medium: 90日） |
| 公開 Advisory | 修正リリース後、報告者と合意の上で公開 |

これらは目標値であり、複雑な脆弱性ではさらに時間がかかることがあります。透明性をもって状況を共有します。

## 責任ある開示

- 修正パッチがリリースされるまでは、脆弱性の詳細を第三者に開示しないでください。
- 90 日経過しても進展がない場合は、メンテナと相談の上で開示することを検討します。
- 良識ある報告者には Hall of Fame・Acknowledgments ページで謝意を表します（希望者のみ）。

## 報告者への謝意

このプロジェクトは独立した OSS であり、報奨金プログラムは現時点では提供していません。ただし、責任ある開示をいただいた報告者には：

- Hall of Fame（[acknowledgments.md](./docs/acknowledgments.md)）への掲載
- CHANGELOG での credit
- 商用版を採用いただいているお客様への共有（同意の上）

を行います。

## 範囲外

以下は脆弱性として扱いません：

- 公式リリースでない main ブランチでの未完成機能
- 設定ミス（CA 配布設定をしていない、ポリシーを設定していない等）に起因する動作
- DoS（Docker host が落ちる）等の自明な攻撃
- サードパーティライブラリの既知の問題（依存関係の更新で対応）

## 商用版・Enterprise 版のセキュリティ

商用ライセンスをご利用のお客様は、[secscanpro.com](https://www.secscanpro.com) 経由で個別のサポートチャネルをご利用いただけます。

---

このポリシーは [CVD（Coordinated Vulnerability Disclosure）](https://www.first.org/global/sigs/cvd/) のベストプラクティスに沿って運用しています。
