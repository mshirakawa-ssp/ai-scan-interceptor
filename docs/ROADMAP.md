# AI-Scan-Interceptor ロードマップ

最終更新: 2026-04-27  
Month 1 完了コミット: e849331  
Month 2 完了  
Month 3 完了（ダッシュボード認証・ログ保持期間・UI改善）  
Month 4 進行中

---

## ステータス凡例
- ✅ 完了
- 🚧 進行中
- ⬜ 未着手
- ❌ ブロック中

---

## 基盤フェーズ（完了）

| # | 機能 | ステータス |
|---|------|----------|
| B-1 | tls-proxy 実装（Chrome utls フィンガープリント） | ✅ |
| B-2 | PKCS8 CA 鍵対応 | ✅ |
| B-3 | HTTP/2 → HTTP/1.1 ALPN 強制（Cloudflare 回避） | ✅ |
| B-4 | Claude Code / Desktop / Web 全検知 | ✅ |
| B-5 | Squid SSL Bump を AI サービスのみに限定（Slack 等への影響排除） | ✅ |
| B-6 | GitHub Copilot / Azure OpenAI 対応 | ✅ |

---

## Month 1: 制御機能 + 対応サービス拡充

### M1-1 ポリシーエンジン（ブロック・マスク・モード切替）

| # | タスク | ステータス | 担当 |
|---|--------|----------|------|
| 1-1 | `policy` パッケージ作成（Mode 型・Config・ホットリロード） | ✅ | Software Engineer |
| 1-2 | `policy.MaskBody` 関数（キーワードの [REDACTED] 置換） | ✅ | Software Engineer |
| 1-3 | ICAP ハンドラーにポリシー適用（block/mask/monitor/warn） | ✅ | Software Engineer |
| 1-4 | ICAP WriteBlock（RFC 3507 準拠の 403 deny レスポンス） | ✅ | Software Engineer |
| 1-5 | ICAP WriteMasked（修正リクエスト返却） | ✅ | Software Engineer |
| 1-6 | tls-proxy にポリシー適用（block/mask） | ✅ | Software Engineer |
| 1-7 | WebUI `/api/policy` GET/PUT エンドポイント | ✅ | Software Engineer |
| 1-8 | ダッシュボードに設定パネル追加（モード切替 UI） | ✅ | Software Engineer |
| 1-9 | docker-compose に config ボリューム追加 | ✅ | Software Engineer |

### M1-2 対応サービス拡充

| # | タスク | ステータス | 担当 |
|---|--------|----------|------|
| 2-1 | GitHub Copilot 検出（`api.githubcopilot.com`） | ✅ | Software Engineer |
| 2-2 | Azure OpenAI 検出（`*.openai.azure.com`） | ✅ | Software Engineer |
| 2-3 | findRule にワイルドカードホスト対応追加 | ✅ | Software Engineer |
| 2-4 | Squid ACL に GitHub Copilot / Azure OpenAI 追加 | ✅ | Software Engineer |

### M1-3 品質保証

| # | タスク | ステータス | 担当 |
|---|--------|----------|------|
| 3-1 | policy パッケージのユニットテスト | ✅ | Tester |
| 3-2 | ICAP WriteBlock / WriteMasked のテスト | ✅ | Tester |
| 3-3 | 新サービス（Copilot / Azure OpenAI）の検出テスト | ✅ | Tester |
| 3-4 | セキュリティレビュー（ブロックバイパス・インジェクション確認） | ✅ | Security Engineer |

---

## Month 2: エンタープライズ基盤

| # | タスク | ステータス | 担当 |
|---|--------|----------|------|
| 4-1 | プロキシ認証（Basic auth）によるユーザー同定 | ✅ | Software Engineer |
| 4-2 | JWT ヘッダーから sub クレームを抽出してログに追記 | ✅ | Software Engineer |
| 4-3 | カスタムルール管理 UI（ダッシュボードから追加・削除） | ✅ | Software Engineer |
| 4-4 | Splunk / Elasticsearch エクスポート（非同期） | ✅ | Software Engineer |
| 4-5 | レスポンス監視（ICAP RESPMOD） | ✅ | Software Engineer |

---

## Month 2.5: ファイルアップロード DLP（完了）

| # | タスク | ステータス | コミット |
|---|--------|----------|---------|
| F-1 | multipart/form-data ファイル内容スキャン（Claude Desktop/Web） | ✅ | b4c11a7 |
| F-2 | Claude API document ブロック（inline text source）検出 | ✅ | b4c11a7 |
| F-3 | ファイルアップロード: mask→block 昇格（tls-proxy + ICAP） | ✅ | b4c11a7 |
| F-4 | ファイル名スクリーニング（FILE-001..008）: id_rsa / .env / *.pem / credentials 等 | ✅ | b4c11a7 |
| F-5 | Gemini opaque attachment 検出 (FILE-009) — /contrib_service/ トークン検出 | ✅ | b4c11a7 |
| F-6 | Gemini ネストペイロード全文字列収集（gatherStrings） | ✅ | b4c11a7 |
| F-7 | JSON文字列内マスク（maskJSONStrings）、Gemini URL-encoded マスク | ✅ | b4c11a7 |

**既知の制限**
- Gemini Web ファイルアップロード: ファイル本体は Google CDN（contrib_service）経由で暗号化転送されるため内容スキャン不可。ファイル名も StreamGenerate ペイロードに含まれない。ファイル添付を含む全リクエストを FILE-009 でブロック。
- ChatGPT Web ファイルアップロード: 未実装（別途対応予定）

---

## Month 3: 運用品質 + コンプライアンス

| # | タスク | ステータス |
|---|--------|----------|
| 5-1 | ダッシュボード認証（admin / user 2ロール、ブルートフォース対策付き） | ✅ |
| 5-2 | Helm チャート / Kubernetes マニフェスト | ⬜ |
| 5-3 | ログ保持期間 WebUI 設定（管理者専用、自動削除 6h ごと） | ✅ |
| 5-4 | 初回接続時の監視通知（同意フロー） | ⬜ |
| 5-5 | 監査ログ改ざん検知（ハッシュチェーン） | ⬜ |
| 5-6 | 法的レビュー対応（GDPR / 労働法） | ⬜ |

### Month 3 完了詳細

| 機能 | 内容 |
|------|------|
| **認証・認可** | bcrypt + HttpOnly Cookie セッション管理（8h TTL）、admin/user 2ロール |
| **ブルートフォース対策** | IP レート制限（5回/15分）＋ アカウントロックアウト（10回/30分） |
| **Break-glass CLI** | `docker exec webui /app/webui unlock-user <name>` でロック解除 |
| **パスワードリセット CLI** | `docker exec webui /app/webui set-password <name> <pass>` |
| **ユーザー管理 UI** | 管理者によるユーザー追加・削除・ロック解除（WebUI） |
| **ログ保持期間設定** | デフォルト30日、1〜3650日で設定可能、6時間ごと自動削除 |
| **ブランドカラー刷新** | パープル系 → Security Scan Pro ロイヤルブルー系に統一 |
| **フィルター自動保存・リセット** | localStorage 永続化 ＋ ↺ リセットボタン |

### 技術メモ（Month 3）

**RESPMOD（AIレスポンス検査）の延期判断**  
Gemini のみ動作・日本語文字化けあり・実装コスト大のため正式に Phase 4 以降へ延期。  
リクエスト側（REQMOD）で機密情報をブロックすれば、レスポンス側に機密情報が返ることはないため、運用上のリスクは最小。

---

---

## Month 4: 通知・運用改善

| # | タスク | ステータス |
|---|--------|----------|
| 6-1 | アラート通知設定 WebUI（Slack Webhook / SMTP、管理者専用） | ✅ |
| 6-2 | tls-proxy ModeWarn 通知実装（従来 placeholder） | ✅ |
| 6-3 | notification.json ホットリロード（5秒ポーリング） | ✅ |

### Month 4 完了詳細

| 機能 | 内容 |
|------|------|
| **通知設定 WebUI** | ダッシュボード設定モーダルに Slack/SMTP 設定フォームを追加（admin 専用） |
| **ファイルバック設定** | `/config/notification.json` に永続化、webui・icap-server・tls-proxy が共有 |
| **パスワード保護** | GET は `***` マスク返却。PUT で `***` を受け取ると既存パスワードを維持 |
| **優先順位** | ファイル設定 → 環境変数フォールバック（`WEBHOOK_URL`, `SMTP_*`）の順で評価 |
| **tls-proxy 通知** | ModeWarn 時に icap-server と同様の通知を送信（実装完了） |

---

## アーキテクチャメモ（Tech Lead）

### ポリシーシステム設計
- `icap-server/policy/config.go`: Mode 型 + Config struct + 5秒ポーリングリロード
- `icap-server/policy/mask.go`: MaskBody（正規表現ベースキーワード置換）
- 設定ファイル: `/config/policy.json`（共有 Docker ボリューム）
- 両 icap-server・tls-proxy から `ai-scan-interceptor/policy` としてインポート

### ICAP ブロックレスポンス（RFC 3507）
```
ICAP/1.0 200 OK
Encapsulated: res-hdr=0, res-body=N
[HTTP 403 response headers]
[chunked HTTP 403 body]
```

### ワイルドカードホスト対応
- `*.openai.azure.com` → `strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])`
- Squid: `dstdomain .openai.azure.com` （先頭ドットがワイルドカード）
