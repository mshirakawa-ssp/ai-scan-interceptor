# AI-Scan-Interceptor 設計ドキュメント

## 1. プロジェクト概要

**AI-Scan-Interceptor** は、企業ネットワーク内のエンドポイントが外部AIサービス（ChatGPT / Claude / Gemini）へ送信するプロンプトをリアルタイムで抽出・監視するプロキシゲートウェイ。情報漏洩対策（DLP）および内部統制を目的とする。

### 前提・スコープ外

| 項目 | 説明 |
|------|------|
| **CA配布必須** | 監視対象エンドポイントに企業CAを事前インストールする。未配布端末はSSL検査の対象外 |
| **HSTS回避なし** | 企業CAを信頼させることでHSTSは正常動作。バイパスは行わない |
| **監視専用** | プロンプトを改ざんしない。DLP/監査目的 |
| **対象ネットワーク** | 管理下の企業ネットワーク内エンドポイントのみ |

---

## 2. アーキテクチャ概要

```
[Endpoint]
    |
    | CONNECT (https, CA配布済み)
    v
[tls-proxy (Go) :3128]          ← 外部公開エントリーポイント
    |
    |── Anthropic/Claude ────────→ Chrome utls MITM → 直接オリジンへ
    |   (api.anthropic.com           (HTTP/1.1 ALPN強制)
    |    a-api.anthropic.com          プロンプト抽出・ログ記録
    |    claude.ai)
    |
    └── その他 (OpenAI/Gemini) ──→ [Squid :3129]  ← 内部のみ
                                        |
                                        | ICAP REQMOD (TCP :1344)
                                        v
                                   [ICAP Server (Go)]
                                        |──→ [PromptDetector]
                                        |──→ [Storage] → /logs/prompts.jsonl
                                        └──→ [Notifier] → Webhook/SMTP
```

### なぜ Anthropic は tls-proxy で直接処理するのか

Anthropic ドメイン（`api.anthropic.com`, `claude.ai` 等）は Cloudflare CDN で保護されている。Squid の SSL Bump が使用する標準 TLS ハンドシェイクでは Cloudflare の JA3/HTTP2 フィンガープリント検査を通過できずアクセスが遮断される。

tls-proxy は [uTLS](https://github.com/refraction-networking/utls) の `HelloChrome_Auto` スペックを使って Chrome のTLSフィンガープリントを再現する。ただし HTTP/2 SETTINGS フレームは Go の `x/net/http2` と Chrome で異なるため、ALPN拡張を `http/1.1` に書き換えて HTTP/2 ネゴシエーションを回避している（JA3 は ALPN の値ではなく型番 16 のみを含むため影響なし）。

### コンテナ構成

```
docker-compose.yml
├── tls-proxy     (Go + utls)          :3128  ← 外部公開
├── squid         (Squid + OpenSSL)    :3129  ← 内部のみ
├── icap-server   (Go ICAP Server)     :1344  ← 内部のみ
└── webui         (Go HTTP UI)         :8080
```

---

## 3. シーケンス図

### 3.1 Anthropic / Claude 系（tls-proxy で完結）

```
Endpoint      tls-proxy            Claude / Anthropic
   |               |                       |
   |--CONNECT----->|                       |
   |<--200 OK------|                       |
   |==TLS(企業CA)==|                       |
   |--POST /v1/...>|                       |
   |               |--utls (Chrome JA3)--->|
   |               |  (HTTP/1.1 ALPN)      |
   |               |   extract prompt      |
   |               |   write /logs/        |
   |               |<----------------------|
   |<--Response----|                       |
```

### 3.2 OpenAI / Gemini 系（Squid → ICAP）

```
Endpoint      tls-proxy    Squid        ICAP Server    AI Service
   |               |          |               |              |
   |--CONNECT----->|          |               |              |
   |               |--CONNECT->|              |              |
   |<--200 OK------|          |               |              |
   |==TLS(企業CA)==>          |               |              |
   |--POST /v1/...>|          |               |              |
   |               |--forward->|              |              |
   |               |          |--ICAP REQMOD->|              |
   |               |          |               |--parse JSON  |
   |               |          |               |--log/alert   |
   |               |          |<--ICAP 204----|              |
   |               |          |--POST /v1/...>|              |
   |               |          |               |         (Response)
   |               |          |<---------------------------- |
   |<--Response----|          |                              |
```

---

## 4. 技術スタック

| コンポーネント | 技術 | バージョン |
|--------------|------|-----------|
| tls-proxy | Go + [uTLS](https://github.com/refraction-networking/utls) | Go 1.21+ / utls v1.6.7 |
| Proxy | Squid (OpenSSL対応ビルド) | 5.x |
| ICAP Server | Go (標準ライブラリのみ) | 1.21+ |
| コンテナ | Docker Compose | v2 |
| ログ形式 | JSONL (JSON Lines) | - |
| 通知 | Webhook (HTTP POST) / SMTP | - |

---

## 5. 対象AIサービスと検出ロジック

### 5.1 ChatGPT / OpenAI（Squid → ICAP 経路）

| 項目 | 値 |
|------|----|
| ホスト | `api.openai.com`, `chatgpt.com` |
| パス | `/v1/chat/completions`, `/backend-api/conversation` |
| 抽出フィールド | `messages[].content`（文字列 or contentオブジェクト） |

```json
// /v1/chat/completions
{"messages": [{"role": "user", "content": "プロンプト本文"}]}

// /backend-api/conversation
{"messages": [{"role": "user", "content": {"content_type": "text", "parts": ["プロンプト本文"]}}]}
```

### 5.2 Claude API / Claude Code（tls-proxy 経路）

| 項目 | 値 |
|------|----|
| ホスト | `api.anthropic.com` |
| パス | `/v1/messages`, `/v1/*` |
| 抽出フィールド | 最後の `user` ロールメッセージのみ抽出 |
| 備考 | 全会話履歴ではなく直近のユーザー入力のみ記録。`<system-reminder>` タグ等の自動注入テキストは除去 |

```json
{"model": "claude-3-...", "messages": [{"role": "user", "content": "プロンプト本文"}], "system": "..."}
```

### 5.3 Claude Web UI（tls-proxy 経路）

| 項目 | 値 |
|------|----|
| ホスト | `claude.ai` |
| パス | `/api/*` |
| 抽出フィールド | `messages[].content[].text` or `prompt` |

### 5.4 Claude Web UI バックエンド（tls-proxy 経路）

| 項目 | 値 |
|------|----|
| ホスト | `a-api.anthropic.com` |
| パス | `/v1/*` |
| 抽出フィールド | `/v1/messages` と同形式 |
| 備考 | claude.ai フロントエンドが内部的に呼び出すエンドポイント |

### 5.5 Gemini（Squid → ICAP 経路）

| 項目 | 値 |
|------|----|
| ホスト | `generativelanguage.googleapis.com`, `gemini.google.com` |
| パス | `/v1beta/models/*/generateContent`, `/v1/models/*/generateContent` |
| 抽出フィールド | `contents[].parts[].text` |
| 備考 | Gemini Web UIは URL エンコード形式 (`f.req=`) をデコードして抽出。ネストが深い場合は `gatherStrings` で全文字列を再帰収集 |

```json
{"contents": [{"parts": [{"text": "プロンプト本文"}], "role": "user"}]}
```

### 5.6 ファイルアップロード DLP

#### multipart/form-data（Claude Desktop / Web ファイル添付）

Claude の `/api/.../files` エンドポイントはファイルを `multipart/form-data` で受け取る。tls-proxy は:

1. ボディ先頭が `--` で始まる場合、multipart として処理
2. テキストパートの内容をクレデンシャルパターンでスキャン
3. ファイル名を FILE-001..008 ルールと照合
4. ヒット時はポリシーに関わらず **ブロック**（maskedボディはサーバーに拒否されるため mask→block 昇格）

#### ファイル名スクリーニング（FILE-001..008）

| ルール | パターン | 対象 |
|--------|---------|------|
| FILE-001 | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` | SSH秘密鍵 |
| FILE-002 | `*.env`, `.env` | 環境変数ファイル |
| FILE-003 | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.p8` | 証明書・鍵ファイル |
| FILE-004 | `credentials`, `credentials.json`, `credentials.csv` | クラウド認証情報 |
| FILE-005 | `service-account.json`, `serviceaccount.json` | GCPサービスアカウント |
| FILE-006 | `*.tfvars` | Terraformシークレット |
| FILE-007 | `secrets.yaml`, `secrets.yml` | Kubernetes Secrets |
| FILE-008 | `kubeconfig`, `*.kubeconfig` | Kubernetes設定 |

#### Gemini Web ファイル添付（FILE-009）

Gemini Web UI はファイルを Google 内部の `contrib_service` CDN に先行アップロードする。StreamGenerate ペイロードには `/contrib_service/ttl_1d/<token>` 形式のURLトークンのみが含まれ、ファイル名・内容ともに不可視。

- ファイル名スクリーニング: **不可**（トークンのみでファイル名なし）
- 内容スキャン: **不可**（クライアントサイドで暗号化）
- 対応: `/contrib_service/` トークンを含む全 StreamGenerate をブロック（FILE-009）

---

## 6. プロンプト抽出の注意点

### 最後のユーザーメッセージのみ記録（Anthropic API）

Anthropic API の各リクエストは会話の全履歴を含む。全メッセージを記録するとログが膨大になり、かつ最新の入力が 4096 文字のトランケートに埋もれるため、**最後の `user` ロールのメッセージのみ**を抽出する。

### system-reminder の除去

Claude Code は毎リクエストの user ターンの先頭に `<system-reminder>...</system-reminder>` ブロックを自動挿入する。これはユーザーが入力したテキストではないため、抽出時に除去する。

---

## 7. ダッシュボード認証・認可

### 7.1 ロール定義

| ロール | 権限 |
|--------|------|
| `admin` | ユーザー管理・ルール編集・ポリシー変更・ログ保持期間設定・レート制限リセット |
| `user` | ルール編集・ポリシー変更のみ（ユーザー管理・システム設定は不可） |
| 未認証 | ダッシュボードへのアクセス不可（ログインページにリダイレクト） |

### 7.2 認証設計

| 項目 | 実装 |
|------|------|
| パスワードハッシュ | bcrypt（DefaultCost）|
| 最小パスワード長 | 12文字 |
| セッション | 32バイト乱数トークン、HttpOnly + SameSite=Strict Cookie |
| セッション TTL | 8時間 |
| セッション保存 | インメモリ（再起動でリセット） |
| ユーザーストア | `/config/users.json`（Docker ボリューム永続化） |

### 7.3 ブルートフォース対策

| 対策 | 設定 |
|------|------|
| IP レート制限 | 5回失敗/15分 でロック（`loginRateLimiter`） |
| アカウントロックアウト | 10回連続失敗で30分ロック（再起動でリセット） |
| ユーザー名列挙対策 | 存在しないユーザーにも bcrypt ダミー比較（タイミング攻撃防止） |
| ログイン失敗レスポンス遅延 | IP レート超過時に 2秒 遅延 |

### 7.4 Break-glass 運用手順

アカウントロックアウト発生時:

```bash
# アカウントロック解除
docker exec ai-scan-interceptor-webui-1 /app/webui unlock-user admin

# パスワードリセット（要コンテナ再起動で反映）
docker exec ai-scan-interceptor-webui-1 /app/webui set-password admin <新パスワード>
docker compose restart webui

# IP レート制限の一括クリア（管理者セッションが有効な場合）
curl -X DELETE http://localhost:8080/api/auth/rate-limits -b "ai_scan_session=<token>"
```

---

## 8. ログ管理

### 8.1 ログ保存仕様

| 項目 | 内容 |
|------|------|
| 形式 | JSONL（1リクエスト1行）|
| ファイル名 | `prompts_YYYYMMDD_HHMMSS.jsonl` |
| ローテーション | 10MB で新ファイル作成（サイズベース） |
| 保持期間 | デフォルト30日（WebUI 管理者設定で変更可能、1〜3650日） |
| 自動削除 | 保持期間を超えたファイルを 6時間ごとに削除 |
| 設定ファイル | `/config/settings.json` |

### 8.2 WebUI 表示制限

| 項目 | 上限 |
|------|------|
| 読み込みファイル数 | 最新 20 ファイル |
| 表示件数 | 500件（フィルター後） |

---

## 9. アラート通知設定

### 9.1 概要

機密情報検知時（ModeWarn）に Slack Webhook および SMTP メールでアラートを送信する。設定は WebUI 管理者画面から変更でき、icap-server・tls-proxy はファイルをホットリロードして即時反映する。

### 9.2 設定ファイル

| 項目 | 内容 |
|------|------|
| パス | `/config/notification.json` |
| 共有方法 | Docker ボリューム経由で webui・icap-server・tls-proxy が共有 |
| ホットリロード | 5秒ポーリング（policy.json と同方式） |
| パスワード保護 | GET API はパスワードを `***` にマスク。PUT で `***` を受け取った場合は既存値を維持 |

```json
{
  "slack_webhook_url": "https://hooks.slack.com/services/...",
  "smtp_host": "smtp.gmail.com",
  "smtp_port": "587",
  "smtp_user": "alert@example.com",
  "smtp_pass": "...",
  "smtp_from": "alert@example.com",
  "alert_email_to": ["admin@example.com"]
}
```

### 9.3 優先順位

ファイル設定 → 環境変数フォールバック（`WEBHOOK_URL`, `SMTP_HOST` 等）の順で評価。ファイルに値があればファイルを優先する。

### 9.4 WebUI エンドポイント

| Method | Path | 権限 | 説明 |
|--------|------|------|------|
| GET | `/api/notification` | admin | 現在の設定取得（パスワードはマスク） |
| PUT | `/api/notification` | admin | 設定を更新・即時保存 |

### 9.5 tls-proxy での通知

従来 ModeWarn は placeholder のみだったが、今回実装。icap-server と同様に `NewDynamicNotifier` を使用して送信する。

---

## 10. セキュリティ要件

| 要件 | 実装 |
|------|------|
| ICAP経路の認証 | 同一Dockerネットワーク内のみ（外部公開しない） |
| ログの個人情報保護 | プロンプトは最大4096文字でトランケート |
| バッファオーバーフロー対策 | チャンクサイズ上限 16MB、本文サイズ上限 32MB |
| インジェクション対策 | JSON抽出はencoding/jsonのみ（eval等不使用） |
| CAキー保護 | `certs/` ディレクトリは .gitignore 対象 |
| ログファイル権限 | 0600（オーナーのみ読み書き） |
| Cloudflare回避 | uTLS Chrome フィンガープリント + HTTP/1.1 ALPN強制 |
| ダッシュボード認証 | bcrypt + HttpOnly Cookie + IP レート制限（7章参照） |

---

## 11. パフォーマンス要件

| 要件 | 設定値 |
|------|-------|
| Squid最大同時接続 | `max_filedescriptors 65536` |
| ICAP接続タイムアウト | `icap_connect_timeout 10 seconds` |
| ICAP I/Oタイムアウト | `icap_io_timeout 60 seconds` |
| tls-proxy upstream接続タイムアウト | 15秒 |
| ログローテーション | 10MB / 最大10ファイル |

---

## 12. 企業CA配布手順（エンドポイント側）

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/squid-ca.pem

# Ubuntu/Debian
sudo cp certs/squid-ca.pem /usr/local/share/ca-certificates/squid-ca.crt
sudo update-ca-certificates

# Windows (管理者PowerShell)
Import-Certificate -FilePath "squid-ca.pem" -CertStoreLocation Cert:\LocalMachine\Root

# Chrome/Firefox: 設定 > 証明書管理 > 認証局 > squid-ca.pem をインポート
```

### Claude Code 向け追加設定

```bash
# 環境変数でプロキシを指定（claude CLI 起動前に設定）
export HTTPS_PROXY=http://<proxy-host>:3128
export HTTP_PROXY=http://<proxy-host>:3128
```

---

## 13. ディレクトリ構成

```
ai-scan-interceptor/
├── docs/
│   └── design_doc.md        # このドキュメント
├── scripts/
│   └── gen-certs.sh         # CA証明書生成スクリプト
├── tls-proxy/               # 外部エントリーポイント（Anthropic/Claude専用MITM）
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go              # utls Chrome フィンガープリント + HTTP/1.1 ALPN
├── squid/
│   ├── Dockerfile
│   └── squid.conf           # OpenAI/Gemini 向け SSL Bump。Anthropic は splice
├── icap-server/
│   ├── Dockerfile
│   ├── go.mod
│   ├── main.go
│   ├── icap/
│   │   ├── server.go        # ICAP TCP サーバー
│   │   └── handler.go       # REQMOD ハンドラー
│   ├── detection/
│   │   ├── detector.go      # 検出オーケストレーター
│   │   ├── patterns.go      # サービス別抽出ロジック
│   │   └── rules.go         # 組み込みアラートルール（regex）
│   ├── notification/
│   │   └── notifier.go      # Webhook / SMTP 通知
│   └── storage/
│       └── logger.go        # JSONLファイルロガー
├── webui/                   # ログビューア UI
│   ├── Dockerfile
│   └── main.go
├── certs/                   # .gitignore対象（CA証明書・秘密鍵）
├── logs/                    # .gitignore対象（プロンプトログ）
├── docker-compose.yml
├── Makefile
└── .gitignore
```
