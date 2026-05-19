# AI-Scan-Connect

エンドポイント常駐の軽量エージェント。CA配布・環境変数設定・ローカル mTLS 転送プロキシ・自動更新を担う。

本ディレクトリは **Phase 1 + Phase 2 序盤** (Linux 完動、Win/Mac/WSL は本体実装済み・実機検証は Phase 2) です。設計は `../docs/PLAN_CONNECT_MTLS.md` を参照。

## ビルド

```bash
# host build
make

# unit tests
make test

# クロスコンパイル
make linux
make windows
make darwin
make all      # 全部
```

`go build ./...` も通ります（`make` は `dist/` 配下に置きたい場合のみ使用）。

## サブコマンド

```
ai-scan-connect install     # CA投入 + env var追記 + 鍵生成 + enroll
ai-scan-connect forward     # ローカル転送プロキシ常駐 (フォアグラウンド)
ai-scan-connect monitor     # 60秒毎の整合性チェック
ai-scan-connect enroll      # 単独 enroll (再エンロール)
ai-scan-connect uninstall   # rcからマーカーブロック削除 + システムCA削除
ai-scan-connect status      # 診断スナップショット
ai-scan-connect version
```

## 設定ファイル

- Unix: `/etc/ai-scan-connect/config.json`
- Windows: `%PROGRAMDATA%\AIScanConnect\config.json`

最小例:

```json
{
  "interceptor_url": "https://acme.cloud.secscanpro.com",
  "enroll_url":      "https://acme.cloud.secscanpro.com:3131/enroll",
  "org_ca_pem":      "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "enrollment_token": "<one-time>",
  "local_listen":    "127.0.0.1:8443",
  "fail_close":      false,
  "org":             "acme"
}
```

`--config <path>` で別パスを指定可能。

## 状態ファイル

- `/var/lib/ai-scan-connect/client.key`  (RSA 2048, 0600)
- `/var/lib/ai-scan-connect/cert.pem`    (mTLS クライアント証明書, 0600)
- `/etc/ssl/certs/aiscan.pem`            (組織CA バンドル — `NODE_EXTRA_CA_CERTS` 等が指す)
- `/var/log/ai-scan-connect.log`         (Phase 2 で structured log 移行予定)

## rc ファイル管理ブロック

`install` は対象ユーザの `~/.bashrc` `~/.zshrc` `~/.profile` に以下のブロックを追記する（既存があれば剥がして書き直す＝冪等）:

```sh
# >>> ai-scan-connect managed block (DO NOT EDIT) v1 >>>
# generated: 2026-05-09T...
export HTTPS_PROXY='http://127.0.0.1:8443'
export https_proxy='http://127.0.0.1:8443'
export HTTP_PROXY='http://127.0.0.1:8443'
export http_proxy='http://127.0.0.1:8443'
export NODE_EXTRA_CA_CERTS='/etc/ssl/certs/aiscan.pem'
export REQUESTS_CA_BUNDLE='/etc/ssl/certs/aiscan.pem'
export SSL_CERT_FILE='/etc/ssl/certs/aiscan.pem'
# <<< ai-scan-connect managed block <<<
```

`sudo` 経由起動時は `SUDO_USER` を尊重し、root の rc ではなく実ユーザの rc を更新します。

## ディレクトリ構成

```
connect/
├── main.go                       # サブコマンド ディスパッチ
├── go.mod
├── Makefile
├── cmd/
│   ├── install.go    forward.go  monitor.go
│   ├── enroll.go     uninstall.go status.go
├── config/config.go               # /etc/ai-scan-connect/config.json
├── certstore/
│   ├── certstore.go               # 共通インターフェース
│   ├── linux.go                   # update-ca-certificates / update-ca-trust
│   ├── darwin.go                  # security add-trusted-cert + System.keychain
│   ├── darwin_helpers.go          # 引数組立 (build-tag なし、CIテスト可能)
│   ├── windows.go                 # certutil -addstore Root + 冪等性 (SHA-1 thumbprint)
│   ├── windows_helpers.go         # PEM/SHA-1/argv ヘルパ (build-tag なし)
│   ├── wsl.go                     # wsl.exe enumerate + per-distro install
│   ├── wsl_helpers.go             # UTF-16LE デコード, distro 分類, install script ビルダ
│   └── tempfile.go                # 共通 temp PEM 書き込み
├── envvars/
│   ├── envvars.go                 # 共通インターフェース
│   ├── markers.go                 # マーカー定数 (build-tag なし、Win→WSL でも共有)
│   ├── unix.go                    # rc編集 + マーカーブロック
│   ├── unix_test.go
│   ├── windows.go                 # HKLM/HKCU Environment + WinINet/WinHTTP + WM_SETTINGCHANGE
│   └── windows_helpers.go         # stripURLScheme 等 (build-tag なし)
├── proxy/
│   ├── forwarder.go               # 127.0.0.1:8443 -> mTLS to Interceptor
│   └── forwarder_test.go
├── enroll/
│   ├── enroll.go                  # 鍵生成 + CSR + /enroll POST
│   └── enroll_test.go
└── monitor/monitor.go              # 60s ヘルスチェック + 自動復旧
```

## OS別の動作概要

| プラットフォーム | CA 投入 | env var | プロキシ |
|--|--|--|--|
| Linux | `update-ca-certificates` / `update-ca-trust` 経由 | `~/.bashrc` `~/.zshrc` `~/.profile` にマーカーブロック | rc 経由 |
| macOS | `security add-trusted-cert -k System.keychain` | rc 経由 (envvars/unix) | rc 経由 (`networksetup` 統合は Phase 3) |
| Windows | `certutil -addstore -f Root <pem>` (SHA-1 thumbprint で冪等) | `HKLM\…\Session Manager\Environment` + `WM_SETTINGCHANGE` ブロードキャスト | WinINet (`HKCU\…\Internet Settings\ProxyServer`) + WinHTTP (`netsh winhttp set proxy`) |
| WSL (Win→各 distro) | `wsl.exe -d <distro> -u root` で in-distro スクリプト実行 (`debian` / `rhel` family のみ、それ以外は warn skip) | `/etc/profile.d/aiscan.sh` + UID≥1000 の各ユーザの rc | rc 経由 |

## Phase 2/3 残TODO

- 実機検証: 主要 AI クライアント (Claude Code/Cursor/ChatGPT.app/Claude.app/Copilot) の `HTTPS_PROXY` 挙動
- 自動 cert renewal (有効期限 50% で再エンロールするバックグラウンドタスク)
- MSI (WiX) / macOS PKG (notarization) / deb / rpm パッケージング
- WSL2 で host 127.0.0.1 が解決できないケース (host gateway IP に切替)
- macOS `networksetup -setwebproxy / -setsecurewebproxy` 統合 (Phase 3)
- 自己アップデート除外 (MDM 配布前提)
- 構造化ログ (`/var/log/ai-scan-connect.log` への JSON Lines)
- 各 OS 実機での Install/Uninstall 通し検証 (現状は引数組立て + UTF-16LE デコード + script ビルダのユニットテストのみ)

## 開発ルール

- 標準ライブラリ最優先、外部依存は `golang.org/x/sys` のみ (Windows registry / WM_SETTINGCHANGE 用)
- OS別実装は build tag (`//go:build linux` 等) で分離
- マーカーブロックは絶対に剥がしてから書き直す（重複追記禁止）
- `install` は root が必要だが、warning のみで継続して env-var-only モードで動く（CI 等で都合がよい）
