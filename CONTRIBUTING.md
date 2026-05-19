# コントリビューションガイド

AI-Scan-Interceptor へのご関心ありがとうございます。バグ報告・機能提案・ドキュメント改善・プルリクエスト、すべて歓迎します。

## 歓迎する貢献

- バグ報告（Issue）
- 機能提案（Issue / Discussions）
- ドキュメントの修正・拡充
- 検出ポリシーのサンプル追加
- 翻訳（英語版ドキュメントの改善）
- 統合事例の Discussions 投稿
- プルリクエスト（バグ修正・小さな改善）

大規模な機能追加・アーキテクチャ変更は、PR を作る前に **Issue または Discussions で先に相談** してください。実装が無駄になるのを防ぐためです。

## 開発環境のセットアップ

```bash
# 必要なもの
# - Go 1.21 以上
# - Docker Engine 24+ / Docker Compose v2
# - make
# - golangci-lint（推奨）

git clone https://github.com/mshirakawa-ssp/ai-scan-interceptor.git
cd ai-scan-interceptor

# CA 証明書を生成（初回のみ）
make certs

# 開発用コンテナ起動
docker compose up -d --build

# 個別コンポーネントの開発
cd tls-proxy && go run .
cd icap-server && go run .
cd webui && go run .
```

## コーディング規約

### Go

- `go fmt` / `gofmt` を必ず実行
- `golangci-lint run` でリンタを通すこと
- 標準ライブラリと公式推奨パターンを優先
- パッケージ単位でテストを書く（`*_test.go`）
- exported な API には godoc コメントを付ける

### 一般

- インデントは Go 標準（タブ）
- 行末空白なし
- ファイル終端に改行
- コミットメッセージは英語または日本語、命令形（"Add", "Fix", "Update"）

## コミットメッセージ規約

```
<type>: <短い要約（50字以内）>

<本文（72字で改行、なぜを書く、whatではなく）>

<関連 Issue: #123>
Signed-off-by: Your Name <your@email.example>
```

`<type>` は次のいずれか：
- `feat`: 新機能
- `fix`: バグ修正
- `docs`: ドキュメントのみ
- `style`: フォーマット・空白等
- `refactor`: 機能変更を伴わないリファクタリング
- `test`: テストの追加・修正
- `chore`: ビルド・依存関係・補助ツール

## DCO（Developer Certificate of Origin）

このプロジェクトは [DCO](https://developercertificate.org/) を採用しています。すべてのコミットに `Signed-off-by:` 行を含めてください：

```bash
git commit -s -m "Your commit message"
```

これにより、あなたが貢献したコードを AGPL v3 でライセンスすることに同意したと見なされます。

## プルリクエストの流れ

1. リポジトリを fork
2. ブランチを作成（`feat/short-description` or `fix/issue-number`）
3. 変更を実装し、テストを追加
4. `go fmt` / `golangci-lint run` / `go test ./...` を通す
5. DCO を含むコミットを作成
6. PR を作成し、テンプレートに沿って記入
7. CI が通ることを確認
8. レビュー対応
9. マージ

## レビュー方針

- 小さな PR を優先（500 行以下推奨）
- ひとつの PR にはひとつの目的
- 影響範囲が大きい変更は先に Issue で議論
- セキュリティに関わる変更は [SECURITY.md](./SECURITY.md) のフローを優先

## ライセンスについて

このプロジェクトのコードは **AGPL v3** で公開されています。コントリビューションをいただいた時点で、あなたのコードも AGPL v3 でライセンスされることに同意したと見なされます。

商用ライセンスでの提供については、メンテナが独自に判断します（contributor の貢献分は AGPL v3 で公開済みのため、商用版に組み込まれることはありません）。

## 行動規範

すべての参加者は [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) に従ってください。

## 質問・相談

- 技術的な質問：GitHub Discussions
- バグ報告：GitHub Issues
- セキュリティ脆弱性：[SECURITY.md](./SECURITY.md)
- ビジネス・商用：sales@secscanpro.com
