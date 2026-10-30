# CLAUDE.md — 開発運用ルール

本リポジトリ（`mtls_manager`）で Claude / 開発者が守る運用ルール。構成・使い方は `README.md`。

## 1. コミュニケーション

- 対話は日本語で行う。
- コミットメッセージ・PR・コード内コメントは原則日本語（技術用語の英語は可）。
- コミットメッセージに `Claude-Session:` の行（Claude Code のセッションの URL）を付けない（公開リポジトリの履歴にセッションの ID を残さないため）。
- ドキュメントは**日本語と英語の両方**を用意する（`README.md` / `README.en.md`、`docs/ja/` / `docs/en/`）。
  日本語版を正とし、変更するときは両方を同じ内容にそろえる。

## 2. 実装方針

- 実装は **Go**。対象 OS は **Linux（主）と macOS**。
- 依存は増やしすぎない（現状: `go-jose`、`golang.org/x/crypto`、`golang.org/x/net`（パブリックサフィックスの判定のみ）、`bbolt`、`go.yaml.in/yaml/v3`）。
  暗号・JWS・ACME クライアントなどは自前で実装せず、標準ライブラリか実績のあるライブラリを使う。
- 既定値は安全側に倒す（EAB 必須、名前制約、`allowed_domains` 必須、秘密鍵ファイルは 0600 必須など）。
  安全性を下げる変更は、理由を PR に明記する。

## 3. 秘密情報（最重要）

- **鍵・証明書・EAB 鍵・HMAC・実運用の設定値をリポジトリに入れない。**
- 秘密情報は実行時にリポジトリ外のファイルから読む。設定ファイルには秘密情報を書かず、パスで指す。
- テストで使う鍵・証明書はテストの実行時に生成する（固定の鍵ファイルをコミットしない）。
- CI の gitleaks（全履歴の検査）を外さない。

## 4. ブランチ戦略

| ブランチ | 役割 | 直接 push |
| --- | --- | --- |
| `main` | リリース | 不可（PR 経由） |
| `develop` | 開発統合 | 不可（PR 経由） |
| 作業ブランチ（`claude/*`, `feature/*`） | 個別の実装 | 可 |

- 実装は作業ブランチで行い、`develop` 向けに PR を作る。PR は原則 Draft で作る。
- `develop` がまとまったら `develop` → `main` の PR でリリースする。

## 5. レビュー対応

- レビューの依頼（Copilot など）は、実行前にユーザーへ可否を確認する。レビュー → 修正のサイクルを自律的に繰り返さない。
- 指摘を受けたら、内容を精査し、**指摘と対応方針を一覧表にしてユーザーに可否を確認**してから対応する。
- 対応しない指摘は理由を返信する。対応・返信が済んだスレッドは resolve する。

## 6. テスト・CI

- 変更したら `go test -race ./...`、`go vet ./...`、`gofmt -l .` を通す。
- ACME のふるまいを変えたら、lego との相互接続試験（`go test -tags interop ./test/interop/`）も確かめる。
- CI（`.github/workflows/ci.yml`）: 書式、staticcheck、Linux / macOS のテスト、lego との相互接続、クロスビルド、govulncheck、gitleaks。
  PR（develop / main 向けの作成・更新）のときだけ動く。新しい脆弱性は `.github/workflows/weekly.yml` で週 1 回確かめる。

## 7. ドキュメント維持

コードを変えたら、関係する次の文書を更新する（日本語・英語の両方）。

| ファイル | 内容 |
| --- | --- |
| `README.md` / `README.en.md` | 概要 |
| `docs/*/getting-started.md` | 導入手順 |
| `docs/*/configuration.md` | 設定項目（`examples/*.example.yaml` とも合わせる） |
| `docs/*/operations.md` | 運用手順 |
| `docs/*/operations-design.md` | 運用設計（ネットワーク、自動化の範囲、管理画面、監視、障害・事故への対応） |
| `docs/*/test-procedure.md` | 動作テスト手順書（1 台の Linux での環境の準備とテスト）。コマンド・出力・設定項目を変えたら合わせる |
| `docs/*/security.md` | セキュリティ設計（守れること・守れないこと） |
| `docs/*/federation-design.md` | 連携版の設計（別々の mtls-manager の間の信頼）。実装に合わせて更新する |
