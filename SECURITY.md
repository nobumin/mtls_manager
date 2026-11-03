# セキュリティポリシー / Security Policy

## 脆弱性の報告（日本語）

mtls_manager は認証の基盤になるソフトウェアです。脆弱性を見つけた場合は、**公開の Issue には書かず**、
GitHub の非公開の脆弱性報告（リポジトリの **Security** タブ → **Report a vulnerability**）から報告してください。

報告には、可能な範囲で次の内容を含めてください。

- 影響を受けるバージョン（コミット）と構成
- 再現の手順
- 想定される影響

受け付けたことを、できるだけ早く返信します。修正の公開までは、内容を公開しないようお願いします。

### 対象のバージョン

v0.x の間は、最新のリリース（または `main` ブランチ）のみを修正の対象とします。

### 注意

本ソフトウェアは無保証です（[LICENSE](LICENSE)）。本番環境で広く使う前に、利用者の責任で
セキュリティレビューを行うことを推奨します。設計上守れること・守れないことは
[docs/ja/security.md](docs/ja/security.md) にまとめています。

---

## Reporting a vulnerability (English)

mtls_manager is authentication infrastructure. If you find a vulnerability, **do not open a public issue**.
Please use GitHub's private vulnerability reporting (the repository's **Security** tab → **Report a vulnerability**).

Where possible, include:

- the affected version (commit) and configuration
- steps to reproduce
- the expected impact

We will acknowledge your report as soon as possible. Please keep the details private until a fix is released.

### Supported versions

While in v0.x, only the latest release (or the `main` branch) receives fixes.

### Note

This software is provided without warranty ([LICENSE](LICENSE)). We recommend an independent security review before
broad production use. What the design does and does not protect against is described in
[docs/en/security.md](docs/en/security.md).
