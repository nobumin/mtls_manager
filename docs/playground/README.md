# mtls_manager playground（体験用の環境）

[English](README.en.md)

Docker だけで、**プライベートネットワークの 2 台のサーバの間の mTLS** を、導入から削除まで試せる環境です。
証明書の発行・配布・更新は mtls_manager が自動で行い、管理画面でその様子を見られます。

```
                    Docker のプライベートネットワーク（playground.internal）
  ┌────────────────────────────────────────────────────────────────────────────┐
  │                                                                            │
  │   ┌──────────────────┐   証明書の発行（ACME）   ┌──────────────────────┐   │
  │   │ mtls-manager     │ ◀──────────────────────── │ server-a             │   │
  │   │  mtls-ca         │                           │  Go のアプリ         │   │
  │   │  （CA・管理画面）│ ◀──────────┐              │  ＋ mtls-agent       │   │
  │   └────────┬─────────┘            │              └──────────┬───────────┘   │
  │            │ 9443                 │                         │ mTLS ⇅        │
  │            │                      │              ┌──────────┴───────────┐   │
  │            │                      └───────────── │ server-b             │   │
  │            │                                     │  nginx ＋ mtls-agent │   │
  │            │                                     └──────────────────────┘   │
  └────────────┼───────────────────────────────────────────────────────────────┘
               │ 127.0.0.1:9443（PC から見えるのは管理画面だけ）
          あなたの PC のブラウザ
```

| コンテナ | 名前（ネットワークの中） | 動かすもの |
| --- | --- | --- |
| `mtls-manager` | `ca.playground.internal` | `mtls-ca`（ACME: 8443 番、管理画面: 9443 番） |
| `server-a` | `server-a.playground.internal` | Go のアプリ（`mtls` ライブラリ。`GET /hello`、8443 番）＋ `mtls-agent` |
| `server-b` | `server-b.playground.internal` | nginx（`GET /hello`、8443 番）＋ `mtls-agent` |

- server-a は **server-b だけ**、server-b は **server-a だけ**を接続を許可する相手にしています。
- server-a・server-b の 8443 番は PC には公開しません（プライベートネットワークの中だけ）。

> **体験用の構成です。本番では使わないでください。** 手順を短くするため、本番ではオフラインの端末に置くルート CA の鍵も
> `mtls-manager` のコンテナの中で作り、どのコンテナも root で動かし、アプリと mtls-agent を同じコンテナで動かしています。
> 本番の構成は[導入手順](../ja/getting-started.md)と[運用設計ガイド](../ja/operations-design.md)を参照してください。

## 必要なもの

| 項目 | 内容 |
| --- | --- |
| Docker | Docker Desktop（macOS・Windows）または Docker Engine（Linux）。`docker compose`（v2 以降）が使えること |
| シェル | bash（macOS・Linux はそのまま。Windows は WSL2 の中で実行する） |
| ブラウザ | 管理画面を開くのに使う（Chrome・Edge・Firefox・Safari） |
| 空いているポート | PC の `127.0.0.1:9443`（管理画面） |
| ネットワーク | 初回のビルドで、Docker Hub・Debian のパッケージ・Go のモジュールを取得する |

所要時間は、初回のビルドを含めて 10 分ほどです。

## 全体の流れ

以下を、このディレクトリ（`docs/playground/`）で順に実行します。

| 手順 | コマンド | 内容 |
| --- | --- | --- |
| [1. 起動](#1-起動する) | `docker compose up -d --build` | 3 台のコンテナを作って起動する |
| [2. 初期設定](#2-初期設定する) | `./setup.sh` | CA を作り、各サーバに証明書を配る |
| [3. 動作確認](#3-動作を確かめる) | `./check.sh` | server-a ⇔ server-b の mTLS を確かめる |
| [4. 管理画面](#4-管理画面を開く) | ブラウザ | 発行した証明書・EAB 鍵・ログを見る |
| [6. 片付け](#6-片付ける) | `docker compose down -v --rmi local` | 環境をすべて消す |

## 1. 起動する

```bash
git clone https://github.com/nobumin/mtls_manager.git
```

```bash
cd mtls_manager/docs/playground
```

```bash
docker compose up -d --build
```

初回はイメージのビルドに数分かかります。起動したら、状態を確かめます。

```bash
docker compose ps
```

3 台とも `Up` なら成功です。この時点では、まだ CA も証明書もありません（各コンテナは初期設定を待っています）。

```bash
docker compose logs
```

`setup.sh を実行すると、…` と出ていれば、次の手順に進みます。

## 2. 初期設定する

```bash
./setup.sh
```

10 秒ほどで終わり、最後に `初期設定が終わった。` と出ます。`setup.sh` は次のことを行います。

| 段階 | 内容 |
| --- | --- |
| 1/5 | ルート CA と中間 CA を作る。中間 CA には名前制約（`playground.internal`）を付け、その外の名前の証明書は作れないようにする |
| 2/5 | EAB 鍵（サーバごとの発行の許可）を作る。server-a の鍵では `server-a.playground.internal` だけ、というように取得できる名前を 1 つに限る |
| 3/5 | CA（`mtls-ca`）を、管理画面つきで起動する |
| 4/5 | server-a・server-b に mtls-agent の設定を置く。各コンテナの mtls-agent が CA に登録し、所有確認（http-01）を経て証明書を取得し、アプリ（Go のアプリ・nginx）を起動する |
| 5/5 | 管理者の証明書を取得し、ブラウザに読み込むファイルを `out/` に書き出す |

`out/` には、次のファイルができます（リポジトリには含めません）。

| ファイル | 内容 |
| --- | --- |
| `out/admin.p12` | 管理者の証明書と鍵（ブラウザに読み込む。パスワードは `playground`） |
| `out/root.crt` | ルート CA の証明書（ブラウザ・OS に信頼させる） |
| `out/admin.crt` / `out/admin.key` | 管理者の証明書と鍵（curl で管理画面を開くとき用） |

各サーバの様子は、ログで見られます。

```bash
docker compose logs server-a server-b
```

`CA にアカウントを登録した` → `証明書を更新した` → `証明書ができた。アプリを起動する` と出ています。

## 3. 動作を確かめる

```bash
./check.sh
```

次の 6 項目を確かめ、最後に `6 件すべて合格` と出れば成功です。

| 確かめること | 期待する結果 |
| --- | --- |
| server-a → server-b（nginx） | `hello from server-b (nginx), client=CN=server-a.playground.internal` |
| server-b → server-a（Go） | `hello, [server-b.playground.internal]` |
| 証明書なし → server-b | nginx が `400`（クライアント証明書が無い） |
| 証明書なし → server-a | TLS の握手で拒否される |
| 管理者の証明書 → server-b | nginx が `403`（同じ CA の正しい証明書でも、許可した相手ではない） |
| 管理者の証明書 → server-a | TLS の握手で拒否される（同上） |

curl で 1 つずつ試すこともできます。server-a から server-b を呼び出すには、次のようにします。

```bash
docker compose exec server-a curl --cacert /etc/mtls-agent/tls/ca.pem --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem https://server-b.playground.internal:8443/hello
```

server-b から server-a を呼び出すには、次のようにします。

```bash
docker compose exec server-b curl --cacert /etc/mtls-agent/tls/ca.pem --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem https://server-a.playground.internal:8443/hello
```

証明書（`--cert` / `--key`）を外すと、どちらも拒否されることを確かめられます。

## 4. 管理画面を開く

管理画面のログインは、パスワードではなく**この CA が発行したクライアント証明書（mTLS）**で行います。
ブラウザで開くには、次の 3 つを一度だけ行います。

### 4-1. hosts に名前を加える

CA 自身のサーバ証明書の名前は `ca.playground.internal` なので、その名前で `127.0.0.1` に届くようにします。

macOS・Linux の場合:

```bash
echo "127.0.0.1 ca.playground.internal" | sudo tee -a /etc/hosts
```

Windows の場合は、メモ帳を管理者として実行し、`C:\Windows\System32\drivers\etc\hosts` の末尾に `127.0.0.1 ca.playground.internal` を加えます。

### 4-2. 管理者の証明書とルート CA をブラウザに読み込む

`out/admin.p12`（パスワード `playground`）と `out/root.crt` を読み込みます。

| 環境 | `out/admin.p12`（管理者の証明書） | `out/root.crt`（ルート CA） |
| --- | --- | --- |
| macOS（Chrome・Safari・Edge） | ダブルクリックしてキーチェーンアクセスの「ログイン」に追加する | ダブルクリックして追加し、キーチェーンアクセスで開いて「信頼」→「常に信頼」にする |
| Windows（Chrome・Edge） | ダブルクリックし、証明書のインポート ウィザードで「現在のユーザー」→「個人」に入れる | ダブルクリック →「証明書のインストール」→「現在のユーザー」→「信頼されたルート証明機関」に入れる |
| Firefox（全 OS） | 設定 →「プライバシーとセキュリティ」→「証明書を表示」→「あなたの証明書」→「インポート」 | 同じ画面の「認証局証明書」→「インポート」→「この認証局によるウェブサイトの識別を信頼する」 |
| Linux（Chrome） | 設定 →「プライバシーとセキュリティ」→「セキュリティ」→「証明書の管理」→「自分の証明書」→「インポート」 | 同じ画面の「認証局」→「インポート」 |

> ルート CA を信頼させたくない場合は、`out/root.crt` の読み込みを省き、ブラウザの警告画面から進んでも構いません
> （管理者の証明書の読み込みは必要です）。

### 4-3. 開く

ブラウザで次を開きます。

```
https://ca.playground.internal:9443/
```

証明書の選択を求められたら、`admin.admins.playground.internal` を選びます。次の画面を見られます。

| 画面 | 見られること |
| --- | --- |
| 概要 | 有効な証明書・EAB 鍵・アカウントの数、ルート CA と中間 CA の有効期限と名前制約、CA の設定 |
| 発行済み証明書 | server-a・server-b・管理者の証明書（シリアル・有効期限）。ここから失効もできる |
| EAB 鍵 | サーバごとの発行の許可（取得できる名前）。ここから発行・取り消しもできる |
| ログ | CA のログ（発行・所有確認・管理画面の操作） |

ブラウザを使わずに確かめる場合は、curl でも開けます（4-1 の hosts は必要）。

```bash
curl --cacert out/root.crt --cert out/admin.crt --key out/admin.key https://ca.playground.internal:9443/
```

## 5. もう少し試す

### 証明書の更新

証明書の有効期間は 24 時間で、mtls-agent が残り 1/3 になると自動で更新します。すぐに更新するには、次のコマンドを使います。

```bash
docker compose exec server-b mtls-agent renew -force -config /etc/mtls-agent/config.yaml
```

`証明書を更新した` → `更新後のコマンドを実行した`（nginx の reload）と出ます。状態を確かめるには、次のコマンドを使います。

```bash
docker compose exec server-b mtls-agent check -config /etc/mtls-agent/config.yaml
```

シリアルが変わり、管理画面の「発行済み証明書」にも新しい証明書が並びます。server-a（Go のアプリ）は、再起動しなくても新しい証明書を使います（`mtls` ライブラリが 30 秒ごとにファイルを確かめる）。

### 再起動しても続くこと

```bash
docker compose restart
```

CA・証明書・設定は Docker のボリュームに残るので、再起動の後もそのまま動きます。もう一度 `./check.sh` で確かめられます。

### サーバの取り消し

管理画面の「EAB 鍵」で server-b の鍵を取り消すと、server-b は以後新しい証明書を取得できなくなります（上の `renew -force` が拒否される）。
「発行済み証明書」で失効させることもできます。

> mtls_manager は、短い有効期間で被害の時間を限る設計です。失効させた証明書でも、Go のアプリと nginx は有効期限まで接続を受け付けます
> （[運用ガイド](../ja/operations.md#証明書を失効させる)）。取り消しのあとに試すときは、6. の片付けからやり直してください。

## 6. 片付ける

コンテナ・ボリューム（CA・鍵・証明書）・ビルドしたイメージをすべて消します。

```bash
docker compose down -v --rmi local
```

書き出したファイルも消します。

```bash
rm -f out/admin.p12 out/admin.crt out/admin.key out/root.crt
```

4. で行ったことも元に戻します。

- hosts から `127.0.0.1 ca.playground.internal` の行を消す
- ブラウザ・OS から、管理者の証明書（`admin.admins.playground.internal`）と、ルート CA（`Playground Root CA`）を消す
  （**ルート CA を信頼させたままにしない**でください）

もう一度試すときは、[1. 起動](#1-起動する)からやり直します。

## うまくいかないとき

| 症状 | 対処 |
| --- | --- |
| `./setup.sh` が `… が動いていない` で止まる | `docker compose up -d --build` を先に実行する。`docker compose ps` で 3 台が `Up` か確かめる |
| `./setup.sh` が `すでに設定済み` で止まる | 初期設定は 1 回だけ。やり直すときは `docker compose down -v` の後、`docker compose up -d --build` と `./setup.sh` を実行する |
| `./setup.sh` が `… を待ったが、… 秒たっても終わらない` で止まる | `docker compose logs mtls-manager server-a server-b` でエラーを確かめる |
| `docker compose up` が `port is already allocated` で失敗する | PC の 9443 番を使っているものを止めるか、`compose.yaml` の `127.0.0.1:9443:9443` の左側を別の番号にする（ブラウザで開く番号も変わる） |
| ブラウザで開くと証明書の選択が出ない・`ERR_BAD_SSL_CLIENT_AUTH_CERT` | `out/admin.p12` を読み込んだか確かめ、ブラウザを再起動する |
| ブラウザで `ca.playground.internal` が見つからない | 4-1 の hosts を確かめる |
| 環境を作り直した後、管理画面に入れない（証明書のエラー） | 作り直すとルート CA も新しくなる。ブラウザ・OS から古い管理者の証明書とルート CA を消し、新しい `out/admin.p12` と `out/root.crt` を読み込み直す |
| `./setup.sh` が `Permission denied` | `chmod +x setup.sh check.sh` を実行する |
