# 設定リファレンス

[English](../en/configuration.md)

設定ファイルは YAML です。**未知のキーはエラー**になります（綴り間違いを黙って無視しないため）。
期間は `30s` / `10m` / `24h` のような Go の書式に加えて、`7d`（日）・`2y`（365 日単位の年）が使えます。
設定ファイルには秘密情報そのものを書かず、鍵などはファイルのパスで指します。
同梱の `examples/ca.example.yaml` と `examples/agent.example.yaml` がそのまま読めることを、テストで確かめています。

## mtls-ca

| キー | 既定値 | 内容 |
| --- | --- | --- |
| `listen` | `":8443"` | 待ち受けアドレス |
| `external_url` | （必須） | クライアントから見た CA の URL（`https://ホスト[:ポート]`）。ACME の各 URL と、署名付きリクエストの `url` の照合に使う |
| `hostnames` | `external_url` のホスト名 | CA 自身の TLS サーバ証明書に載せる名前。証明書は中間 CA で自動発行し、7 日ごとに作り直す。中間 CA の名前制約の範囲内であること |
| `data_dir` | （必須） | アカウント・注文・発行履歴のデータベース（bbolt）の置き場所。0700 で作る |
| `root_cert` | （必須） | ルート CA の証明書 |
| `intermediate_cert` | （必須） | 中間 CA の証明書 |
| `intermediate_key` | （必須） | 中間 CA の秘密鍵。**0600 でなければ起動しない** |
| `eab_file` | （必須） | EAB 鍵ファイル（`mtlsctl eab` で管理）。**0600 でなければ起動しない**。変更は再起動なしで反映される |
| `allowed_client_cidrs` | `[]`（制限なし） | CA に接続できる送信元（CIDR または IP アドレス）。TCP の接続元で判定し、`X-Forwarded-For` は見ない |
| `policy.allowed_domains` | （必須） | 発行してよいドメイン（そのドメイン自身とサブドメイン）。中間 CA の名前制約の範囲内であること |
| `policy.max_names_per_order` | `10` | 1 枚の証明書に載せられる名前の上限（1〜100） |
| `cert.validity` | `"24h"` | 発行する証明書の有効期間（10m〜90d）。中間 CA の期限で切り詰められる。切り詰めた結果がこの値の半分を下回る場合は発行を拒否する（中間 CA を更新する合図） |
| `challenge.types` | `["http-01", "tls-alpn-01"]` | 受け付ける所有確認の方式（重複はエラー） |
| `challenge.http01_port` | `80` | http-01 で接続するポート |
| `challenge.tlsalpn01_port` | `443` | tls-alpn-01 で接続するポート |
| `challenge.resolver` | （OS の設定） | 所有確認の名前解決に使う DNS サーバ（`"10.0.0.2:53"`） |
| `challenge.timeout` | `"10s"` | 1 回の確認の制限時間 |
| `challenge.attempts` | `3` | 失敗とみなすまでの試行回数（2 秒間隔、1〜10） |
| `crl.validity` | `"24h"` | CRL の有効期間（`NextUpdate`）。有効期間の半分が過ぎるか、失効があると作り直す |
| `log.level` | `"info"` | `debug` / `info` / `warn` / `error` |
| `log.format` | `"text"` | `text` / `json` |
| `admin.listen` | （空 = 無効） | 管理画面の待ち受けアドレス。ACME とは別のポートにし、localhost か管理用のサブネットのアドレスで待ち受ける（例: `"127.0.0.1:9443"`） |
| `admin.allowed_clients` | （`admin.listen` を指定したら必須） | 管理画面に入れる管理者の証明書の名前（パターン）。ログインはこの CA が発行したクライアント証明書による mTLS で、パスワードは使わない。**サーバとは別のサブドメイン**（例: `*.admins.internal.example.com`）にする。一致する名前の証明書は、その名前をワイルドカードを使わずに許可した EAB 鍵でだけ発行される。失効させた証明書では入れない |
| `admin.operators` | `[]`（全員が閲覧のみ） | 管理画面から変更（EAB 鍵の発行・取り消し、証明書の失効）ができる管理者の証明書の名前（パターン）。`admin.allowed_clients` にも含まれている必要がある。指定すると、mtls-ca が `eab_file` を書き換えるため、そのディレクトリに mtls-ca が書き込めないと起動しない（[運用設計ガイド 9-6](operations-design.md#9-6-管理画面からの変更の操作)） |
| `admin.allowed_cidrs` | `[]`（制限なし） | 管理画面に接続できる送信元。localhost 以外で待ち受けるのに空のままだと、起動時に警告する |
| `admin.log_buffer` | `5000` | 管理画面で閲覧できる直近のログの件数（100〜100000）。メモリに保持し、起動以降の分だけ |
| `federation.file` | （空 = 連携版を使わない） | 連携版の連携情報のファイル（`mtlsctl federation` で管理する。秘密情報は含まない）。指定すると、`/federation/bundle` でトラストバンドルを配る。**名前制約の無い中間 CA では起動しない**（自分の範囲を名前制約から得るため）。[連携版の設計](federation-design.md) |
| `federation.bundle_validity` | `"48h"` | トラストバンドルの有効期限（1h〜168h）。「CA が止まっても連携が続く期間」と「停止が届かないときの最悪の期間」を兼ねる |

### エンドポイント

| パス | 内容 |
| --- | --- |
| `/acme/directory` | ACME のディレクトリ（クライアントにはこの URL を設定する） |
| `/crl` | 中間 CA が署名した CRL（DER） |
| `/healthz` | 死活監視用（`ok` を返す） |
| `/federation/bundle` | トラストバンドル（中間 CA の鍵で署名した JWS。`federation.file` を指定したときだけ） |

管理画面（`admin.listen`）は別のポートで、次の画面を表示します。

| パス | 内容 |
| --- | --- |
| `/` | 概要（CA の証明書の期限、件数、警告） |
| `/certs` | 発行済み証明書（`admin.operators` の管理者は失効も） |
| `/eab` | EAB 鍵（`admin.operators` の管理者は発行・取り消しも） |
| `/federation` | 連携（連携版。`admin.operators` の管理者は取り込み・申請・承認・停止・削除も）。`federation.file` を指定したときだけ |
| `/logs` | ログ |

鍵や HMAC などの秘密情報は表示しません（EAB 鍵を発行した直後に、その HMAC 鍵を 1 回だけ表示するのを除く）。使い方は[運用設計ガイド](operations-design.md#9-管理画面)を参照してください。

### 管理用のサブコマンド

データベースを直接開くので、**mtls-ca を止めてから**実行します。

```sh
mtls-ca certs  -config /etc/mtls-ca/config.yaml [-all]               # 発行済みの証明書の一覧（状態: 有効・失効・期限切れ・未完了）
mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <16進> [-reason 1]
```

## mtls-agent

| キー | 既定値 | 内容 |
| --- | --- | --- |
| `ca_url` | （必須） | ACME ディレクトリの URL（`https://.../acme/directory`） |
| `ca_root` | （必須） | ルート CA の証明書。CA への接続と、発行された証明書の検証に使う。ルート CA の入れ替え中は新旧を 1 つのファイルに並べてよい |
| `account_key` | （必須） | ACME アカウントの鍵。無ければ初回に作る（0600）。内部状態をアカウント鍵のファイル名に `.state.json` を付けたファイル（例: `account.key.state.json`。取得した時刻と中間 CA。0600）に置く |
| `eab.kid` | | `mtlsctl eab create` が表示する kid。初回の登録にだけ使う |
| `eab.hmac_file` | | HMAC 鍵のファイル（**0600 必須**）。環境変数 `MTLS_AGENT_EAB_HMAC` でも渡せる。初回の登録後は不要 |
| `names` | （必須） | 証明書に載せる名前（FQDN）。EAB 鍵で許可された名前であること |
| `key_type` | `"ecdsa-p256"` | `ecdsa-p256` / `ecdsa-p384` / `rsa-2048` / `rsa-3072` / `rsa-4096` / `ed25519` |
| `challenge.type` | `"http-01"` | `http-01` / `tls-alpn-01` |
| `challenge.listen` | http-01: `":80"`、tls-alpn-01: `":443"` | 所有確認の間だけ開くアドレス |
| `challenge.webroot` | | 指定すると http-01 で待ち受けず、既存の Web サーバの公開ディレクトリに応答ファイルを置く |
| `output.cert` | （必須） | 証明書（末端のみ）。最後に書かれるので、更新の検知に使える |
| `output.key` | （必須） | 秘密鍵 |
| `output.chain` | | 中間 CA |
| `output.fullchain` | | 証明書 + 中間 CA（アプリにはこれを指定する） |
| `output.ca` | | ルート CA の写し（`ca_root` の内容） |
| `output.key_mode` | `"0600"` | 秘密鍵の権限。`"0600"` または `"0640"`（同じグループのアプリに読ませる） |
| `output.trust_bundle` | | 連携版のトラストバンドル（署名付き）。`mtls` ライブラリの `TrustBundleFile` に指定する。`output.trust_bundle` か `output.federation_dir` を指定すると、CA からトラストバンドルを取得する |
| `output.federation_dir` | | 連携先ごとのルート CA（`<識別子>.pem`）と範囲（`<識別子>.domains`）。nginx などで連携先からの接続を受けるときに使う。停止・期限切れの連携先は「どこにもつながらない PEM」に置き換わる（消えない） |
| `renew.fraction` | `0.66` | 有効期間のこの割合が過ぎたら更新する（0.1〜0.9） |
| `renew.check_interval` | `"1m"` | 状態を確かめる間隔 |
| `renew.timeout` | `"5m"` | 1 回の取得の制限時間 |
| `hooks.post_renew` | | 更新後に実行するコマンド。**シェルを介さず**実行する（例: `["systemctl", "reload", "nginx"]`）。環境変数 `MTLS_AGENT_NAMES` / `MTLS_AGENT_CERT` / `MTLS_AGENT_KEY` / `MTLS_AGENT_FULLCHAIN` が渡される |
| `hooks.timeout` | `"60s"` | 更新後のコマンドの制限時間（`post_renew` / `post_bundle` 共通） |
| `hooks.post_bundle` | | トラストバンドル（連携先）の更新後に実行するコマンド（例: `["/bin/sh", "-c", "nginx -t && systemctl reload nginx"]`）。失敗したら 30 秒〜15 分の指数バックオフで成功するまで再試行し、その間は `check` が終了コード 1 を返す。環境変数 `MTLS_AGENT_TRUST_BUNDLE` / `MTLS_AGENT_FEDERATION_DIR` が渡される |
| `log.level` / `log.format` | `info` / `text` | mtls-ca と同じ |

取得に失敗したときは 30 秒から始めて最大 15 分まで、間隔を倍にしながら再試行します。

### サブコマンド

```sh
mtls-agent run   -config FILE           # 常駐して自動更新する（SIGHUP ですぐ更新）
mtls-agent renew -config FILE [-force]  # 1 回だけ確認し、必要なら更新して終了する
mtls-agent check -config FILE           # 証明書と連携版の状態を表示する（問題があれば終了コード 1）
```

## mtlsctl

```sh
mtlsctl root create -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p384] [-validity 10y]
mtlsctl intermediate csr  -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p256]
mtlsctl intermediate sign -root-cert F -root-key F -csr F -out F -permitted-domain D[,D...] [-validity 2y]
mtlsctl eab create -file F -names P[,P...] [-note TEXT] [-hmac-out F]
mtlsctl eab list   -file F
mtlsctl eab revoke -file F -kid KID
mtlsctl federation export  -config CA設定 [-org ORG] [-contacts ..] [-domains ..] [-out F]
mtlsctl federation import  -config CA設定 -in F -id ID
mtlsctl federation request -config CA設定 -id ID -compared-with TEXT [-fingerprint FP] [-domains ..] [-validity 1y]
mtlsctl federation approve -config CA設定 -id ID [-fingerprint FP]
mtlsctl federation suspend -config CA設定 -id ID [-reason TEXT]
mtlsctl federation remove  -config CA設定 -id ID
mtlsctl federation list    -config CA設定 [-id ID]
mtlsctl federation announce     -config CA設定 -id ID -in F
mtlsctl federation approve-next -config CA設定 -id ID
mtlsctl federation retire-root  -config CA設定 -id ID
mtlsctl federation cancel-next  -config CA設定 -id ID
mtlsctl root announce -old-root-cert F -old-root-key F -new-root-cert F -domains D[,D...] -out F [-switch-at YYYY-MM-DD] [-validity 90d]
mtlsctl inspect FILE
```

鍵のファイルは常に新規作成で、既存のファイルは上書きしません。

### 名前のパターン（`eab create -names`、ライブラリの `AllowedPeers`）

| パターン | 一致する名前 |
| --- | --- |
| `web1.internal.example.com` | 完全一致のみ |
| `*.batch.internal.example.com` | `batch.internal.example.com` の直下 1 ラベル（`a.batch...` は一致、`a.b.batch...` と `batch...` 自身は不一致） |
