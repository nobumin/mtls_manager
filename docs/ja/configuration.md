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

### エンドポイント

| パス | 内容 |
| --- | --- |
| `/acme/directory` | ACME のディレクトリ（クライアントにはこの URL を設定する） |
| `/crl` | 中間 CA が署名した CRL（DER） |
| `/healthz` | 死活監視用（`ok` を返す） |

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
| `renew.fraction` | `0.66` | 有効期間のこの割合が過ぎたら更新する（0.1〜0.9） |
| `renew.check_interval` | `"1m"` | 状態を確かめる間隔 |
| `renew.timeout` | `"5m"` | 1 回の取得の制限時間 |
| `hooks.post_renew` | | 更新後に実行するコマンド。**シェルを介さず**実行する（例: `["systemctl", "reload", "nginx"]`）。環境変数 `MTLS_AGENT_NAMES` / `MTLS_AGENT_CERT` / `MTLS_AGENT_KEY` / `MTLS_AGENT_FULLCHAIN` が渡される |
| `hooks.timeout` | `"60s"` | 更新後のコマンドの制限時間 |
| `log.level` / `log.format` | `info` / `text` | mtls-ca と同じ |

取得に失敗したときは 30 秒から始めて最大 15 分まで、間隔を倍にしながら再試行します。

### サブコマンド

```sh
mtls-agent run   -config FILE           # 常駐して自動更新する（SIGHUP ですぐ更新）
mtls-agent renew -config FILE [-force]  # 1 回だけ確認し、必要なら更新して終了する
mtls-agent check -config FILE           # 状態を表示する（更新が必要なら終了コード 1）
```

## mtlsctl

```sh
mtlsctl root create -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p384] [-validity 10y]
mtlsctl intermediate csr  -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p256]
mtlsctl intermediate sign -root-cert F -root-key F -csr F -out F -permitted-domain D[,D...] [-validity 2y]
mtlsctl eab create -file F -names P[,P...] [-note TEXT] [-hmac-out F]
mtlsctl eab list   -file F
mtlsctl eab revoke -file F -kid KID
mtlsctl inspect FILE
```

鍵のファイルは常に新規作成で、既存のファイルは上書きしません。

### 名前のパターン（`eab create -names`、ライブラリの `AllowedPeers`）

| パターン | 一致する名前 |
| --- | --- |
| `web1.internal.example.com` | 完全一致のみ |
| `*.batch.internal.example.com` | `batch.internal.example.com` の直下 1 ラベル（`a.batch...` は一致、`a.b.batch...` と `batch...` 自身は不一致） |
