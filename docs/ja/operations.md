# 運用ガイド

[English](../en/operations.md)

## サーバを追加する

1. CA サーバで EAB 鍵を作る。

   ```sh
   sudo mtlsctl eab create -file /etc/mtls-ca/eab.json -names web2.internal.example.com -note "web2" -hmac-out ./web2.hmac
   ```

2. `root.crt` と `web2.hmac` を web2 に運び、[導入手順の 5.](getting-started.md#5-各サーバで-mtls-agent-を起動する) のとおり mtls-agent を起動する。

CA の再起動は不要です（EAB 鍵ファイルの変更は自動で反映されます）。

管理画面で `admin.operators` を設定していれば、「EAB 鍵」の画面からも発行できます（HMAC 鍵は発行直後に 1 回だけ表示。[運用設計ガイド 9-6](operations-design.md#9-6-管理画面からの変更の操作)）。

## サーバを取り消す（廃棄・乗っ取りの疑い）

```sh
sudo mtlsctl eab list   -file /etc/mtls-ca/eab.json
sudo mtlsctl eab revoke -file /etc/mtls-ca/eab.json -kid <kid>
```

その EAB 鍵で登録したアカウントは、以後**新しい証明書を取得できません**。
発行済みの証明書は有効期限（既定 24 時間）まで使えます。すぐに使えなくするには、続けて失効させます。
管理画面（`admin.operators`）の「EAB 鍵」の画面からも取り消せます。

## 証明書を失効させる

```sh
sudo systemctl stop mtls-ca
sudo -u mtls-ca mtls-ca certs  -config /etc/mtls-ca/config.yaml
sudo -u mtls-ca mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <シリアル> -reason 1
sudo systemctl start mtls-ca
```

失効は CRL（`https://ca.internal.example.com:8443/crl`）に反映されます。

管理画面（`admin.operators`）の「発行済み証明書」の画面からは、**CA を止めずに**失効させられます。

`certs` で状態が「未完了」のものは、署名の前に記録したまま、発行を完了できなかったシリアルです（CA の停止やディスクの障害で起き得ます）。
クライアントには返していないので外に出ている可能性は低いですが、念のため失効させることもできます。

> **注意**: v0.x の `mtls` ライブラリと `mtls-agent` は CRL を確かめません。失効の効果があるのは、CRL を読むように
> 設定したソフト（nginx の `ssl_crl` など）だけです。mtls_manager は、**有効期間を短くする**（既定 24 時間）ことで、
> 失効に頼らずに済む設計にしています。急ぎの場合は、相手側のアプリの許可リスト（`AllowedPeers`）から外すことも検討してください。

サーバ自身が、ACME の失効要求（`lego revoke` など）で自分の証明書を失効させることもできます。

## 証明書の名前を変える

EAB 鍵に許可された名前の範囲内なら、mtls-agent の設定の `names` を変えて `systemctl restart mtls-agent` するだけです
（設定は起動時に読むので、`reload` では反映されません。起動すると名前の違いを検知してすぐに取得し直します）。
範囲外の名前にする場合は、新しい EAB 鍵を作り、mtls-agent の `account_key` を削除してから、新しい `eab.kid` / `eab.hmac_file` で起動し直します。

## 中間 CA を更新する（有効期限の前）

中間 CA の既定の有効期間は 2 年です。mtls-ca は残り 30 日を切ると、起動時と 1 日ごとに警告を出します。
残りが証明書の有効期間（`cert.validity`）の半分を切ると、短い証明書を出さずに**発行を拒否**します
（全サーバが短い証明書を取り直し続けるのを防ぐため）。それまでに更新してください。
ルート CA が同じなので、**各サーバ側の作業は不要**です。

1. CA サーバで、新しい鍵と CSR を別のディレクトリに作る。

   ```sh
   sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca/2028
   sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca/2028 -cn "Example mTLS CA 2028"
   sudo chown mtls-ca:mtls-ca /etc/mtls-ca/2028/intermediate.key
   ```

2. オフラインの端末で署名する（[導入手順の 3-2.](getting-started.md#3-2-オフラインの端末-署名する)）。
3. 証明書を `/etc/mtls-ca/2028/` に置き、`config.yaml` の `intermediate_cert` / `intermediate_key` を書き換えて、`sudo systemctl restart mtls-ca`。

古い中間 CA で発行した証明書は有効期限まで使え、各サーバは次の更新で新しい中間 CA の証明書に切り替わります。

## ルート CA を入れ替える

ルート CA の鍵が漏れた疑いがある場合や、有効期限が近い場合に行います。全サーバに手を入れる作業です。

1. オフラインの端末で新しいルート CA を作る。
2. **新旧のルート CA を 1 つのファイルに並べたもの**を、全サーバの mtls-agent の `ca_root` に配る
   （mtls-agent は `output.ca` にも新旧の両方を書き出すので、アプリも両方を信頼するようになる）。
3. 新しいルート CA で中間 CA を作り、CA サーバを切り替える。
4. 全サーバの証明書が新しいルート CA のものに更新されたら（既定なら 1 日後）、各サーバの `ca_root` から古いルート CA を外す。

## 別の組織と連携する（連携版）

A 社のサーバと B 社のサーバのように、**別々の mtls-ca（別々のルート CA）で管理するサーバ間**を mTLS でつなぎます。
互いのルート CA を、**相手の範囲（ドメイン）の名前に限って**信頼します。設計の詳細は [連携版の設計](federation-design.md) を参照してください。

前提:

- A と B は別のドメインを使う（例: A は `a.example.com`、B は `b.example.net`）
- 各組織の中間 CA に名前制約がある（`mtlsctl intermediate sign -permitted-domain`）。名前制約の無い中間 CA では連携版を使えない

### 1. CA で連携版を有効にする（両方の組織）

`config.yaml` に次を加えて、mtls-ca を再起動します。

```yaml
federation:
  file: "/etc/mtls-ca/federation.json"
```

管理画面（`admin.operators`）から連携先を管理する場合は、mtls-ca が `federation.file` を書き換えるので、EAB 鍵ファイルと同じく
mtls-ca が書き込めるディレクトリ（同梱の systemd ユニットなら `/var/lib/mtls-ca/federation.json`）に置きます（書き込めないと起動しない）。

### 2. 連携情報を交換する（両方の組織）

```sh
sudo mtlsctl federation export -config /etc/mtls-ca/config.yaml -org "A 社" -contacts security@a.example.com -out a.json
```

`a.json` を相手に渡します（秘密情報は含まないので、メールでかまいません）。相手からは `b.json` を受け取り、取り込みます。

```sh
sudo mtlsctl federation import -config /etc/mtls-ca/config.yaml -in b.json -id b-corp
```

`-id` は自分の側で付ける識別子です（英小文字・数字・ハイフン。ファイル名に使う）。

### 3. 指紋を照合し、2 人で承認する

1. 表示された指紋の**全体（64 桁）**を、**ファイルとは無関係に前もって知っている相手の連絡先**（契約書の窓口など）と、
   電話・対面など**ファイルとは別の経路**で読み合わせる。ファイルに書かれた連絡先は相手の申告（未検証）なので使わない
2. 1 人目の管理者が申請する（指紋は読み上げを聞いて入力する）。

   ```sh
   sudo mtlsctl federation request -config /etc/mtls-ca/config.yaml -id b-corp \
     -compared-with "契約書記載の B 社 情報システム部 △△ 氏、電話" -by alice
   ```

   範囲を狭めるには `-domains api.b.example.net` を付けます（相手の申告より広くはできない）。
3. **別の**管理者が承認する（指紋をもう一度入力する）。

   ```sh
   sudo mtlsctl federation approve -config /etc/mtls-ca/config.yaml -id b-corp -by bob
   ```

相手の組織も、同じ手順で A を承認します（**双方が承認して初めて**通信できる）。
`mtlsctl federation list -config ... [-id b-corp]` で状態と操作の記録を確認できます。

**管理画面の「連携」画面でも、同じ操作（取り込み・申請・承認・停止・削除、自分の連携情報の書き出し）ができます。こちらを推奨します。**
管理画面では、操作した管理者の名前をログインに使った証明書（mTLS）で確かめるので、申請者と承認者が本当に別の人であることを保証できます。
指紋の入力欄は貼り付けできず、読み上げを聞いて入力します。
**承認は申請と同じ経路で行います**（画面で申請したものは画面で、CLI で申請したものは CLI で）。画面と CLI では名前の付け方（証明書の名前と自己申告の名前）が違い、混ぜると 1 人で 2 人の承認を通せてしまうためです。

> CLI では、`-by` の名前は自己申告です（2 人の承認は「別の名前」であることだけを確かめる）。CLI で申請・承認した連携先は、
> 管理画面で「CLI（自己申告）を含む」と表示されます。CA サーバにログインできる人を限り、操作の記録（`federation list -id`）を定期的に確かめてください。

### 4. 各サーバの mtls-agent で連携先を受け取る

mtls-agent の設定に、出力先と（nginx などを使う場合は）更新後のコマンドを加えて再起動します。

```yaml
output:
  trust_bundle: "/etc/mtls-agent/tls/trust-bundle.jws"   # mtls ライブラリ用
  federation_dir: "/etc/mtls-agent/federation"           # nginx など用（<識別子>.pem / <識別子>.domains）
hooks:
  post_bundle: ["/bin/sh", "-c", "nginx -t && systemctl reload nginx"]
```

mtls-agent は既定 1 分ごとに CA からトラストバンドルを取得し、署名と内容を確かめて書き出します。

### 5. アプリで連携先を受け入れる

- **Go（`mtls` ライブラリ）**: `TrustBundleFile` を加え、`AllowedPeers` に相手のサーバの名前を加えます。`CertFile` には fullchain を指定します。

  ```go
  cfg, err := mtls.NewServerTLSConfig(mtls.Config{
      CertFile: "/etc/mtls-agent/tls/fullchain.pem", KeyFile: "/etc/mtls-agent/tls/key.pem",
      CAFile: "/etc/mtls-agent/tls/ca.pem", TrustBundleFile: "/etc/mtls-agent/tls/trust-bundle.jws",
      AllowedPeers: []string{"app1.a.example.com", "web1.b.example.net"},
  })
  ```

  - 連携先の相手は、必ず `AllowedPeers` に名前を書きます（`AllowAnyPeer` は自分の組織の相手にだけ効く）。
  - クライアント側は、**ホスト名（DNS 名）で接続**します。IP アドレスでの接続はホスト名を確かめられないので拒否されます（`tls.Config.ServerName` を指定すれば接続できる）。

- **nginx など**: 範囲を確かめられないので、**連携先からの接続を受けるポートを分け**、そのポートでは
  `federation_dir/<識別子>.pem`（その連携先のルート CA だけ）を信頼し、相手の名前を**完全一致**で許可します（ワイルドカードを書かない）。
  導入時と停止の後に、`nginx -t` が通ること、reload 後に連携先からの接続が拒否されることを確かめます。

### 6. 連携を停止する

```sh
sudo mtlsctl federation suspend -config /etc/mtls-ca/config.yaml -id b-corp -reason "侵害の疑い" -by carol
```

停止は 1 人で即時にできます。各サーバには既定 1 分以内に届き、`federation_dir` の PEM は「どこにもつながらない PEM」に置き換わります。
**CA と各サーバの通信が妨げられている場合、最悪はトラストバンドルの有効期限（既定 2 日）まで信頼が残ります**。
急ぐ場合は、各アプリの `AllowedPeers`（nginx は許可リスト）からも相手の名前を外してください。
再開は、照合と 2 人の承認（手順 3）をやり直します。不要になったら `mtlsctl federation remove` で消します。消すと操作の記録もファイルから消えるので、先に `mtlsctl federation list -config ... -id <識別子>` で記録を控えてください（監査ログには要約が残ります）。

### 監視

`mtls-agent check` は、トラストバンドルの期限切れ・期限が 1 日を切った・更新後のコマンドが失敗し続けている場合に、終了コード 1 を返します。
連携の有効期限（既定 1 年）が 30 日を切ると、mtls-ca のログに警告が出ます。期限までに照合と承認をやり直してください。

## バックアップ

| 対象 | 場所 | 内容 |
| --- | --- | --- |
| ルート CA の鍵 | オフラインの端末 | 暗号化した媒体に 2 部。CA サーバとは別の場所に保管する |
| 中間 CA の鍵・証明書 | `/etc/mtls-ca/` | 失うと中間 CA を作り直すことになる（各サーバ側の作業は不要） |
| EAB 鍵ファイル | `/etc/mtls-ca/eab.json` | 失うと全サーバの EAB 鍵を発行し直すことになる |
| 連携情報のファイル（連携版） | `/etc/mtls-ca/federation.json` | 連携先と承認の記録。失うと照合と承認をやり直すことになる（秘密情報は含まない） |
| データベース | `/var/lib/mtls-ca/` | アカウントと発行履歴。mtls-ca を止めてからコピーする。失うと各サーバの再登録が必要 |

バックアップには秘密鍵が含まれます。暗号化し、アクセスできる人を限ってください。

## 監視

- 管理画面（`admin.listen`）を有効にすると、CA の証明書の期限・更新の遅れ・直近のログをブラウザで確認できます
  （[運用設計ガイド](operations-design.md#9-管理画面)）。
- `mtls-agent check -config ...` は、更新が必要なとき（期限切れ・更新の遅れ・名前の不一致など）に**終了コード 1** を返します。
  監視システムから定期的に実行してください。
- `https://ca.internal.example.com:8443/healthz` で CA の死活を確かめられます。
- ログの主なメッセージ:

  | メッセージ | 意味 |
  | --- | --- |
  | `証明書を発行`（mtls-ca） | 発行の記録（シリアル・名前・EAB 鍵） |
  | `所有確認に失敗`（mtls-ca） | 所有確認が通らなかった（ポート・名前解決・ファイアウォールを確認） |
  | `許可されていない送信元からの接続を拒否`（mtls-ca） | `allowed_client_cidrs` 以外からの接続 |
  | `証明書を取得できない（再試行する）`（mtls-agent） | 取得の失敗。理由がログに続く |
  | `更新後のコマンドが失敗した`（mtls-agent） | 証明書は更新済み。`hooks.post_renew` の設定を確認 |
  | `取得した直後なのに更新が必要と判断された`（mtls-agent） | 設定か CA の状態に問題がある。取得を繰り返さず、間を置いて確かめ直している。理由がログに続く |
  | `中間 CA の有効期限が近い`（mtls-ca） | 中間 CA を更新する（[手順](#中間-ca-を更新する有効期限の前)） |

## トラブルシューティング

| 症状 | 確認すること |
| --- | --- |
| mtls-ca が「権限が緩すぎる」で起動しない | `intermediate.key` / `eab.json` を `chmod 600` し、所有者を mtls-ca にする |
| mtls-ca が「データベースを開けない」 | 別の mtls-ca が動いていないか（`certs` / `revoke` は CA を止めてから実行する） |
| mtls-agent が「EAB 鍵が無効」 | kid の書き間違い、または `mtlsctl eab revoke` で取り消されている |
| 「このアカウント（EAB 鍵）には許可されていない」 | `names` が EAB 鍵の `-names` に含まれていない |
| 「この CA で発行できるドメインの範囲外」 | `policy.allowed_domains` と中間 CA の名前制約を確認 |
| 所有確認で `connection` エラー | CA サーバ → 対象サーバの 80 番（または 443 番）が通るか、CA サーバで名前解決できるか |
| 所有確認で `incorrectResponse` | 80 番で別の Web サーバが応答していないか（その場合は `challenge.webroot` を使う） |
| 「80 を開けない」 | mtls-agent に `CAP_NET_BIND_SERVICE` があるか（同梱の systemd ユニットでは付与済み）、ポートを他のプロセスが使っていないか |
| CA に接続できない（`x509: certificate signed by unknown authority`） | `ca_root` が正しいルート CA か。`ca_url` のホスト名が `hostnames` に含まれているか |
| HTTPS_PROXY がある環境で CA に届かない | mtls-agent は環境変数のプロキシを使わない。lego など他のクライアントは `NO_PROXY` に CA のホスト名を加える |
