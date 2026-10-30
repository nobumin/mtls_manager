# 導入手順

[English](../en/getting-started.md)

CA を構築し、2 台のサーバ間で mTLS の接続ができるところまでを説明します。
例として、社内のドメインを `internal.example.com`、CA サーバを `ca.internal.example.com`、
証明書を受け取るサーバを `web1.internal.example.com` とします。実際の環境に読み替えてください。

## 0. 準備するもの

| 項目 | 内容 |
| --- | --- |
| オフラインの端末 | ルート CA の鍵を作って保管する。ネットワークにつながない PC が望ましい（最低でも CA サーバとは別の端末） |
| CA サーバ | `mtls-ca` を動かす Linux サーバ（macOS も可） |
| 各サーバ | 証明書を受け取るサーバ。社内 DNS で FQDN を引けること |
| 通信 | 各サーバ → CA サーバの 8443 番（ACME）。CA サーバ → 各サーバの 80 番（http-01）または 443 番（tls-alpn-01） |
| Go | 1.26 以降（バイナリをビルドする端末だけでよい） |

CA サーバからも各サーバの FQDN を名前解決できる必要があります（所有確認で接続するため）。

## 1. バイナリを用意する

```sh
go install github.com/nobumin/mtls_manager/cmd/...@latest
# $(go env GOPATH)/bin に mtlsctl / mtls-ca / mtls-agent ができる
```

ビルドした端末と OS・CPU が異なるサーバ向けには、クロスビルドしてから運びます。

```sh
git clone https://github.com/nobumin/mtls_manager && cd mtls_manager
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/ ./cmd/...
```

各サーバでは `/usr/local/bin/` に置きます。

## 2. ルート CA を作る（オフラインの端末）

```sh
mtlsctl root create -out-dir ./offline -cn "Example Internal Root CA" -org "Example"
```

| ファイル | 扱い |
| --- | --- |
| `offline/root.key` | **ルート CA の秘密鍵。CA サーバにもどこにも置かない。** 暗号化した USB メモリなどに 2 部保管する |
| `offline/root.crt` | ルート CA の証明書（公開してよい）。CA サーバと各サーバに配る |

既定では、鍵は ECDSA P-384、有効期間は 10 年です（`-key-type` / `-validity` で変えられます）。

## 3. 中間 CA を作る

中間 CA の鍵は CA サーバで作り、CA サーバの外へ出しません。署名だけをオフラインの端末で行います。

### 3-1. CA サーバ: 利用者とディレクトリを用意し、鍵と CSR を作る

```sh
sudo useradd --system --home /var/lib/mtls-ca --shell /usr/sbin/nologin mtls-ca
sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca
sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca -cn "Example mTLS CA 2026"
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/intermediate.key
```

`/etc/mtls-ca/intermediate.csr`（公開してよいファイル）をオフラインの端末へ運びます。

### 3-2. オフラインの端末: 署名する

```sh
mtlsctl intermediate sign \
  -root-cert offline/root.crt -root-key offline/root.key \
  -csr intermediate.csr -out intermediate.crt \
  -permitted-domain internal.example.com
```

`-permitted-domain` は**名前制約**です。この中間 CA は `internal.example.com` とそのサブドメインの証明書しか発行できません。
中間 CA の鍵が漏れた場合の被害を限定するので、必ず指定してください（複数指定可。既定の有効期間は 2 年）。

### 3-3. CA サーバ: 証明書を置く

`intermediate.crt` と `root.crt` を CA サーバへ運びます。

```sh
sudo install -m 0644 intermediate.crt root.crt /etc/mtls-ca/
```

## 4. CA サーバを起動する

### 4-1. 設定ファイル

```sh
sudo install -m 0640 -o root -g mtls-ca examples/ca.example.yaml /etc/mtls-ca/config.yaml
sudo vi /etc/mtls-ca/config.yaml
```

最低限、次の項目を環境に合わせます（各項目は[設定リファレンス](configuration.md)）。

```yaml
external_url: "https://ca.internal.example.com:8443"
allowed_client_cidrs: ["10.0.0.0/8"]          # CA に接続できる送信元
policy:
  allowed_domains: ["internal.example.com"]   # 発行してよいドメイン
```

### 4-2. 最初のサーバの EAB 鍵を作る

CA は EAB 鍵ファイルが無いと起動しないので、最初のサーバの鍵を先に作ります。

```sh
sudo mtlsctl eab create -file /etc/mtls-ca/eab.json \
  -names web1.internal.example.com -note "web1（Web サーバ）" -hmac-out ./web1.hmac
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/eab.json   # 初回だけ。以後の更新では所有者が引き継がれる
```

表示された `kid` と、`web1.hmac`（**秘密情報**）を控えます。`-names` に指定した名前以外の証明書は、この鍵では発行できません。
複数のサーバ（例: バッチ用のサーバ群）で 1 つの鍵を使う場合は `-names '*.batch.internal.example.com'` のように書けます。

### 4-3. 起動する（systemd）

```sh
sudo install -m 0644 deploy/systemd/mtls-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-ca
journalctl -u mtls-ca -f
```

「mtls-ca を起動した」と出れば成功です。443 番など 1024 未満のポートで待ち受ける場合は、
ユニットファイルの `AmbientCapabilities=CAP_NET_BIND_SERVICE` を有効にします。

ファイルの配置と権限は次のとおりです。

| パス | 所有者 | 権限 |
| --- | --- | --- |
| `/etc/mtls-ca/config.yaml` | root:mtls-ca | 0640 |
| `/etc/mtls-ca/intermediate.key` | mtls-ca | 0600（緩いと起動しない） |
| `/etc/mtls-ca/eab.json` | mtls-ca | 0600（緩いと起動しない） |
| `/etc/mtls-ca/intermediate.crt`, `root.crt` | root | 0644 |
| `/var/lib/mtls-ca/`（データベース） | mtls-ca | 0700 |

## 5. 各サーバで mtls-agent を起動する

### 5-1. ルート CA の証明書と EAB 鍵を配る

`root.crt` と `web1.hmac` を、安全な経路（scp など）で web1 に運びます。

```sh
sudo useradd --system --home /var/lib/mtls-agent --shell /usr/sbin/nologin mtls-agent
sudo install -d -m 0755 /etc/mtls-agent
sudo install -d -m 0755 -o mtls-agent -g mtls-agent /etc/mtls-agent/tls
sudo install -m 0644 root.crt /etc/mtls-agent/root.crt
sudo install -m 0600 -o mtls-agent -g mtls-agent web1.hmac /etc/mtls-agent/eab.hmac
rm web1.hmac
```

### 5-2. 設定ファイル

```sh
sudo install -m 0644 examples/agent.example.yaml /etc/mtls-agent/config.yaml
sudo vi /etc/mtls-agent/config.yaml
```

```yaml
ca_url: "https://ca.internal.example.com:8443/acme/directory"
eab:
  kid: "（4-2 で表示された kid）"
  hmac_file: "/etc/mtls-agent/eab.hmac"
names: ["web1.internal.example.com"]
challenge:
  type: "http-01"
  listen: ":80"
```

80 番をすでに Web サーバが使っている場合は、`challenge.webroot` にその公開ディレクトリを指定します
（mtls-agent が `.well-known/acme-challenge/` に応答ファイルを置きます）。

### 5-3. 起動する

```sh
sudo install -m 0644 deploy/systemd/mtls-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-agent
journalctl -u mtls-agent -f
```

「証明書を更新した」と出れば成功です。状態は次のコマンドで確かめられます（更新が必要なら終了コード 1）。

```sh
sudo mtls-agent check -config /etc/mtls-agent/config.yaml
```

初回の登録が済めば `eab.hmac` は不要です。削除し、設定の `eab.hmac_file` も消して構いません。

以後、mtls-agent は有効期間の 2/3 が過ぎた時点（24 時間の証明書なら約 16 時間後）に自動で更新します。
すぐに更新したいときは `sudo systemctl reload mtls-agent`（SIGHUP）を実行します。

## 6. アプリに組み込む

出力されるファイルは次のとおりです。

| ファイル | 内容 |
| --- | --- |
| `/etc/mtls-agent/tls/fullchain.pem` | 証明書 + 中間 CA。**アプリにはこちらを指定する** |
| `/etc/mtls-agent/tls/key.pem` | 秘密鍵 |
| `/etc/mtls-agent/tls/ca.pem` | ルート CA（接続相手の検証に使う） |
| `/etc/mtls-agent/tls/cert.pem` / `chain.pem` | 証明書のみ / 中間 CA のみ |

アプリを別のユーザーで動かす場合は、鍵を読めるようにします。mtls-agent とアプリで共通のグループを作り、
`mtls-agent.service` の `Group=` をそのグループにして、設定の `output.key_mode` を `"0640"` にします。

### Go のアプリ

```go
import "github.com/nobumin/mtls_manager/mtls"

// サーバ: クライアント証明書を必須にし、接続を許可する相手を名前で指定する
cfg, err := mtls.NewServerTLSConfig(mtls.Config{
	CertFile:     "/etc/mtls-agent/tls/fullchain.pem",
	KeyFile:      "/etc/mtls-agent/tls/key.pem",
	CAFile:       "/etc/mtls-agent/tls/ca.pem",
	AllowedPeers: []string{"app1.internal.example.com"},
})
srv := &http.Server{Addr: ":8443", TLSConfig: cfg, Handler: h}
log.Fatal(srv.ListenAndServeTLS("", ""))

// クライアント
cfg, err := mtls.NewClientTLSConfig(mtls.Config{
	CertFile: "/etc/mtls-agent/tls/fullchain.pem",
	KeyFile:  "/etc/mtls-agent/tls/key.pem",
	CAFile:   "/etc/mtls-agent/tls/ca.pem",
})
client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
```

証明書が更新されると、再起動なしで新しい証明書を使います。動く例は `examples/go/` にあります。

### nginx

```nginx
map $ssl_client_s_dn $mtls_allowed {
    default                                   0;
    "~CN=app1\.internal\.example\.com(,|$)"   1;
}

server {
    listen 8443 ssl;
    ssl_certificate         /etc/mtls-agent/tls/fullchain.pem;
    ssl_certificate_key     /etc/mtls-agent/tls/key.pem;
    ssl_client_certificate  /etc/mtls-agent/tls/ca.pem;
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_protocols           TLSv1.2 TLSv1.3;

    location / {
        if ($mtls_allowed = 0) { return 403; }
        proxy_pass http://127.0.0.1:8080;
    }
}
```

nginx は証明書を読み直すのに reload が必要です。`deploy/systemd/mtls-reload-nginx.path` を使うと、
証明書の更新を systemd が検知して nginx を reload します（mtls-agent に nginx を操作する権限を持たせずに済みます）。

```sh
sudo install -m 0644 deploy/systemd/mtls-reload-nginx.{path,service} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mtls-reload-nginx.path
```

### curl で確かめる

```sh
curl --cacert /etc/mtls-agent/tls/ca.pem \
     --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem \
     https://api.internal.example.com:8443/
```

## macOS で使う場合

- 設定ファイルは `/usr/local/etc/mtls-agent/config.yaml` などに置き、`deploy/launchd/` の plist で常駐させます。

  ```sh
  sudo install -m 0644 deploy/launchd/io.github.nobumin.mtls-agent.plist /Library/LaunchDaemons/
  sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.nobumin.mtls-agent.plist
  sudo launchctl kill HUP system/io.github.nobumin.mtls-agent   # すぐに更新する
  ```

- LaunchDaemons は既定で root として動きます。専用のユーザーで動かす場合は plist に `UserName` を追加し、
  そのユーザーが 80 番（または 443 番）を開けるか、`challenge.webroot` を使ってください。
- ログは plist の `StandardErrorPath`（例では `/usr/local/var/log/mtls-agent.log`）に出ます。ディレクトリは先に作っておきます。

## 次に読むもの

- [運用ガイド](operations.md): サーバの追加・取り消し、失効、中間 CA の更新、バックアップ、監視
- [セキュリティ設計](security.md): 何を守れて、何を守れないか
- [動作テスト手順書](test-procedure.md): 1 台の Linux で導入からテストまでを通しで行う
