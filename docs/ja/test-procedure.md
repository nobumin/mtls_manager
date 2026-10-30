# 動作テスト手順書（1 台の Linux）

[English](../en/test-procedure.md)

1 台の Linux に、CA サーバと証明書を受け取る 3 台のサーバ（`web1` / `app1` / `app2`）を同居させ、
導入からテストまでを通しで行う手順です。手順と期待結果を並べてあるので、上から順に実行し、各項目の「結果」欄に記入してください。

| 対象 | 内容 |
| --- | --- |
| この文書で確かめること | 1. テスト環境の準備、2. CA サーバ、3. mtls-agent、4. アプリへの組み込み（Go・curl・nginx）、5. 失効と EAB 鍵の取り消し |
| この文書の対象外 | 管理画面、ルート CA の入れ替え、連携版（別々の mtls-manager の間の mTLS） |
| 所要時間 | 1 時間半ほど（証明書の有効期間を 15 分にして、自動更新と期限切れを待つ時間を含む） |

> **テスト専用のマシン（または仮想マシン）で行ってください。** `/etc/hosts` の書き換え、利用者の追加、`/etc` への設定の配置、
> 80 番ポートの使用などを行います。使い終わったら [6. 後片付け](#6-後片付け) で元に戻せます。
>
> テスト用のルート CA の鍵は、手順の都合で同じマシンに置きます。**本番では、ルート CA の鍵はオフラインの端末に置きます**（[導入手順](getting-started.md)）。
> この手順で作った鍵・証明書は、テストの外で使わないでください。

## 0. テスト環境の構成

ループバック（`127.0.0.0/8`）の別々のアドレスを、サーバごとに割り当てます。名前は `/etc/hosts` で引きます。

| 役割 | 名前 | アドレス | 動かすもの |
| --- | --- | --- | --- |
| CA サーバ | `ca.internal.example.com` | `127.0.10.1` | `mtls-ca`（`:8443`。systemd） |
| サーバ（接続を受ける側） | `web1.internal.example.com` | `127.0.10.2` | `mtls-agent@web1`（systemd）、Go のサーバの例（`:8443`）、nginx（`:9443`） |
| クライアント（許可する相手） | `app1.internal.example.com` | `127.0.10.3` | `mtls-agent@app1`（systemd）、Go のクライアントの例、curl |
| クライアント（許可しない相手） | `app2.internal.example.com` | `127.0.10.4` | `mtls-agent`（常駐させず、1 回だけ実行） |

- web1 のアプリ（Go のサーバ・nginx）は、**app1 だけを接続を許可する相手**にします。app2 は同じ CA の正しい証明書を持っていても拒否されることを確かめます。
- 証明書の有効期間は **15 分**にします（本番の既定は 24 時間）。mtls-agent は有効期間の 2/3（10 分）が過ぎると更新するので、自動更新と期限切れをテストの時間内に確かめられます。
- mtls-agent の http-01 の所有確認は、サーバごとのアドレスの 80 番で受けます（`127.0.10.2:80` など）。同じマシンで 80 番を全アドレスで使っているもの（nginx の既定のサイトなど）があると失敗します（1-9 で外します）。

## 1. テスト環境の準備

以下、すべて `sudo` できる利用者で実行します。作業用のディレクトリは `~/mtls-test` とします。

### 1-1. 準備するもの

| 項目 | 内容 |
| --- | --- |
| OS | systemd の Linux（Ubuntu 24.04 で確認） |
| Go | 1.26 以降 |
| パッケージ | `git`、`curl`、`openssl`、`nginx`（4. の nginx の項目で使う。使わない場合は不要） |

```sh
sudo apt-get install -y git curl openssl nginx    # Debian / Ubuntu の場合
go version                                        # go1.26 以降であること
```

> `HTTPS_PROXY` などのプロキシの環境変数を設定している場合、curl がテスト用の名前をプロキシへ送ってしまいます。
> この手順の curl には `--noproxy '*'` を付けています。mtls-agent と mtls-ca は、環境変数のプロキシを使いません。

### 1-2. ビルドして配置する

```sh
mkdir -p ~/mtls-test && cd ~/mtls-test
git clone https://github.com/nobumin/mtls_manager src
cd src
git checkout develop                       # テストする版（ブランチ・タグ）を選ぶ
go build -trimpath -o ../bin/ ./cmd/... ./examples/go/...
sudo install -m 0755 ../bin/mtlsctl ../bin/mtls-ca ../bin/mtls-agent /usr/local/bin/
cd ~/mtls-test
ls bin                                     # client mtls-agent mtls-ca mtlsctl server
```

`bin/server` と `bin/client` は、`mtls` ライブラリを使った Go のアプリの例（`examples/go/`）です。

### 1-3. 名前を設定する

```sh
sudo tee -a /etc/hosts <<'EOF'
# mtls_manager テスト環境
127.0.10.1 ca.internal.example.com
127.0.10.2 web1.internal.example.com
127.0.10.3 app1.internal.example.com
127.0.10.4 app2.internal.example.com
EOF
getent hosts web1.internal.example.com     # 127.0.10.2 と出ること
```

### 1-4. 利用者を作る

```sh
sudo useradd --system --home /var/lib/mtls-ca    --shell /usr/sbin/nologin mtls-ca
sudo useradd --system --home /var/lib/mtls-agent --shell /usr/sbin/nologin mtls-agent
```

### 1-5. ルート CA と中間 CA を作る

```sh
cd ~/mtls-test
# ルート CA（本番ではオフラインの端末で行う）
mtlsctl root create -out-dir ./offline -cn "Test Root CA" -org "mtls-test"

# 中間 CA の鍵と CSR（CA サーバで作る）
sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca
sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca -cn "Test mTLS CA"
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/intermediate.key

# ルート CA で署名する（本番ではオフラインの端末で行う）。名前制約は internal.example.com
sudo cp /etc/mtls-ca/intermediate.csr .
mtlsctl intermediate sign -root-cert offline/root.crt -root-key offline/root.key \
  -csr intermediate.csr -out intermediate.crt -permitted-domain internal.example.com

sudo install -m 0644 intermediate.crt offline/root.crt /etc/mtls-ca/
```

### 1-6. CA の設定と EAB 鍵

```sh
sudo tee /etc/mtls-ca/config.yaml >/dev/null <<'EOF'
listen: "127.0.10.1:8443"
external_url: "https://ca.internal.example.com:8443"
data_dir: "/var/lib/mtls-ca"
root_cert: "/etc/mtls-ca/root.crt"
intermediate_cert: "/etc/mtls-ca/intermediate.crt"
intermediate_key: "/etc/mtls-ca/intermediate.key"
eab_file: "/etc/mtls-ca/eab.json"
allowed_client_cidrs: ["127.0.0.0/8"]
policy:
  allowed_domains: ["internal.example.com"]
  max_names_per_order: 10
cert:
  validity: "15m"          # テスト用。本番の既定は 24h
challenge:
  types: ["http-01", "tls-alpn-01"]
  http01_port: 80
  tlsalpn01_port: 443
  timeout: "10s"
  attempts: 3
crl:
  validity: "24h"
log:
  level: "info"
  format: "text"
EOF
sudo chown root:mtls-ca /etc/mtls-ca/config.yaml && sudo chmod 0640 /etc/mtls-ca/config.yaml

# サーバごとの EAB 鍵（その名前の証明書だけを発行できる）
for h in web1 app1 app2; do
  sudo mtlsctl eab create -file /etc/mtls-ca/eab.json -names $h.internal.example.com -note "$h（テスト）" -hmac-out ./$h.hmac
done
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/eab.json
sudo mtlsctl eab list -file /etc/mtls-ca/eab.json
```

`*.hmac` は秘密情報です（テストでも、リポジトリなどに置かないでください）。

### 1-7. CA を起動する

```sh
sudo install -m 0644 src/deploy/systemd/mtls-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-ca
journalctl -u mtls-ca -n 5 --no-pager      # 「mtls-ca を起動した」と出ること
```

### 1-8. mtls-agent を用意する（web1 / app1 / app2）

同じマシンで複数の mtls-agent を動かすため、同梱のユニットから**サーバごとのテンプレート**（`mtls-agent@<名前>`）を作ります。
設定は `/etc/mtls-agent-<名前>/`、アカウント鍵は `/var/lib/mtls-agent-<名前>/` に分けます。

```sh
sed -e 's#/etc/mtls-agent/config.yaml#/etc/mtls-agent-%i/config.yaml#' \
    -e 's#^ReadWritePaths=/etc/mtls-agent/tls#ReadWritePaths=/etc/mtls-agent-%i/tls#' \
    -e 's#^StateDirectory=mtls-agent$#StateDirectory=mtls-agent-%i#' \
    -e 's#^Description=mtls-agent #Description=mtls-agent %i #' \
    src/deploy/systemd/mtls-agent.service | sudo tee /etc/systemd/system/mtls-agent@.service >/dev/null
sudo systemctl daemon-reload
```

サーバごとの設定を作ります。更新後のコマンド（`hooks.post_renew`）には、実行されたことが分かるように `renewed` というファイルを作るコマンドを指定します。

```sh
cd ~/mtls-test
for h in web1 app1 app2; do
  case $h in web1) ip=127.0.10.2;; app1) ip=127.0.10.3;; app2) ip=127.0.10.4;; esac
  kid=$(sudo mtlsctl eab list -file /etc/mtls-ca/eab.json | awk -v n="$h.internal.example.com" '$2 == n {print $1}')
  sudo install -d -m 0755 /etc/mtls-agent-$h
  sudo install -d -m 0755 -o mtls-agent -g mtls-agent /etc/mtls-agent-$h/tls
  sudo install -m 0644 /etc/mtls-ca/root.crt /etc/mtls-agent-$h/root.crt
  sudo install -m 0600 -o mtls-agent -g mtls-agent $h.hmac /etc/mtls-agent-$h/eab.hmac
  sudo tee /etc/mtls-agent-$h/config.yaml >/dev/null <<EOF
ca_url: "https://ca.internal.example.com:8443/acme/directory"
ca_root: "/etc/mtls-agent-$h/root.crt"
account_key: "/var/lib/mtls-agent-$h/account.key"
eab:
  kid: "$kid"
  hmac_file: "/etc/mtls-agent-$h/eab.hmac"
names: ["$h.internal.example.com"]
challenge:
  type: "http-01"
  listen: "$ip:80"
output:
  cert: "/etc/mtls-agent-$h/tls/cert.pem"
  chain: "/etc/mtls-agent-$h/tls/chain.pem"
  fullchain: "/etc/mtls-agent-$h/tls/fullchain.pem"
  key: "/etc/mtls-agent-$h/tls/key.pem"
  ca: "/etc/mtls-agent-$h/tls/ca.pem"
hooks:
  post_renew: ["/usr/bin/touch", "/etc/mtls-agent-$h/tls/renewed"]
log:
  level: "info"
EOF
  echo "$h: kid=$kid"
done
rm -f web1.hmac app1.hmac app2.hmac
```

`kid=` が空の行があれば、1-6 の EAB 鍵の作成を確かめてください。

### 1-9. nginx を用意する（web1 の 9443 番）

既定のサイトは 80 番を全アドレスで使い、mtls-agent の所有確認とぶつかるので外します。

```sh
sudo rm -f /etc/nginx/sites-enabled/default
sudo tee /etc/nginx/conf.d/mtls-test.conf >/dev/null <<'EOF'
map $ssl_client_s_dn $mtls_allowed {
    default                                   0;
    "~CN=app1\.internal\.example\.com(,|$)"   1;
}
server {
    listen 127.0.10.2:9443 ssl;
    server_name web1.internal.example.com;
    ssl_certificate         /etc/mtls-agent-web1/tls/fullchain.pem;
    ssl_certificate_key     /etc/mtls-agent-web1/tls/key.pem;
    ssl_client_certificate  /etc/mtls-agent-web1/tls/ca.pem;
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_protocols           TLSv1.2 TLSv1.3;
    location / {
        if ($mtls_allowed = 0) { return 403; }
        return 200 "nginx: hello, $ssl_client_s_dn\n";
    }
}
EOF
```

nginx は、web1 の証明書ができてから（3. の AG-01 の後）起動します（AP-09）。

### 1-10. 別のルート CA の証明書を作る（拒否されることの確認用）

この CA とは無関係のルート CA と、それが発行した「app1 を名乗る証明書」を openssl で作ります。

```sh
mkdir -p ~/mtls-test/fake && cd ~/mtls-test/fake
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout fake-root.key -out fake-root.crt \
  -days 1 -subj "/CN=Fake Root CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout app1.key -out app1.csr -subj "/CN=app1.internal.example.com"
printf "subjectAltName=DNS:app1.internal.example.com\nextendedKeyUsage=clientAuth,serverAuth\n" > ext.cnf
openssl x509 -req -in app1.csr -CA fake-root.crt -CAkey fake-root.key -CAcreateserial -out app1.crt -days 1 -extfile ext.cnf
cd ~/mtls-test
```

### 1-11. よく使うファイルの場所

以下のテストでは、次の変数を使います（シェルを開き直したら、もう一度設定します）。

```sh
cd ~/mtls-test
W=/etc/mtls-agent-web1/tls; A=/etc/mtls-agent-app1/tls; P=/etc/mtls-agent-app2/tls
```

## 2. CA サーバ

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| CA-01 | `systemctl status mtls-ca --no-pager` | `active (running)`。`journalctl -u mtls-ca` に「mtls-ca を起動した」と、`listen=127.0.10.1:8443`・`allowed_domains=[internal.example.com]`・`cert_validity=15m0s` | |
| CA-02 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/acme/directory` | JSON が返る。`"externalAccountRequired":true` を含む（EAB 鍵が無いと登録できない） | |
| CA-03 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt -o /dev/null -w '%{http_code} %{content_type}\n' https://ca.internal.example.com:8443/crl` | `200 application/pkix-crl` | |
| CA-04 | `sudo ls -l /etc/mtls-ca /var/lib/mtls-ca` | `intermediate.key` と `eab.json` が `mtls-ca` の所有で `-rw-------`（0600）。`/var/lib/mtls-ca` は `mtls-ca` の所有 | |

### 起動を拒否する設定（CA-05〜CA-10）

CA を止めてから、設定を壊した状態で前面で起動し、**起動を拒否すること**を確かめます。終わったら必ず元に戻して起動し直します。
（CA を動かしたままだと、数秒後に「データベースを開けない（別の mtls-ca が動いていないか確認する）」で失敗し、確かめたい誤りまで進まないので、先に止めます。）

```sh
sudo systemctl stop mtls-ca
sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca/test
mk() { sudo sed "$2" /etc/mtls-ca/config.yaml | sudo tee /etc/mtls-ca/test/$1.yaml >/dev/null
       sudo chown root:mtls-ca /etc/mtls-ca/test/$1.yaml; sudo chmod 0640 /etc/mtls-ca/test/$1.yaml; }
mk domain 's#allowed_domains: .*#allowed_domains: ["example.org"]#'
mk validity 's#validity: "15m"#validity: "5m"#'
mk url 's#^external_url: .*#external_url: "http://ca.internal.example.com:8443"#'
mk cidr 's#^allowed_client_cidrs: .*#allowed_client_cidrs: ["10.0.0.0/8"]#'
```

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| CA-05 | `sudo chmod 0640 /etc/mtls-ca/intermediate.key; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo chmod 0600 /etc/mtls-ca/intermediate.key` | `/etc/mtls-ca/intermediate.key: 権限が緩すぎる（0640）。chmod 600 ... を実行すること` と出て、終了コード 1 | |
| CA-06 | `sudo chmod 0644 /etc/mtls-ca/eab.json; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo chmod 0600 /etc/mtls-ca/eab.json` | `eab_file: /etc/mtls-ca/eab.json: 権限が緩すぎる（0644）。…` と出て、終了コード 1 | |
| CA-07 | `sudo mv /etc/mtls-ca/eab.json /etc/mtls-ca/eab.json.bak; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo mv /etc/mtls-ca/eab.json.bak /etc/mtls-ca/eab.json` | `eab_file: stat /etc/mtls-ca/eab.json: no such file or directory（mtlsctl eab create で作成する）` と出て、終了コード 1 | |
| CA-08 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/domain.yaml; echo $?` | `policy.allowed_domains の "example.org" が中間 CA の名前制約 [internal.example.com] の範囲外` と出て、終了コード 1 | |
| CA-09 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/validity.yaml; echo $?` | `cert.validity は 10m〜90d` と出て、終了コード 1 | |
| CA-10 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/url.yaml; echo $?` | `external_url "http://..." は https://ホスト[:ポート] の形にする` と出て、終了コード 1 | |

### 送信元の制限（CA-11）

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| CA-11 | 1 つ目の端末で `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/cidr.yaml` を実行したまま、2 つ目の端末で `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/acme/directory`。確かめたら 1 つ目の端末で Ctrl+C | `403`。CA のログに「許可されていない送信元からの接続を拒否」（送信元 `127.0.0.1` は `10.0.0.0/8` に含まれない） | |

確かめ終わったら、元の設定で起動し直します。

```sh
sudo rm -rf /etc/mtls-ca/test
sudo systemctl start mtls-ca && systemctl is-active mtls-ca     # active
```

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| CA-12 | CA が動いている状態で、もう 1 つ起動する: `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?` | 数秒後に `データベースを開けない（別の mtls-ca が動いていないか確認する）: timeout`、終了コード 1（二重起動しない）。動いている CA には影響しない（`systemctl is-active mtls-ca` が `active`） | |

## 3. mtls-agent

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| AG-01 | `sudo systemctl enable --now mtls-agent@web1 mtls-agent@app1` を実行し、数秒後に `journalctl -u mtls-agent@web1 -n 10 --no-pager`（app1 も同様） | 「アカウント鍵を作成した」→「CA にアカウントを登録した」→「証明書を更新した」→「更新後のコマンドを実行した」の順に出る | |
| AG-02 | `sudo ls -l $W` | `ca.pem`・`cert.pem`・`chain.pem`・`fullchain.pem`・`key.pem`・`renewed` がある。`key.pem` だけ `-rw-------`（0600）で、所有者は `mtls-agent` | |
| AG-03 | `mtlsctl inspect $W/cert.pem` | `Subject: CN=web1.internal.example.com`、`Issuer: CN=Test mTLS CA`、`DNS 名: [web1.internal.example.com]`、`用途: serverAuth, clientAuth`、有効期間が 15 分ほど | |
| AG-04 | `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml; echo $?` | `状態: 正常`、`更新予定` が発行のおよそ 10 分後、終了コード 0 | |
| AG-05 | `sudo systemctl restart mtls-agent@web1` の後、`journalctl -u mtls-agent@web1 -n 3 --no-pager` | 「mtls-agent を起動した」だけで、証明書を取り直さない（有効な証明書があるため） | |
| AG-06 | `sudo systemctl reload mtls-agent@web1`（すぐの更新）の後、`journalctl -u mtls-agent@web1 -n 3 --no-pager` と `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml` | 「証明書を取得する reason=手動での更新要求」→「証明書を更新した」。`check` のシリアルが AG-04 から変わる | |
| AG-07 | AG-06 の 10 分後まで待ち（`check` の `更新予定` の時刻）、`journalctl -u mtls-agent@web1 -n 3 --no-pager` | 「証明書を取得する reason=更新時期を過ぎた」→「証明書を更新した」→「更新後のコマンドを実行した」。手を触れずに更新される | |

AG-07 の待ち時間の間に、4. の AP-01〜AP-08 を進めて構いません。

### app2 の証明書（1 回だけ取得する）

app2 は常駐させず、`renew` で 1 回だけ取得します（root で実行するので、80 番を開ける権限があります）。

```sh
sudo install -d -m 0700 /var/lib/mtls-agent-app2
sudo mtls-agent renew -config /etc/mtls-agent-app2/config.yaml; echo $?
```

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| AG-08 | 上の `renew` | 「CA にアカウントを登録した」→「証明書を更新した」、終了コード 0。`sudo ls $P` に証明書ができる | |
| AG-09 | 次を実行して、app2 の EAB 鍵で web1 の名前を要求する: `sudo sed 's/names: .*/names: ["web1.internal.example.com"]/' /etc/mtls-agent-app2/config.yaml \| sudo tee /etc/mtls-agent-app2/bad-name.yaml >/dev/null; sudo mtls-agent renew -config /etc/mtls-agent-app2/bad-name.yaml; echo $?` | `rejectedIdentifier: "web1.internal.example.com" はこのアカウント（EAB 鍵）には許可されていない`、終了コード 1（EAB 鍵に許可した名前以外は発行されない） | |
| AG-10 | 同様に `names: ["app2.example.org"]` にした設定（`bad-domain.yaml`）で `renew` | `rejectedIdentifier: "app2.example.org" はこの CA で発行できるドメインの範囲外`、終了コード 1 | |
| AG-11 | `sudo mv $P/cert.pem $P/cert.pem.bak; sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml; echo $?; sudo mv $P/cert.pem.bak $P/cert.pem` | `状態: 更新が必要 – 証明書が無い、または読めない`、終了コード 1（監視に使える） | |

AG-09・AG-10 が終わったら、壊した設定を消します: `sudo rm /etc/mtls-agent-app2/bad-*.yaml`

### CA が止まっているとき（AG-12）

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| AG-12 | `sudo systemctl stop mtls-ca` → `sudo systemctl reload mtls-agent@app1` → `journalctl -u mtls-agent@app1 -n 2 --no-pager` → `sudo systemctl start mtls-ca` → 1 分ほど待って `journalctl -u mtls-agent@app1 -n 3 --no-pager` | 止めている間は「証明書を取得できない（再試行する）… connection refused … retry_in=…」。CA を起動すると、再試行で「証明書を更新した」。この間も手元の証明書はそのまま使える | |

## 4. アプリへの組み込み

### Go のアプリ（`mtls` ライブラリ）

別の端末で、web1 の証明書で Go のサーバの例を起動し、そのままにしておきます（接続を許可する相手は app1 だけ）。

```sh
cd ~/mtls-test
sudo ./bin/server -addr 127.0.10.2:8443 -cert /etc/mtls-agent-web1/tls/fullchain.pem \
  -key /etc/mtls-agent-web1/tls/key.pem -ca /etc/mtls-agent-web1/tls/ca.pem -allow app1.internal.example.com
```

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| AP-01 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca $A/ca.pem https://web1.internal.example.com:8443/` | `hello, [app1.internal.example.com]`（サーバは検証済みの相手の名前を返す） | |
| AP-02 | `sudo curl --noproxy '*' -sS --cacert $A/ca.pem --cert $A/fullchain.pem --key $A/key.pem https://web1.internal.example.com:8443/` | `hello, [app1.internal.example.com]` | |
| AP-03 | `curl --noproxy '*' -sS --cacert $A/ca.pem https://web1.internal.example.com:8443/`（クライアント証明書なし） | `alert certificate required` で失敗。サーバのログに `client didn't provide a certificate` | |
| AP-04 | `sudo curl --noproxy '*' -sS --cacert $P/ca.pem --cert $P/fullchain.pem --key $P/key.pem https://web1.internal.example.com:8443/`（app2） | `alert bad certificate` で失敗。サーバのログに `mtls: 相手 [app2.internal.example.com] は許可されていない`（同じ CA の正しい証明書でも、許可した相手以外は通さない） | |
| AP-05 | `curl --noproxy '*' -sS --cacert $A/ca.pem --cert fake/app1.crt --key fake/app1.key https://web1.internal.example.com:8443/`（別のルート CA の「app1」） | `alert unknown ca` で失敗。サーバのログに `certificate signed by unknown authority` | |
| AP-06 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca fake/fake-root.crt https://web1.internal.example.com:8443/`（クライアントが別のルート CA だけを信頼する） | `x509: certificate signed by unknown authority` で失敗（クライアント側もサーバの証明書を検証している） | |
| AP-07 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca $A/ca.pem https://127.0.10.2:8443/`（アドレスで接続） | `cannot validate certificate for 127.0.10.2 because it doesn't contain any IP SANs` で失敗（名前で接続する） | |
| AP-08 | 次の関数で、サーバが使っている証明書のシリアルを見る。`sudo systemctl reload mtls-agent@web1` で更新した後、30 秒以上待ってもう一度見る（サーバは再起動しない）。<br>`ser() { sudo openssl s_client -connect 127.0.10.2:8443 -servername web1.internal.example.com -cert $A/fullchain.pem -key $A/key.pem -CAfile $A/ca.pem </dev/null 2>/dev/null \| openssl x509 -noout -serial; }` | 更新の前と後でシリアルが変わる（`mtls` ライブラリは 30 秒ごとにファイルを確かめ、再起動なしで新しい証明書を使う）。変わったシリアルは `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml` のシリアルと同じ | |

### nginx

```sh
sudo nginx -t && sudo systemctl restart nginx
```

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| AP-09 | `sudo curl --noproxy '*' -sS -w '%{http_code}\n' --cacert $A/ca.pem --cert $A/fullchain.pem --key $A/key.pem https://web1.internal.example.com:9443/`（app1） | `nginx: hello, CN=app1.internal.example.com` と `200` | |
| AP-10 | AP-09 の app1 を app2 にする（`$A` → `$P`） | `403`（TLS の検証は通るが、許可した相手ではない） | |
| AP-11 | `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert $A/ca.pem https://web1.internal.example.com:9443/`（クライアント証明書なし） | `400`（No required SSL certificate was sent） | |
| AP-12 | `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert $A/ca.pem --cert fake/app1.crt --key fake/app1.key https://web1.internal.example.com:9443/`（別のルート CA） | `400`（The SSL certificate error） | |

nginx は証明書を読み直すのに reload が必要です（本番では `deploy/systemd/mtls-reload-nginx.path` を使います。[導入手順 6.](getting-started.md#nginx)）。
このテストでは更新のたびに reload しないので、テストを 15 分以上続ける場合は、AP-09 の前に `sudo systemctl reload nginx` を実行してください。

## 5. 失効と EAB 鍵の取り消し

app2 を「廃棄したサーバ」と見立てて、EAB 鍵の取り消しと証明書の失効を行います。

| ID | 手順 | 期待結果 | 結果 |
| --- | --- | --- | --- |
| RV-01 | app2 の kid を `sudo mtlsctl eab list -file /etc/mtls-ca/eab.json` で確かめ、`sudo mtlsctl eab revoke -file /etc/mtls-ca/eab.json -kid <app2 の kid>` | 「EAB 鍵 … を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない」。`eab list` から app2 が消える | |
| RV-02 | `sudo mtls-agent renew -config /etc/mtls-agent-app2/config.yaml -force; echo $?` | `403 urn:ietf:params:acme:error:unauthorized: このアカウントの EAB 鍵は取り消されている`、終了コード 1（CA の再起動なしで反映される） | |
| RV-03 | AP-10 をもう一度実行 | まだ `403`（TLS の検証は通る）。取り消しの後も、発行済みの証明書は有効期限まで使える | |
| RV-04 | CA を止めて、app2 の証明書を失効させる:<br>`sudo systemctl stop mtls-ca`<br>`sudo -u mtls-ca mtls-ca certs -config /etc/mtls-ca/config.yaml`<br>`sudo -u mtls-ca mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <app2 のシリアル> -reason 1`<br>`sudo systemctl start mtls-ca` | `certs` に発行済みの証明書が並ぶ（app2 の行の SERIAL を使う）。「証明書 … を失効させた。mtls-ca を起動すると CRL に反映される」 | |
| RV-05 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/crl -o crl.der && openssl crl -inform DER -in crl.der -out crl.pem && openssl crl -in crl.pem -noout -text` | `Revoked Certificates:` に app2 のシリアルと `CRL Reason Code: Key Compromise` | |
| RV-06 | `for c in $A $P; do sudo openssl verify -crl_check -CAfile $c/ca.pem -untrusted $c/chain.pem -CRLfile crl.pem $c/cert.pem; done` | app1 は `OK`、app2 は `certificate revoked` | |
| RV-07 | app2 の証明書の有効期限（`sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml` の `有効期限`）を過ぎてから、AP-10 をもう一度実行し、`sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml; echo $?` | AP-10 が `400`（期限切れの証明書は TLS の検証で拒否される）。`check` は `状態: 更新が必要 – 有効期限が切れている`、終了コード 1 | |

> **注意**: `mtls` ライブラリと mtls-agent は CRL を確かめません（[運用ガイド](operations.md#証明書を失効させる)）。
> 失効させても、Go のアプリ（AP-01 の形）は有効期限まで接続を受け付けます。急ぐ場合は、相手側の許可リスト（`AllowedPeers`）から外します。
> nginx の `ssl_crl` については、[7. 既知の制限](#7-既知の制限) を参照してください。

## 6. 後片付け

```sh
sudo systemctl disable --now mtls-agent@web1 mtls-agent@app1 mtls-ca
sudo rm -f /etc/systemd/system/mtls-agent@.service /etc/systemd/system/mtls-ca.service
sudo systemctl daemon-reload
sudo rm -f /etc/nginx/conf.d/mtls-test.conf && sudo systemctl restart nginx   # 既定のサイトを戻す場合は sites-enabled/default のリンクを作り直す
sudo rm -rf /etc/mtls-ca /var/lib/mtls-ca /etc/mtls-agent-web1 /etc/mtls-agent-app1 /etc/mtls-agent-app2 \
            /var/lib/mtls-agent-web1 /var/lib/mtls-agent-app1 /var/lib/mtls-agent-app2
sudo rm -f /usr/local/bin/mtlsctl /usr/local/bin/mtls-ca /usr/local/bin/mtls-agent
sudo userdel mtls-ca; sudo userdel mtls-agent
sudo sed -i '/# mtls_manager テスト環境/,/app2.internal.example.com/d' /etc/hosts
rm -rf ~/mtls-test        # テスト用のルート CA の鍵（offline/root.key）もここで消える
```

Go のサーバの例を動かした端末は Ctrl+C で止めます。

## 7. 既知の制限

- **nginx の `ssl_crl` は、この CA の CRL だけでは使えません。** nginx は CRL を指定すると、チェーンのすべての段（中間 CA を発行したルート CA の段も含む）の CRL を求めます。
  mtls-ca が配るのは中間 CA の CRL だけで、ルート CA の CRL はありません。そのため、`ssl_crl` に CA の CRL を指定すると、
  失効していない証明書も含めてすべての接続が `400`（error.log に `unable to get certificate CRL`）になります。
  失効の確認は、RV-05・RV-06 のとおり openssl で行ってください。

## 結果のまとめ

| 区分 | 項目 | 合格 | 不合格 | 備考 |
| --- | --- | --- | --- | --- |
| 2. CA サーバ | CA-01〜CA-12 | | | |
| 3. mtls-agent | AG-01〜AG-12 | | | |
| 4. アプリへの組み込み | AP-01〜AP-12 | | | |
| 5. 失効と EAB 鍵の取り消し | RV-01〜RV-07 | | | |

テストした版（`git -C ~/mtls-test/src rev-parse --short HEAD`）: ＿＿＿＿　実施日: ＿＿＿＿　実施者: ＿＿＿＿
