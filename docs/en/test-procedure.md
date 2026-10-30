# Test procedure (single Linux machine)

[日本語](../ja/test-procedure.md)

This procedure runs the CA server and three certificate-receiving servers (`web1` / `app1` / `app2`) on one Linux machine,
from installation through testing. Each step lists its expected result; work from top to bottom and fill in the "Result" column.

| Item | Contents |
| --- | --- |
| Covered | 1. preparing the test environment, 2. CA server, 3. mtls-agent, 4. application integration (Go, curl, nginx), 5. revocation and EAB key revocation |
| Not covered | Admin UI, root CA rotation, federation (mTLS between separate mtls-managers) |
| Time needed | About 1.5 hours (certificates last 15 minutes, so this includes waiting for automatic renewal and expiry) |

> **Use a machine (or VM) dedicated to testing.** The procedure edits `/etc/hosts`, adds users, puts configuration under `/etc`
> and uses port 80. [6. Cleanup](#6-cleanup) undoes it afterwards.
>
> For convenience the test root CA key lives on the same machine. **In production the root CA key stays on an offline machine** ([getting started](getting-started.md)).
> Do not use keys or certificates created here outside the test.
>
> mtls-ca and mtls-agent print messages in Japanese. The expected results quote them, with an English gloss in parentheses.

## 0. Test environment

Each server gets its own loopback (`127.0.0.0/8`) address. Names are resolved through `/etc/hosts`.

| Role | Name | Address | Runs |
| --- | --- | --- | --- |
| CA server | `ca.internal.example.com` | `127.0.10.1` | `mtls-ca` (`:8443`, systemd) |
| Server (accepts connections) | `web1.internal.example.com` | `127.0.10.2` | `mtls-agent@web1` (systemd), the Go server example (`:8443`), nginx (`:9443`) |
| Client (allowed peer) | `app1.internal.example.com` | `127.0.10.3` | `mtls-agent@app1` (systemd), the Go client example, curl |
| Client (not allowed) | `app2.internal.example.com` | `127.0.10.4` | `mtls-agent` (run once, not as a service) |

- web1's applications (the Go server and nginx) **allow only app1**. The tests show that app2 is rejected even with a valid certificate from the same CA.
- Certificates last **15 minutes** (the production default is 24 hours). mtls-agent renews after 2/3 of the lifetime (10 minutes), so renewal and expiry can be observed during the test.
- mtls-agent answers http-01 validation on port 80 of each server's own address (`127.0.10.2:80` and so on). Anything that uses port 80 on all addresses (such as nginx's default site) makes it fail (it is removed in 1-9).

## 1. Preparing the test environment

Run everything as a user who can `sudo`. The working directory is `~/mtls-test`.

### 1-1. Prerequisites

| Item | Contents |
| --- | --- |
| OS | Linux with systemd (checked on Ubuntu 24.04) |
| Go | 1.26 or later |
| Packages | `git`, `curl`, `openssl`, `nginx` (used by the nginx items in 4.; not needed otherwise) |

```sh
sudo apt-get install -y git curl openssl nginx    # Debian / Ubuntu
go version                                        # must be go1.26 or later
```

> If proxy variables such as `HTTPS_PROXY` are set, curl sends the test names to the proxy.
> The curl commands here use `--noproxy '*'`. mtls-agent and mtls-ca never use proxy variables.

### 1-2. Build and install

```sh
mkdir -p ~/mtls-test && cd ~/mtls-test
git clone https://github.com/nobumin/mtls_manager src
cd src
git checkout develop                       # pick the version (branch or tag) to test
go build -trimpath -o ../bin/ ./cmd/... ./examples/go/...
sudo install -m 0755 ../bin/mtlsctl ../bin/mtls-ca ../bin/mtls-agent /usr/local/bin/
cd ~/mtls-test
ls bin                                     # client mtls-agent mtls-ca mtlsctl server
```

`bin/server` and `bin/client` are the Go application examples using the `mtls` library (`examples/go/`).

### 1-3. Names

```sh
sudo tee -a /etc/hosts <<'EOF'
# mtls_manager test environment
127.0.10.1 ca.internal.example.com
127.0.10.2 web1.internal.example.com
127.0.10.3 app1.internal.example.com
127.0.10.4 app2.internal.example.com
EOF
getent hosts web1.internal.example.com     # must print 127.0.10.2
```

### 1-4. Users

```sh
sudo useradd --system --home /var/lib/mtls-ca    --shell /usr/sbin/nologin mtls-ca
sudo useradd --system --home /var/lib/mtls-agent --shell /usr/sbin/nologin mtls-agent
```

### 1-5. Root and intermediate CA

```sh
cd ~/mtls-test
# Root CA (done on an offline machine in production)
mtlsctl root create -out-dir ./offline -cn "Test Root CA" -org "mtls-test"

# Intermediate CA key and CSR (created on the CA server)
sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca
sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca -cn "Test mTLS CA"
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/intermediate.key

# Sign with the root CA (done on the offline machine in production). Name constraint: internal.example.com
sudo cp /etc/mtls-ca/intermediate.csr .
mtlsctl intermediate sign -root-cert offline/root.crt -root-key offline/root.key \
  -csr intermediate.csr -out intermediate.crt -permitted-domain internal.example.com

sudo install -m 0644 intermediate.crt offline/root.crt /etc/mtls-ca/
```

### 1-6. CA configuration and EAB keys

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
  validity: "15m"          # for testing; the production default is 24h
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

# One EAB key per server (it can only issue certificates for that name)
for h in web1 app1 app2; do
  sudo mtlsctl eab create -file /etc/mtls-ca/eab.json -names $h.internal.example.com -note "$h (test)" -hmac-out ./$h.hmac
done
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/eab.json
sudo mtlsctl eab list -file /etc/mtls-ca/eab.json
```

The `*.hmac` files are secrets (even in a test, keep them out of repositories).

### 1-7. Start the CA

```sh
sudo install -m 0644 src/deploy/systemd/mtls-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-ca
journalctl -u mtls-ca -n 5 --no-pager      # must show 「mtls-ca を起動した」 (mtls-ca started)
```

### 1-8. mtls-agent (web1 / app1 / app2)

To run several mtls-agents on one machine, create a **per-server template** (`mtls-agent@<name>`) from the bundled unit.
Configuration goes in `/etc/mtls-agent-<name>/` and the account key in `/var/lib/mtls-agent-<name>/`.

```sh
sed -e 's#/etc/mtls-agent/config.yaml#/etc/mtls-agent-%i/config.yaml#' \
    -e 's#^ReadWritePaths=/etc/mtls-agent/tls#ReadWritePaths=/etc/mtls-agent-%i/tls#' \
    -e 's#^StateDirectory=mtls-agent$#StateDirectory=mtls-agent-%i#' \
    -e 's#^Description=mtls-agent #Description=mtls-agent %i #' \
    src/deploy/systemd/mtls-agent.service | sudo tee /etc/systemd/system/mtls-agent@.service >/dev/null
sudo systemctl daemon-reload
```

Create each server's configuration. The post-renewal command (`hooks.post_renew`) creates a file named `renewed`, so you can see that it ran.

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

If any line shows an empty `kid=`, check the EAB keys from 1-6.

### 1-9. nginx (port 9443 on web1)

The default site uses port 80 on all addresses and collides with mtls-agent's validation, so remove it.

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

Start nginx once web1 has a certificate (after AG-01 in 3.; see AP-09).

### 1-10. A certificate from another root CA (for rejection tests)

Create, with openssl, a root CA unrelated to this CA and a certificate from it that claims to be app1.

```sh
mkdir -p ~/mtls-test/fake && cd ~/mtls-test/fake
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout fake-root.key -out fake-root.crt \
  -days 1 -subj "/CN=Fake Root CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout app1.key -out app1.csr -subj "/CN=app1.internal.example.com"
printf "subjectAltName=DNS:app1.internal.example.com\nextendedKeyUsage=clientAuth,serverAuth\n" > ext.cnf
openssl x509 -req -in app1.csr -CA fake-root.crt -CAkey fake-root.key -CAcreateserial -out app1.crt -days 1 -extfile ext.cnf
cd ~/mtls-test
```

### 1-11. Shortcuts

The tests use these variables (set them again in every new shell).

```sh
cd ~/mtls-test
W=/etc/mtls-agent-web1/tls; A=/etc/mtls-agent-app1/tls; P=/etc/mtls-agent-app2/tls
```

## 2. CA server

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| CA-01 | `systemctl status mtls-ca --no-pager` | `active (running)`. `journalctl -u mtls-ca` shows 「mtls-ca を起動した」 (started) with `listen=127.0.10.1:8443`, `allowed_domains=[internal.example.com]`, `cert_validity=15m0s` | |
| CA-02 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/acme/directory` | JSON including `"externalAccountRequired":true` (registration needs an EAB key) | |
| CA-03 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt -o /dev/null -w '%{http_code} %{content_type}\n' https://ca.internal.example.com:8443/crl` | `200 application/pkix-crl` | |
| CA-04 | `sudo ls -l /etc/mtls-ca /var/lib/mtls-ca` | `intermediate.key` and `eab.json` are owned by `mtls-ca` with `-rw-------` (0600). `/var/lib/mtls-ca` is owned by `mtls-ca` | |

### Settings that prevent startup (CA-05 to CA-10)

Stop the CA, then start it in the foreground with a broken setting and confirm that **it refuses to start**. Always restore and restart afterwards.
(Stop the service first: otherwise the foreground process fails after a few seconds with 「データベースを開けない（別の mtls-ca が動いていないか確認する）」 (cannot open the database; check that no other mtls-ca is running) before reaching the error being tested.)

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

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| CA-05 | `sudo chmod 0640 /etc/mtls-ca/intermediate.key; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo chmod 0600 /etc/mtls-ca/intermediate.key` | `/etc/mtls-ca/intermediate.key: 権限が緩すぎる（0640）…` (permissions too loose) and exit code 1 | |
| CA-06 | `sudo chmod 0644 /etc/mtls-ca/eab.json; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo chmod 0600 /etc/mtls-ca/eab.json` | `eab_file: /etc/mtls-ca/eab.json: 権限が緩すぎる（0644）…` (permissions too loose) and exit code 1 | |
| CA-07 | `sudo mv /etc/mtls-ca/eab.json /etc/mtls-ca/eab.json.bak; sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?; sudo mv /etc/mtls-ca/eab.json.bak /etc/mtls-ca/eab.json` | `eab_file: stat /etc/mtls-ca/eab.json: no such file or directory…` and exit code 1 | |
| CA-08 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/domain.yaml; echo $?` | `policy.allowed_domains の "example.org" が中間 CA の名前制約 [internal.example.com] の範囲外` (outside the intermediate's name constraints) and exit code 1 | |
| CA-09 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/validity.yaml; echo $?` | `cert.validity は 10m〜90d` (must be 10m to 90d) and exit code 1 | |
| CA-10 | `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/url.yaml; echo $?` | `external_url "http://..." は https://ホスト[:ポート] の形にする` (must be https://host[:port]) and exit code 1 | |

### Source address restriction (CA-11)

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| CA-11 | In one terminal run `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/test/cidr.yaml`; in a second terminal run `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/acme/directory`. Then press Ctrl+C in the first terminal | `403`. The CA log shows 「許可されていない送信元からの接続を拒否」 (connection from a disallowed source refused; the source `127.0.0.1` is not in `10.0.0.0/8`) | |

Then restart with the original configuration.

```sh
sudo rm -rf /etc/mtls-ca/test
sudo systemctl start mtls-ca && systemctl is-active mtls-ca     # active
```

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| CA-12 | Start a second instance while the CA is running: `sudo -u mtls-ca mtls-ca -config /etc/mtls-ca/config.yaml; echo $?` | After a few seconds, `データベースを開けない（別の mtls-ca が動いていないか確認する）: timeout` (cannot open the database; check that no other mtls-ca is running), exit code 1 (no double start). The running CA is unaffected (`systemctl is-active mtls-ca` shows `active`) | |

## 3. mtls-agent

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| AG-01 | `sudo systemctl enable --now mtls-agent@web1 mtls-agent@app1`, then after a few seconds `journalctl -u mtls-agent@web1 -n 10 --no-pager` (same for app1) | In order: 「アカウント鍵を作成した」 (account key created) → 「CA にアカウントを登録した」 (registered with the CA) → 「証明書を更新した」 (certificate renewed) → 「更新後のコマンドを実行した」 (post-renewal command ran) | |
| AG-02 | `sudo ls -l $W` | `ca.pem`, `cert.pem`, `chain.pem`, `fullchain.pem`, `key.pem` and `renewed` exist. Only `key.pem` is `-rw-------` (0600); the owner is `mtls-agent` | |
| AG-03 | `mtlsctl inspect $W/cert.pem` | `Subject: CN=web1.internal.example.com`, `Issuer: CN=Test mTLS CA`, DNS names `[web1.internal.example.com]`, usage `serverAuth, clientAuth`, a lifetime of about 15 minutes | |
| AG-04 | `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml; echo $?` | Status `正常` (OK), the planned renewal (`更新予定`) about 10 minutes after issuance, exit code 0 | |
| AG-05 | `sudo systemctl restart mtls-agent@web1`, then `journalctl -u mtls-agent@web1 -n 3 --no-pager` | Only 「mtls-agent を起動した」 (started); no new certificate is fetched (the current one is valid) | |
| AG-06 | `sudo systemctl reload mtls-agent@web1` (renew now), then `journalctl -u mtls-agent@web1 -n 3 --no-pager` and `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml` | 「証明書を取得する reason=手動での更新要求」 (fetching; manual request) → 「証明書を更新した」. The serial in `check` differs from AG-04 | |
| AG-07 | Wait 10 minutes after AG-06 (the `更新予定` time in `check`), then `journalctl -u mtls-agent@web1 -n 3 --no-pager` | 「証明書を取得する reason=更新時期を過ぎた」 (renewal time passed) → 「証明書を更新した」 → 「更新後のコマンドを実行した」, without any action | |

While waiting for AG-07 you can go ahead with AP-01 to AP-08 in 4.

### app2's certificate (fetched once)

app2 is not run as a service; `renew` fetches its certificate once (run as root, so it can open port 80).

```sh
sudo install -d -m 0700 /var/lib/mtls-agent-app2
sudo mtls-agent renew -config /etc/mtls-agent-app2/config.yaml; echo $?
```

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| AG-08 | The `renew` above | 「CA にアカウントを登録した」 → 「証明書を更新した」, exit code 0. `sudo ls $P` shows the certificate | |
| AG-09 | Request web1's name with app2's EAB key: `sudo sed 's/names: .*/names: ["web1.internal.example.com"]/' /etc/mtls-agent-app2/config.yaml \| sudo tee /etc/mtls-agent-app2/bad-name.yaml >/dev/null; sudo mtls-agent renew -config /etc/mtls-agent-app2/bad-name.yaml; echo $?` | `rejectedIdentifier: "web1.internal.example.com" はこのアカウント（EAB 鍵）には許可されていない` (not allowed for this account's EAB key), exit code 1 | |
| AG-10 | Likewise with `names: ["app2.example.org"]` (`bad-domain.yaml`) and `renew` | `rejectedIdentifier: "app2.example.org" はこの CA で発行できるドメインの範囲外` (outside the domains this CA issues), exit code 1 | |
| AG-11 | `sudo mv $P/cert.pem $P/cert.pem.bak; sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml; echo $?; sudo mv $P/cert.pem.bak $P/cert.pem` | Status `更新が必要 – 証明書が無い、または読めない` (renewal needed; certificate missing or unreadable), exit code 1 (usable for monitoring) | |

After AG-09 and AG-10, remove the broken configurations: `sudo rm /etc/mtls-agent-app2/bad-*.yaml`

### While the CA is down (AG-12)

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| AG-12 | `sudo systemctl stop mtls-ca` → `sudo systemctl reload mtls-agent@app1` → `journalctl -u mtls-agent@app1 -n 2 --no-pager` → `sudo systemctl start mtls-ca` → wait about a minute → `journalctl -u mtls-agent@app1 -n 3 --no-pager` | While stopped: 「証明書を取得できない（再試行する）」 (cannot fetch; will retry) `… connection refused … retry_in=…`. After the CA starts, the retry logs 「証明書を更新した」. The existing certificate keeps working meanwhile | |

## 4. Application integration

### Go applications (`mtls` library)

In another terminal, start the Go server example with web1's certificate and leave it running (only app1 is allowed).

```sh
cd ~/mtls-test
sudo ./bin/server -addr 127.0.10.2:8443 -cert /etc/mtls-agent-web1/tls/fullchain.pem \
  -key /etc/mtls-agent-web1/tls/key.pem -ca /etc/mtls-agent-web1/tls/ca.pem -allow app1.internal.example.com
```

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| AP-01 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca $A/ca.pem https://web1.internal.example.com:8443/` | `hello, [app1.internal.example.com]` (the server returns the verified peer name) | |
| AP-02 | `sudo curl --noproxy '*' -sS --cacert $A/ca.pem --cert $A/fullchain.pem --key $A/key.pem https://web1.internal.example.com:8443/` | `hello, [app1.internal.example.com]` | |
| AP-03 | `curl --noproxy '*' -sS --cacert $A/ca.pem https://web1.internal.example.com:8443/` (no client certificate) | Fails with `alert certificate required`. The server log shows `client didn't provide a certificate` | |
| AP-04 | `sudo curl --noproxy '*' -sS --cacert $P/ca.pem --cert $P/fullchain.pem --key $P/key.pem https://web1.internal.example.com:8443/` (app2) | Fails with `alert bad certificate`. The server log shows `mtls: 相手 [app2.internal.example.com] は許可されていない` (peer not allowed): a valid certificate from the same CA is still refused unless the peer is allowed | |
| AP-05 | `curl --noproxy '*' -sS --cacert $A/ca.pem --cert fake/app1.crt --key fake/app1.key https://web1.internal.example.com:8443/` ("app1" from another root CA) | Fails with `alert unknown ca`. The server log shows `certificate signed by unknown authority` | |
| AP-06 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca fake/fake-root.crt https://web1.internal.example.com:8443/` (the client trusts only the other root) | Fails with `x509: certificate signed by unknown authority` (the client verifies the server too) | |
| AP-07 | `sudo ./bin/client -cert $A/fullchain.pem -key $A/key.pem -ca $A/ca.pem https://127.0.10.2:8443/` (connect by address) | Fails with `cannot validate certificate for 127.0.10.2 because it doesn't contain any IP SANs` (connect by name) | |
| AP-08 | Define the function below to see the serial the server presents. Renew with `sudo systemctl reload mtls-agent@web1`, wait at least 30 seconds and look again (without restarting the server).<br>`ser() { sudo openssl s_client -connect 127.0.10.2:8443 -servername web1.internal.example.com -cert $A/fullchain.pem -key $A/key.pem -CAfile $A/ca.pem </dev/null 2>/dev/null \| openssl x509 -noout -serial; }` | The serial changes (the `mtls` library checks the files every 30 seconds and switches without a restart). The new serial matches the one from `sudo mtls-agent check -config /etc/mtls-agent-web1/config.yaml` | |

### nginx

```sh
sudo nginx -t && sudo systemctl restart nginx
```

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| AP-09 | `sudo curl --noproxy '*' -sS -w '%{http_code}\n' --cacert $A/ca.pem --cert $A/fullchain.pem --key $A/key.pem https://web1.internal.example.com:9443/` (app1) | `nginx: hello, CN=app1.internal.example.com` and `200` | |
| AP-10 | AP-09 with app2 (`$A` → `$P`) | `403` (TLS verification passes, but the peer is not allowed) | |
| AP-11 | `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert $A/ca.pem https://web1.internal.example.com:9443/` (no client certificate) | `400` (No required SSL certificate was sent) | |
| AP-12 | `curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' --cacert $A/ca.pem --cert fake/app1.crt --key fake/app1.key https://web1.internal.example.com:9443/` (another root CA) | `400` (The SSL certificate error) | |

nginx needs a reload to pick up new certificates (in production use `deploy/systemd/mtls-reload-nginx.path`; see [getting started 6.](getting-started.md#nginx)).
This test does not reload on every renewal, so **run `sudo systemctl reload nginx` before every nginx item (AP-09 to AP-12, RV-03, RV-07)**.
The web1 certificate nginx loaded expires in 15 minutes; without a reload, curl fails on the expired server certificate (`certificate has expired`, `%{http_code}` is `000`) before reaching the result being tested.

## 5. Revocation and EAB key revocation

Treat app2 as a decommissioned server: revoke its EAB key and revoke its certificate.

| ID | Steps | Expected result | Result |
| --- | --- | --- | --- |
| RV-01 | Find app2's kid with `sudo mtlsctl eab list -file /etc/mtls-ca/eab.json`, then `sudo mtlsctl eab revoke -file /etc/mtls-ca/eab.json -kid <app2's kid>` | 「EAB 鍵 … を取り消した。この鍵で登録したサーバは、以後新しい証明書を取得できない」 (revoked; servers registered with it can no longer get certificates). app2 disappears from `eab list` | |
| RV-02 | `sudo mtls-agent renew -config /etc/mtls-agent-app2/config.yaml -force; echo $?` | `403 urn:ietf:params:acme:error:unauthorized: このアカウントの EAB 鍵は取り消されている` (this account's EAB key has been revoked), exit code 1 (applied without restarting the CA) | |
| RV-03 | After `sudo systemctl reload nginx`, run AP-10 again | Still `403` (TLS verification passes): certificates already issued remain usable until they expire | |
| RV-04 | Stop the CA and revoke app2's certificate:<br>`sudo systemctl stop mtls-ca`<br>`sudo -u mtls-ca mtls-ca certs -config /etc/mtls-ca/config.yaml`<br>`sudo -u mtls-ca mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <app2's serial> -reason 1`<br>`sudo systemctl start mtls-ca` | `certs` lists the issued certificates (use the SERIAL of app2's row). 「証明書 … を失効させた。mtls-ca を起動すると CRL に反映される」 (revoked; reflected in the CRL when mtls-ca starts) | |
| RV-05 | `curl --noproxy '*' -sS --cacert /etc/mtls-ca/root.crt https://ca.internal.example.com:8443/crl -o crl.der && openssl crl -inform DER -in crl.der -out crl.pem && openssl crl -in crl.pem -noout -text` | `Revoked Certificates:` lists app2's serial with `CRL Reason Code: Key Compromise` | |
| RV-06 | `for c in $A $P; do sudo openssl verify -crl_check -CAfile $c/ca.pem -untrusted $c/chain.pem -CRLfile crl.pem $c/cert.pem; done` | app1 is `OK`; app2 is `certificate revoked` | |
| RV-07 | After app2's certificate expires (the `有効期限` (expiry) in `sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml`), run `sudo systemctl reload nginx` and AP-10 again, then `sudo mtls-agent check -config /etc/mtls-agent-app2/config.yaml; echo $?` | AP-10 returns `400` (expired certificates fail TLS verification). `check` shows `更新が必要 – 有効期限が切れている` (renewal needed; expired), exit code 1 | |

> **Note**: the `mtls` library and mtls-agent do not check the CRL ([operations guide](operations.md#revoking-a-certificate)).
> After revocation, Go applications (as in AP-01) keep accepting the certificate until it expires. In urgent cases, remove the peer from the allow list (`AllowedPeers`).
> For nginx's `ssl_crl`, see [7. Known limitations](#7-known-limitations).

## 6. Cleanup

```sh
sudo systemctl disable --now mtls-agent@web1 mtls-agent@app1 mtls-ca
sudo rm -f /etc/systemd/system/mtls-agent@.service /etc/systemd/system/mtls-ca.service
sudo systemctl daemon-reload
sudo rm -f /etc/nginx/conf.d/mtls-test.conf && sudo systemctl restart nginx   # to restore the default site, recreate the sites-enabled/default link
sudo rm -rf /etc/mtls-ca /var/lib/mtls-ca /etc/mtls-agent-web1 /etc/mtls-agent-app1 /etc/mtls-agent-app2 \
            /var/lib/mtls-agent-web1 /var/lib/mtls-agent-app1 /var/lib/mtls-agent-app2
sudo rm -f /usr/local/bin/mtlsctl /usr/local/bin/mtls-ca /usr/local/bin/mtls-agent
sudo userdel mtls-ca; sudo userdel mtls-agent
sudo sed -i '/# mtls_manager test environment/,/app2.internal.example.com/d' /etc/hosts
rm -rf ~/mtls-test        # this also deletes the test root CA key (offline/root.key)
```

Stop the Go server example with Ctrl+C in its terminal.

## 7. Known limitations

- **nginx's `ssl_crl` cannot be used with this CA's CRL alone.** When a CRL is configured, nginx requires CRLs for every level of the chain (including the root CA level that issued the intermediate).
  mtls-ca publishes only the intermediate CA's CRL; there is no root CA CRL. As a result, setting the CA's CRL in `ssl_crl` makes
  every connection fail with `400` (error.log: `unable to get certificate CRL`), including certificates that are not revoked.
  To work around it, create an empty root CA CRL (one that revokes no intermediate) with the root CA key on the offline machine, and put it in one file together with the CA's CRL. The root CA CRL also expires, so it must be recreated regularly. `mtlsctl` cannot do this yet; a command to create the root CA CRL (such as `mtlsctl root crl`) is future work.
  Check revocation with openssl as in RV-05 and RV-06.

## Summary of results

| Section | Items | Passed | Failed | Notes |
| --- | --- | --- | --- | --- |
| 2. CA server | CA-01 to CA-12 | | | |
| 3. mtls-agent | AG-01 to AG-12 | | | |
| 4. Application integration | AP-01 to AP-12 | | | |
| 5. Revocation and EAB key revocation | RV-01 to RV-07 | | | |

Version tested (`git -C ~/mtls-test/src rev-parse --short HEAD`): ________  Date: ________  Tester: ________
