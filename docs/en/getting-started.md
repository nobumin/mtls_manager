# Getting started

[日本語](../ja/getting-started.md)

This guide builds a CA and sets up an mTLS connection between two servers.
The examples use the internal domain `internal.example.com`, the CA server `ca.internal.example.com`
and a server receiving a certificate, `web1.internal.example.com`. Adjust them to your environment.

## 0. Prerequisites

| Item | Details |
| --- | --- |
| Offline machine | Creates and stores the root CA key. Ideally a PC never connected to a network (at least a machine other than the CA server) |
| CA server | A Linux server (macOS also works) running `mtls-ca` |
| Servers | Machines that receive certificates. Their FQDNs must resolve in your internal DNS |
| Network | Servers → CA server on port 8443 (ACME). CA server → servers on port 80 (http-01) or 443 (tls-alpn-01) |
| Go | 1.26 or later (only on the machine where you build the binaries) |

The CA server must also be able to resolve each server's FQDN (it connects to them for validation).

## 1. Get the binaries

```sh
go install github.com/nobumin/mtls_manager/cmd/...@latest
# mtlsctl / mtls-ca / mtls-agent are installed into $(go env GOPATH)/bin
```

For servers with a different OS or CPU, cross-build and copy the binaries:

```sh
git clone https://github.com/nobumin/mtls_manager && cd mtls_manager
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/ ./cmd/...
```

Place them in `/usr/local/bin/` on each server.

## 2. Create the root CA (offline machine)

```sh
mtlsctl root create -out-dir ./offline -cn "Example Internal Root CA" -org "Example"
```

| File | Handling |
| --- | --- |
| `offline/root.key` | **Root CA private key. Never put it on the CA server or anywhere else.** Keep two copies on encrypted media |
| `offline/root.crt` | Root CA certificate (public). Distribute it to the CA server and every server |

By default the key is ECDSA P-384 and the validity is 10 years (`-key-type` / `-validity`).

## 3. Create the intermediate CA

The intermediate key is generated on the CA server and never leaves it. Only the signing happens on the offline machine.

### 3-1. CA server: create a user and directory, then the key and CSR

```sh
sudo useradd --system --home /var/lib/mtls-ca --shell /usr/sbin/nologin mtls-ca
sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca
sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca -cn "Example mTLS CA 2026"
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/intermediate.key
```

Copy `/etc/mtls-ca/intermediate.csr` (not secret) to the offline machine.

### 3-2. Offline machine: sign it

```sh
mtlsctl intermediate sign \
  -root-cert offline/root.crt -root-key offline/root.key \
  -csr intermediate.csr -out intermediate.crt \
  -permitted-domain internal.example.com
```

`-permitted-domain` sets **Name Constraints**: this intermediate can only issue certificates for `internal.example.com` and its subdomains.
It limits the damage if the intermediate key leaks, so always set it (repeatable; the default validity is 2 years).

### 3-3. CA server: install the certificates

Copy `intermediate.crt` and `root.crt` to the CA server.

```sh
sudo install -m 0644 intermediate.crt root.crt /etc/mtls-ca/
```

## 4. Start the CA

### 4-1. Configuration

```sh
sudo install -m 0640 -o root -g mtls-ca examples/ca.example.yaml /etc/mtls-ca/config.yaml
sudo vi /etc/mtls-ca/config.yaml
```

At minimum, adjust the following (see the [configuration reference](configuration.md)):

```yaml
external_url: "https://ca.internal.example.com:8443"
allowed_client_cidrs: ["10.0.0.0/8"]          # sources allowed to connect
policy:
  allowed_domains: ["internal.example.com"]   # domains that may be issued
```

### 4-2. Create the EAB key for the first server

The CA does not start without an EAB key file, so create the first server's key first.

```sh
sudo mtlsctl eab create -file /etc/mtls-ca/eab.json \
  -names web1.internal.example.com -note "web1 (web server)" -hmac-out ./web1.hmac
sudo chown mtls-ca:mtls-ca /etc/mtls-ca/eab.json   # first time only; later updates keep the owner
```

Note the printed `kid` and keep `web1.hmac` (**secret**). This key cannot obtain certificates for names other than those in `-names`.
To share one key among several servers (e.g. a batch fleet), use a pattern such as `-names '*.batch.internal.example.com'`.

### 4-3. Start it (systemd)

```sh
sudo install -m 0644 deploy/systemd/mtls-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-ca
journalctl -u mtls-ca -f
```

The log line `mtls-ca を起動した` ("mtls-ca started") means success. To listen on a port below 1024 such as 443,
enable `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit file.

Files and permissions:

| Path | Owner | Mode |
| --- | --- | --- |
| `/etc/mtls-ca/config.yaml` | root:mtls-ca | 0640 |
| `/etc/mtls-ca/intermediate.key` | mtls-ca | 0600 (refuses to start if looser) |
| `/etc/mtls-ca/eab.json` | mtls-ca | 0600 (refuses to start if looser) |
| `/etc/mtls-ca/intermediate.crt`, `root.crt` | root | 0644 |
| `/var/lib/mtls-ca/` (database) | mtls-ca | 0700 |

## 5. Start mtls-agent on each server

### 5-1. Distribute the root certificate and EAB key

Copy `root.crt` and `web1.hmac` to web1 over a secure channel (e.g. scp).

```sh
sudo useradd --system --home /var/lib/mtls-agent --shell /usr/sbin/nologin mtls-agent
sudo install -d -m 0755 /etc/mtls-agent
sudo install -d -m 0755 -o mtls-agent -g mtls-agent /etc/mtls-agent/tls
sudo install -m 0644 root.crt /etc/mtls-agent/root.crt
sudo install -m 0600 -o mtls-agent -g mtls-agent web1.hmac /etc/mtls-agent/eab.hmac
rm web1.hmac
```

### 5-2. Configuration

```sh
sudo install -m 0644 examples/agent.example.yaml /etc/mtls-agent/config.yaml
sudo vi /etc/mtls-agent/config.yaml
```

```yaml
ca_url: "https://ca.internal.example.com:8443/acme/directory"
eab:
  kid: "(the kid printed in 4-2)"
  hmac_file: "/etc/mtls-agent/eab.hmac"
names: ["web1.internal.example.com"]
challenge:
  type: "http-01"
  listen: ":80"
```

If a web server already uses port 80, set `challenge.webroot` to its document root
(mtls-agent places the response files under `.well-known/acme-challenge/`).

### 5-3. Start it

```sh
sudo install -m 0644 deploy/systemd/mtls-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-agent
journalctl -u mtls-agent -f
```

The log line `証明書を更新した` ("certificate renewed") means success. Check the status with
(exit code 1 if renewal is needed):

```sh
sudo mtls-agent check -config /etc/mtls-agent/config.yaml
```

After the first registration `eab.hmac` is no longer needed; you may delete it and remove `eab.hmac_file` from the configuration.

From then on, mtls-agent renews automatically after two thirds of the lifetime (about 16 hours for a 24-hour certificate).
To renew immediately, run `sudo systemctl reload mtls-agent` (SIGHUP).

## 6. Integrate with applications

Output files:

| File | Contents |
| --- | --- |
| `/etc/mtls-agent/tls/fullchain.pem` | Certificate + intermediate. **Configure applications with this one** |
| `/etc/mtls-agent/tls/key.pem` | Private key |
| `/etc/mtls-agent/tls/ca.pem` | Root CA (used to verify peers) |
| `/etc/mtls-agent/tls/cert.pem` / `chain.pem` | Certificate only / intermediate only |

If the application runs as a different user, let it read the key: create a group shared by mtls-agent and the application,
set `Group=` in `mtls-agent.service` to that group, and set `output.key_mode` to `"0640"`.

### Go applications

```go
import "github.com/nobumin/mtls_manager/mtls"

// Server: require client certificates and allow peers by name
cfg, err := mtls.NewServerTLSConfig(mtls.Config{
	CertFile:     "/etc/mtls-agent/tls/fullchain.pem",
	KeyFile:      "/etc/mtls-agent/tls/key.pem",
	CAFile:       "/etc/mtls-agent/tls/ca.pem",
	AllowedPeers: []string{"app1.internal.example.com"},
})
srv := &http.Server{Addr: ":8443", TLSConfig: cfg, Handler: h}
log.Fatal(srv.ListenAndServeTLS("", ""))

// Client
cfg, err := mtls.NewClientTLSConfig(mtls.Config{
	CertFile: "/etc/mtls-agent/tls/fullchain.pem",
	KeyFile:  "/etc/mtls-agent/tls/key.pem",
	CAFile:   "/etc/mtls-agent/tls/ca.pem",
})
client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
```

Renewed certificates are picked up without a restart. Working examples live in `examples/go/`.

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

nginx needs a reload to pick up new certificates. With `deploy/systemd/mtls-reload-nginx.path`, systemd detects the renewal
and reloads nginx, so mtls-agent needs no permission to control nginx.

```sh
sudo install -m 0644 deploy/systemd/mtls-reload-nginx.{path,service} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mtls-reload-nginx.path
```

### Test with curl

```sh
curl --cacert /etc/mtls-agent/tls/ca.pem \
     --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem \
     https://api.internal.example.com:8443/
```

## macOS

- Put the configuration in e.g. `/usr/local/etc/mtls-agent/config.yaml` and run the agent with the plist in `deploy/launchd/`.

  ```sh
  sudo install -m 0644 deploy/launchd/io.github.nobumin.mtls-agent.plist /Library/LaunchDaemons/
  sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.nobumin.mtls-agent.plist
  sudo launchctl kill HUP system/io.github.nobumin.mtls-agent   # renew now
  ```

- LaunchDaemons run as root by default. To use a dedicated user, add `UserName` to the plist and make sure that user can open
  port 80 (or 443), or use `challenge.webroot`.
- Logs go to the plist's `StandardErrorPath` (`/usr/local/var/log/mtls-agent.log` in the example). Create the directory first.

## Next steps

- [Operations guide](operations.md): adding/removing servers, revocation, intermediate rotation, backup, monitoring
- [Security design](security.md): what is and is not protected
- [Test procedure](test-procedure.md): installation and testing end to end on one Linux machine
