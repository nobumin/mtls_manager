# mtls_manager playground

[日本語](README.md)

With nothing but Docker, try **mTLS between two servers on a private network**, from installation to removal.
mtls_manager issues, distributes and renews the certificates automatically, and you can watch it happen in the admin UI.

```
                    Docker private network (playground.internal)
  ┌────────────────────────────────────────────────────────────────────────────┐
  │                                                                            │
  │   ┌──────────────────┐   certificate issuance    ┌──────────────────────┐  │
  │   │ mtls-manager     │ ◀──────── (ACME) ──────── │ server-a             │  │
  │   │  mtls-ca         │                           │  Go application      │  │
  │   │  (CA, admin UI)  │ ◀──────────┐              │  + mtls-agent        │  │
  │   └────────┬─────────┘            │              └──────────┬───────────┘  │
  │            │ 9443                 │                         │ mTLS ⇅       │
  │            │                      │              ┌──────────┴───────────┐  │
  │            │                      └───────────── │ server-b             │  │
  │            │                                     │  nginx + mtls-agent  │  │
  │            │                                     └──────────────────────┘  │
  └────────────┼───────────────────────────────────────────────────────────────┘
               │ 127.0.0.1:9443 (only the admin UI is visible from your PC)
          The browser on your PC
```

| Container | Name (inside the network) | Runs |
| --- | --- | --- |
| `mtls-manager` | `ca.playground.internal` | `mtls-ca` (ACME: port 8443, admin UI: port 9443) |
| `server-a` | `server-a.playground.internal` | Go application (`mtls` library, `GET /hello` on port 8443) + `mtls-agent` |
| `server-b` | `server-b.playground.internal` | nginx (`GET /hello` on port 8443) + `mtls-agent` |

- server-a allows **only server-b** to connect, and server-b allows **only server-a**.
- Port 8443 of server-a and server-b is not published to your PC (private network only).

> **This is a setup for trying things out. Do not use it in production.** To keep the steps short, the root CA key (which belongs on an
> offline machine in production) is created inside the `mtls-manager` container, every container runs as root, and each application runs
> in the same container as its mtls-agent. For a production setup, see the [getting started guide](../en/getting-started.md) and the
> [operations design guide](../en/operations-design.md).

## Requirements

| Item | Details |
| --- | --- |
| Docker | Docker Desktop (macOS, Windows) or Docker Engine (Linux), with `docker compose` (v2 or later) |
| Shell | bash (as is on macOS and Linux; on Windows, run inside WSL2) |
| Browser | To open the admin UI (Chrome, Edge, Firefox or Safari) |
| Free port | `127.0.0.1:9443` on your PC (admin UI) |
| Network | The first build downloads from Docker Hub, Debian package mirrors and the Go module proxy |

It takes about 10 minutes, including the first build.

## Overview

Run the following in this directory (`docs/playground/`), in order.

| Step | Command | What it does |
| --- | --- | --- |
| [1. Start](#1-start) | `docker compose up -d --build` | Build and start the three containers |
| [2. Set up](#2-set-up) | `./setup.sh` | Create the CA and give each server a certificate |
| [3. Check](#3-check-that-it-works) | `./check.sh` | Check mTLS between server-a and server-b |
| [4. Admin UI](#4-open-the-admin-ui) | Browser | See the issued certificates, EAB keys and logs |
| [6. Clean up](#6-clean-up) | `docker compose down -v --rmi local` | Remove everything |

## 1. Start

```bash
git clone https://github.com/nobumin/mtls_manager.git
```

```bash
cd mtls_manager/docs/playground
```

```bash
docker compose up -d --build
```

The first build takes a few minutes. When it has started, check the state:

```bash
docker compose ps
```

If all three are `Up`, it worked. There is no CA and no certificate yet (each container is waiting for the setup).

```bash
docker compose logs
```

If you see `setup.sh を実行すると、…` ("run setup.sh to …"), go on to the next step.

> The programs log in Japanese only (v0.x). The meaning of the messages you see in this guide is given in parentheses.

## 2. Set up

```bash
./setup.sh
```

It takes about 10 seconds and ends with `初期設定が終わった。` (setup finished). `setup.sh` does the following:

| Stage | What it does |
| --- | --- |
| 1/5 | Create a root CA and an intermediate CA. The intermediate has a name constraint (`playground.internal`), so it cannot issue certificates for names outside it |
| 2/5 | Create EAB keys (per-server permission to obtain certificates). Each key allows exactly one name, e.g. server-a's key allows only `server-a.playground.internal` |
| 3/5 | Start the CA (`mtls-ca`) with its admin UI |
| 4/5 | Put the mtls-agent configuration on server-a and server-b. Each container's mtls-agent registers with the CA, proves ownership (http-01), obtains its certificate and starts the application (Go application / nginx) |
| 5/5 | Obtain the administrator's certificate and write the files for your browser to `out/` |

`out/` then contains the following files (they are not part of the repository):

| File | Contents |
| --- | --- |
| `out/admin.p12` | The administrator's certificate and key (import into your browser; password `playground`) |
| `out/root.crt` | The root CA certificate (have your browser / OS trust it) |
| `out/admin.crt` / `out/admin.key` | The administrator's certificate and key (to open the admin UI with curl) |

You can follow each server in its log:

```bash
docker compose logs server-a server-b
```

You will see `CA にアカウントを登録した` (registered an account with the CA) → `証明書を更新した` (renewed the certificate) →
`証明書ができた。アプリを起動する` (certificate ready; starting the application).

## 3. Check that it works

```bash
./check.sh
```

It checks the following six items and ends with `6 件すべて合格` (all 6 passed) on success.

| Check | Expected result |
| --- | --- |
| server-a → server-b (nginx) | `hello from server-b (nginx), client=CN=server-a.playground.internal` |
| server-b → server-a (Go) | `hello, [server-b.playground.internal]` |
| No certificate → server-b | nginx returns `400` (no client certificate) |
| No certificate → server-a | Refused in the TLS handshake |
| Administrator's certificate → server-b | nginx returns `403` (a valid certificate from the same CA, but not an allowed peer) |
| Administrator's certificate → server-a | Refused in the TLS handshake (same reason) |

You can also try them one at a time with curl. To call server-b from server-a:

```bash
docker compose exec server-a curl --cacert /etc/mtls-agent/tls/ca.pem --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem https://server-b.playground.internal:8443/hello
```

To call server-a from server-b:

```bash
docker compose exec server-b curl --cacert /etc/mtls-agent/tls/ca.pem --cert /etc/mtls-agent/tls/fullchain.pem --key /etc/mtls-agent/tls/key.pem https://server-a.playground.internal:8443/hello
```

Remove the certificate (`--cert` / `--key`) to see both refuse the connection.

## 4. Open the admin UI

The admin UI has no passwords: you log in with **a client certificate issued by this CA (mTLS)**.
To open it in a browser, do the following three things once.

### 4-1. Add the name to hosts

The CA's own server certificate is for `ca.playground.internal`, so make that name reach `127.0.0.1`.

On macOS and Linux:

```bash
echo "127.0.0.1 ca.playground.internal" | sudo tee -a /etc/hosts
```

On Windows, run Notepad as administrator and add `127.0.0.1 ca.playground.internal` to the end of `C:\Windows\System32\drivers\etc\hosts`.

### 4-2. Import the administrator's certificate and the root CA into your browser

Import `out/admin.p12` (password `playground`) and `out/root.crt`.

| Environment | `out/admin.p12` (administrator's certificate) | `out/root.crt` (root CA) |
| --- | --- | --- |
| macOS (Chrome, Safari, Edge) | Double-click it and add it to the "login" keychain in Keychain Access | Double-click it to add it, open it in Keychain Access and set "Trust" → "Always Trust" |
| Windows (Chrome, Edge) | Double-click it and, in the Certificate Import Wizard, put it in "Current User" → "Personal" | Double-click → "Install Certificate" → "Current User" → "Trusted Root Certification Authorities" |
| Firefox (any OS) | Settings → "Privacy & Security" → "View Certificates" → "Your Certificates" → "Import" | Same dialog, "Authorities" → "Import" → "Trust this CA to identify websites" |
| Linux (Chrome) | Settings → "Privacy and security" → "Security" → "Manage certificates" → "Your certificates" → "Import" | Same screen, "Authorities" → "Import" |

> If you would rather not trust the root CA, skip importing `out/root.crt` and click through the browser's warning page
> (importing the administrator's certificate is still required).

### 4-3. Open it

Open the following in your browser:

```
https://ca.playground.internal:9443/
```

When asked to choose a certificate, pick `admin.admins.playground.internal`. You can see these pages:

| Page | What you see |
| --- | --- |
| Overview | Numbers of valid certificates, EAB keys and accounts; root and intermediate CA expiry and name constraints; CA settings |
| Issued certificates | The certificates of server-a, server-b and the administrator (serials, expiry). You can also revoke them here |
| EAB keys | Per-server permissions (the names each can obtain). You can also issue and revoke them here |
| Logs | The CA's log (issuance, ownership checks, admin UI operations) |

The admin UI is in Japanese only (v0.x). You can also open it with curl, without a browser (the hosts entry from 4-1 is needed):

```bash
curl --cacert out/root.crt --cert out/admin.crt --key out/admin.key https://ca.playground.internal:9443/
```

## 5. Try a little more

### Certificate renewal

Certificates are valid for 24 hours, and mtls-agent renews them automatically when one third of the lifetime is left. To renew right away:

```bash
docker compose exec server-b mtls-agent renew -force -config /etc/mtls-agent/config.yaml
```

You will see `証明書を更新した` (renewed the certificate) → `更新後のコマンドを実行した` (ran the post-renewal command: an nginx reload). To check the state:

```bash
docker compose exec server-b mtls-agent check -config /etc/mtls-agent/config.yaml
```

The serial changes, and the new certificate also appears under "Issued certificates" in the admin UI. server-a (the Go application) uses its new
certificate without a restart (the `mtls` library checks the files every 30 seconds).

### It survives restarts

```bash
docker compose restart
```

The CA, keys, certificates and configuration live in Docker volumes, so everything keeps working after a restart. Run `./check.sh` again to see.

### Revoking a server

Revoke server-b's key under "EAB keys" in the admin UI, and server-b can no longer obtain new certificates (the `renew -force` above is refused).
You can also revoke a certificate under "Issued certificates".

> mtls_manager limits exposure with short certificate lifetimes. Even a revoked certificate is accepted by the Go application and nginx until it
> expires ([operations guide](../en/operations.md#revoking-a-certificate)). After revoking, start over from 6. Clean up to try again.

## 6. Clean up

Remove the containers, the volumes (CA, keys, certificates) and the images that were built:

```bash
docker compose down -v --rmi local
```

Remove the exported files too:

```bash
rm -f out/admin.p12 out/admin.crt out/admin.key out/root.crt
```

Also undo what you did in 4.:

- Remove the `127.0.0.1 ca.playground.internal` line from hosts
- Remove the administrator's certificate (`admin.admins.playground.internal`) and the root CA (`Playground Root CA`) from your browser / OS
  (**do not leave the root CA trusted**)

To try again, start over from [1. Start](#1-start).

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `./setup.sh` stops with `… が動いていない` (… is not running) | Run `docker compose up -d --build` first, and check with `docker compose ps` that all three are `Up` |
| `./setup.sh` stops with `すでに設定済み` (already set up) | The setup runs only once. To start over, run `docker compose down -v`, then `docker compose up -d --build` and `./setup.sh` |
| `./setup.sh` stops with `… を待ったが、… 秒たっても終わらない` (gave up waiting for …) | Look for errors with `docker compose logs mtls-manager server-a server-b` |
| `docker compose up` fails with `port is already allocated` | Stop whatever uses port 9443 on your PC, or change the left side of `127.0.0.1:9443:9443` in `compose.yaml` (the port you open in the browser changes too) |
| The browser does not offer a certificate, or shows `ERR_BAD_SSL_CLIENT_AUTH_CERT` | Check that you imported `out/admin.p12`, and restart the browser |
| The browser cannot find `ca.playground.internal` | Check the hosts entry from 4-1 |
| After rebuilding the environment you cannot get into the admin UI (certificate error) | Rebuilding creates a new root CA. Remove the old administrator's certificate and root CA from your browser / OS, and import the new `out/admin.p12` and `out/root.crt` |
| `./setup.sh` fails with `Permission denied` | Run `chmod +x setup.sh check.sh` |
