# Operations guide

[日本語](../ja/operations.md)

## Adding a server

1. Create an EAB key on the CA server.

   ```sh
   sudo mtlsctl eab create -file /etc/mtls-ca/eab.json -names web2.internal.example.com -note "web2" -hmac-out ./web2.hmac
   ```

2. Copy `root.crt` and `web2.hmac` to web2 and start mtls-agent as in [getting started, step 5](getting-started.md#5-start-mtls-agent-on-each-server).

No CA restart is needed (changes to the EAB key file are picked up automatically).

With `admin.operators` configured, you can also issue keys from the "EAB keys" page of the admin UI (the HMAC key is shown once, right after issuing; see [operations design guide 9-6](operations-design.md#9-6-changes-from-the-admin-ui)).

## Removing a server (decommissioned or suspected compromise)

```sh
sudo mtlsctl eab list   -file /etc/mtls-ca/eab.json
sudo mtlsctl eab revoke -file /etc/mtls-ca/eab.json -kid <kid>
```

Accounts registered with that EAB key can **no longer obtain new certificates**.
Already issued certificates remain usable until they expire (24 hours by default). To stop them immediately, revoke them as well.
EAB keys can also be revoked from the "EAB keys" page of the admin UI (`admin.operators`).

## Revoking a certificate

```sh
sudo systemctl stop mtls-ca
sudo -u mtls-ca mtls-ca certs  -config /etc/mtls-ca/config.yaml
sudo -u mtls-ca mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <serial> -reason 1
sudo systemctl start mtls-ca
```

Revocations are published in the CRL (`https://ca.internal.example.com:8443/crl`).

From the "Issued certificates" page of the admin UI (`admin.operators`), you can revoke **without stopping the CA**.

Entries that `certs` shows as `未完了` (incomplete) are serials recorded before signing whose issuance did not complete
(e.g. the CA stopped or the disk failed). They were never returned to a client, so exposure is unlikely, but you can revoke them to be safe.

> **Note**: in v0.x neither the `mtls` library nor `mtls-agent` checks the CRL. Revocation only affects software configured to
> read the CRL (e.g. nginx `ssl_crl`). mtls_manager is designed around **short lifetimes** (24 hours by default) instead of revocation.
> In urgent cases, also consider removing the peer from the applications' allowlists (`AllowedPeers`).

A server can also revoke its own certificate with an ACME revocation request (e.g. `lego revoke`).

## Changing certificate names

If the new names are allowed by the EAB key, change `names` in the mtls-agent configuration and run `systemctl restart mtls-agent`
(the configuration is read at startup, so `reload` is not enough; on start the agent detects the name mismatch and re-issues immediately).
For names outside the key's permission, create a new EAB key, delete mtls-agent's `account_key`, and restart with the new `eab.kid` / `eab.hmac_file`.

## Rotating the intermediate CA (before it expires)

The intermediate's default validity is 2 years. mtls-ca logs a warning at startup and daily when fewer than 30 days remain.
Once less than half of the certificate lifetime (`cert.validity`) remains, it **refuses to issue** rather than handing out
ever-shorter certificates (which would make every server re-issue constantly). Rotate before then.
Since the root CA is unchanged, **no work is needed on the servers**.

1. On the CA server, create a new key and CSR in a separate directory.

   ```sh
   sudo install -d -m 0750 -o root -g mtls-ca /etc/mtls-ca/2028
   sudo mtlsctl intermediate csr -out-dir /etc/mtls-ca/2028 -cn "Example mTLS CA 2028"
   sudo chown mtls-ca:mtls-ca /etc/mtls-ca/2028/intermediate.key
   ```

2. Sign it on the offline machine ([getting started, step 3-2](getting-started.md#3-2-offline-machine-sign-it)).
3. Put the certificate in `/etc/mtls-ca/2028/`, update `intermediate_cert` / `intermediate_key` in `config.yaml`, and run `sudo systemctl restart mtls-ca`.

Certificates issued by the old intermediate remain valid until they expire; each server switches to the new intermediate at its next renewal.

## Rotating the root CA

Do this if the root key may have leaked or the root is close to expiring. It touches every server.

1. Create a new root CA on the offline machine.
2. Distribute **a file containing both the old and new roots** as `ca_root` to mtls-agent on every server
   (mtls-agent also writes both roots to `output.ca`, so applications trust both).
3. Create an intermediate under the new root and switch the CA server to it.
4. Once every server's certificate has been renewed under the new root (after one day by default), remove the old root from each `ca_root`.

## Federating with another organization

Connect, with mTLS, servers **managed by separate mtls-cas (separate root CAs)**, such as company A's and company B's servers.
Each side trusts the other's root CA **only for names within the other's scope (domains)**. See the [federation design](federation-design.md) for details.

Prerequisites:

- A and B use different domains (e.g. `a.example.com` for A and `b.example.net` for B)
- Each organization's intermediate has name constraints (`mtlsctl intermediate sign -permitted-domain`). Federation cannot be used with an intermediate without name constraints

### 1. Enable federation on the CA (both organizations)

Add the following to `config.yaml` and restart mtls-ca.

```yaml
federation:
  file: "/etc/mtls-ca/federation.json"
```

### 2. Exchange federation records (both organizations)

```sh
sudo mtlsctl federation export -config /etc/mtls-ca/config.yaml -org "Company A" -contacts security@a.example.com -out a.json
```

Give `a.json` to the partner (it contains no secrets, so email is fine). Import the partner's `b.json`:

```sh
sudo mtlsctl federation import -config /etc/mtls-ca/config.yaml -in b.json -id b-corp
```

`-id` is an identifier you choose (lowercase letters, digits, hyphens; used in file names).

### 3. Compare the fingerprint and approve with two people

1. Read the **whole fingerprint (64 digits)** aloud with **a partner contact you already know independently of the file** (the contact in the contract, etc.)
   over **a channel other than the file's** (phone, in person). Do not use the contacts written in the file; they are the partner's unverified claims
2. The first admin requests approval (typing the fingerprint while hearing it read aloud):

   ```sh
   sudo mtlsctl federation request -config /etc/mtls-ca/config.yaml -id b-corp \
     -compared-with "Mr./Ms. X, IT department of Company B named in the contract; phone" -by alice
   ```

   Add `-domains api.b.example.net` to narrow the scope (it cannot exceed the partner's declaration).
3. **Another** admin approves (typing the fingerprint again):

   ```sh
   sudo mtlsctl federation approve -config /etc/mtls-ca/config.yaml -id b-corp -by bob
   ```

The partner approves A the same way (traffic flows **only after both sides approve**).
`mtlsctl federation list -config ... [-id b-corp]` shows the state and the record of operations.

> In the stage 1 CLI, the `-by` name is self-declared (two-person approval only checks that the names differ).
> Restrict who can log in to the CA server and review the record of operations (`federation list -id`) regularly.

### 4. Receive partners with mtls-agent on each server

Add the outputs (and, for nginx etc., the post-update command) to the mtls-agent configuration and restart it.

```yaml
output:
  trust_bundle: "/etc/mtls-agent/tls/trust-bundle.jws"   # for the mtls library
  federation_dir: "/etc/mtls-agent/federation"           # for nginx etc. (<id>.pem / <id>.domains)
hooks:
  post_bundle: ["/bin/sh", "-c", "nginx -t && systemctl reload nginx"]
```

mtls-agent fetches the trust bundle from the CA every minute by default, verifies its signature and contents, and writes it out.

### 5. Accept partners in applications

- **Go (`mtls` library)**: add `TrustBundleFile`, and add the partner's server names to `AllowedPeers`. Use the fullchain for `CertFile`.

  ```go
  cfg, err := mtls.NewServerTLSConfig(mtls.Config{
      CertFile: "/etc/mtls-agent/tls/fullchain.pem", KeyFile: "/etc/mtls-agent/tls/key.pem",
      CAFile: "/etc/mtls-agent/tls/ca.pem", TrustBundleFile: "/etc/mtls-agent/tls/trust-bundle.jws",
      AllowedPeers: []string{"app1.a.example.com", "web1.b.example.net"},
  })
  ```

- **nginx etc.**: they cannot check scopes, so **use a separate port for connections from the partner**, trust only
  `federation_dir/<id>.pem` (that partner's root CA) there, and allow the partner's names as **exact names** (no wildcards).
  At setup and after a suspension, confirm that `nginx -t` passes and that connections from the partner are rejected after the reload.

### 6. Suspend a federation

```sh
sudo mtlsctl federation suspend -config /etc/mtls-ca/config.yaml -id b-corp -reason "suspected compromise" -by carol
```

One person can suspend immediately. Servers receive it within 1 minute by default, and the PEM in `federation_dir` is replaced with a "PEM that chains to nothing".
**If traffic between the CA and the servers is blocked, trust may remain until the trust bundle expires (2 days by default) in the worst case.**
In urgent cases, also remove the partner's names from each application's `AllowedPeers` (the allowlist for nginx).
Resuming requires the comparison and two-person approval again (step 3). Remove a partner that is no longer needed with `mtlsctl federation remove`.

### Monitoring

`mtls-agent check` returns exit code 1 when the trust bundle has expired, has less than 1 day left, or the post-update command keeps failing.
When a federation expiry (1 year by default) is less than 30 days away, mtls-ca logs a warning; redo the comparison and approval before then.

## Backup

| Item | Location | Notes |
| --- | --- | --- |
| Root CA key | Offline machine | Two copies on encrypted media, stored apart from the CA server |
| Intermediate key and certificate | `/etc/mtls-ca/` | If lost, create a new intermediate (no work on the servers) |
| EAB key file | `/etc/mtls-ca/eab.json` | If lost, every server's EAB key must be re-issued |
| Federation records file (federation) | `/etc/mtls-ca/federation.json` | Partners and approval records. If lost, comparison and approval must be redone (contains no secrets) |
| Database | `/var/lib/mtls-ca/` | Accounts and issuance history. Copy while mtls-ca is stopped. If lost, servers must re-register |

Backups contain private keys. Encrypt them and restrict access.

## Monitoring

- With the admin UI enabled (`admin.listen`), you can check CA certificate expiry, late renewals and recent logs in a browser
  (see the [operations design guide](operations-design.md#9-admin-web-ui)).
- `mtls-agent check -config ...` returns **exit code 1** when renewal is needed (expired, overdue, name mismatch, etc.).
  Run it periodically from your monitoring system.
- `https://ca.internal.example.com:8443/healthz` reports CA liveness.
- Main log messages (currently in Japanese):

  | Message | Meaning |
  | --- | --- |
  | `証明書を発行` (mtls-ca) | Certificate issued (serial, names, EAB key) |
  | `所有確認に失敗` (mtls-ca) | Validation failed (check ports, name resolution, firewall) |
  | `許可されていない送信元からの接続を拒否` (mtls-ca) | Connection from outside `allowed_client_cidrs` |
  | `証明書を取得できない（再試行する）` (mtls-agent) | Issuance failed; the reason follows |
  | `更新後のコマンドが失敗した` (mtls-agent) | Certificate renewed, but `hooks.post_renew` failed |
  | `取得した直後なのに更新が必要と判断された` (mtls-agent) | Something is wrong with the configuration or the CA; the agent waits instead of re-issuing in a loop. The reason follows |
  | `中間 CA の有効期限が近い` (mtls-ca) | Rotate the intermediate ([procedure](#rotating-the-intermediate-ca-before-it-expires)) |

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| mtls-ca refuses to start: permissions too open (`権限が緩すぎる`) | `chmod 600` `intermediate.key` / `eab.json` and make mtls-ca the owner |
| mtls-ca cannot open the database (`データベースを開けない`) | Another mtls-ca is running (`certs` / `revoke` require the CA to be stopped) |
| mtls-agent: EAB key invalid (`EAB 鍵が無効`) | Wrong kid, or the key was revoked with `mtlsctl eab revoke` |
| Not allowed for this account (`このアカウント（EAB 鍵）には許可されていない`) | `names` is not covered by the EAB key's `-names` |
| Outside the CA's domains (`この CA で発行できるドメインの範囲外`) | Check `policy.allowed_domains` and the intermediate's name constraints |
| Validation fails with `connection` | Can the CA server reach port 80 (or 443) on the server, and resolve its name? |
| Validation fails with `incorrectResponse` | Is another web server answering on port 80? (use `challenge.webroot`) |
| Cannot open port 80 | Does mtls-agent have `CAP_NET_BIND_SERVICE` (granted in the bundled unit)? Is the port in use? |
| Cannot connect to the CA (`x509: certificate signed by unknown authority`) | Is `ca_root` the right root? Is the host in `ca_url` listed in `hostnames`? |
| CA unreachable when HTTPS_PROXY is set | mtls-agent ignores proxy environment variables. For other clients such as lego, add the CA host to `NO_PROXY` |
