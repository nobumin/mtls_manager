# Operations design guide (detailed)

[日本語](../ja/operations-design.md)

This guide covers what to decide and what to keep in mind when building a real service with mtls_manager.
Step-by-step procedures are in [getting started](getting-started.md) and the [operations guide](operations.md); settings are in the [configuration reference](configuration.md).
This document is for deciding *where things go*, *what is automatic and what is manual*, and *what to do when something stops or leaks*.

## 1. Operating model

| Item | Policy |
| --- | --- |
| Certificate lifetime | **24 hours** (default `cert.validity`). The shorter, the less time a stolen key is usable |
| Renewal | **Fully automatic.** mtls-agent on each server renews at two thirds of the lifetime (about 16 hours) |
| Revocation | A secondary measure. The main safeguards are the short lifetime and stopping the next renewal by revoking the EAB key |
| Notifications | None. Check status through logs and the admin UI |
| Manual work | Creating the root CA, signing intermediates (about every 2 years), adding/removing servers, monitoring |

## 2. Overall architecture

```
            ┌──────────────────────── Internal network (no internet egress) ─────────────────────────────────┐
            │                                                                                               │
 ┌────────┐ │  ┌─────────────────────────┐   8443 (ACME)      ┌──────────────┐   mTLS   ┌──────────────┐    │
 │Offline │ │  │ CA server (dedicated)   │ ◀───────────────── │ Server A     │ ◀──────▶ │ Server B     │    │
 │machine │ │  │  mtls-ca                │ ──────────────────▶ │  mtls-agent  │          │  mtls-agent  │    │
 │root key│ │  │  intermediate & EAB keys│  80 / 443 (valid.) │  app         │          │  nginx etc.  │    │
 └────────┘ │  └───────────┬─────────────┘                    └──────────────┘          └──────────────┘    │
 (signing   │              │ 9443 (admin UI, mTLS)                                                           │
  via USB)  │      ┌───────┴────────┐                                                                       │
            │      │ Admin machine  │ (admin subnet, or via SSH)                                            │
            │      └────────────────┘                                                                       │
            └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 3. Network design

### 3-1. Where to place the CA

**Place it in a private subnet isolated from external networks.** The CA needs no internet access at all
(no external CA, time server or update server. Provide a separate path for OS updates according to your policy).

### 3-2. Required traffic

| From | To | Port | Purpose | Notes |
| --- | --- | --- | --- | --- |
| Servers | CA | 8443/tcp | Obtaining/renewing certificates (ACME) | Restrict with `allowed_client_cidrs` |
| CA | Servers | 80/tcp or 443/tcp | Validation (http-01 / tls-alpn-01) | Used only for a few seconds |
| CA | Internal DNS | 53/udp,tcp | Name resolution for validation | Configurable with `challenge.resolver` |
| Admin machine | CA | 9443/tcp | Admin UI | Restrict with `admin.allowed_cidrs` |
| Admin machine | CA | 22/tcp | Maintenance (SSH) | Via a bastion recommended |
| CA | NTP | 123/udp | Time sync | Internal NTP server |

**Block everything else, inbound and outbound.** In particular, the CA never needs to reach the internet.

### 3-3. Name resolution

- Each server's FQDN (e.g. `web1.internal.example.com`) must resolve in internal DNS, **including from the CA** (it connects for validation).
- The CA's host name (e.g. `ca.internal.example.com`) must resolve from each server.
- Even if internal DNS is hijacked, certificates cannot be obtained without an EAB key (see [security design](security.md)).

### 3-4. Multiple subnets or VPCs

The CA must be able to reach port 80 (or 443) on servers in every subnet for validation. Where that is not possible,
use `challenge.webroot` so an existing web server answers, or add a route.

## 4. CA server design and hardening

| Item | Recommendation |
| --- | --- |
| Purpose | **Dedicated to the CA** (no other applications) |
| Who can log in | As few people as possible. SSH key authentication only, via a bastion |
| Disk | Encrypted (it holds the intermediate key, EAB keys and the database) |
| Service user | Dedicated `mtls-ca` user (the bundled systemd unit is already hardened) |
| File permissions | Private keys and the EAB file must be 0600 (the CA refuses to start otherwise) |
| Time | Synchronize with NTP (certificate validity depends on time) |
| Logs | Keep them in journald or similar and decide a retention period. Audit logs (`category=audit`) go to the same place |
| OS updates | Apply regularly (via the separate path from 3-1) |

## 5. Key and certificate hierarchy

| Type | Location | Default lifetime | Key | How often recreated |
| --- | --- | --- | --- | --- |
| Root CA | **Offline machine** (two copies on encrypted media) | 10 years | ECDSA P-384 | Every 10 years, or on compromise |
| Intermediate CA | CA server | 2 years | ECDSA P-256 | Every 2 years, or on compromise |
| Server certificates | Each server | **24 hours** | ECDSA P-256 (configurable) | Automatic (about every 16 hours) |
| CA's own TLS certificate | In CA memory | 7 days | ECDSA P-256 | Automatic |

- Always give the intermediate **Name Constraints** (`-permitted-domain`). Even if its key leaks, it cannot issue certificates outside the permitted domains.
- Server certificates are valid for both server and client authentication. Wildcard certificates are never issued.

## 6. What is automated

| Task | Automatic / manual | Notes |
| --- | --- | --- |
| Obtaining/renewing server certificates | **Automatic** | mtls-agent. Retries every 30 s to 15 min on failure |
| Replacing certificate files | **Automatic** | Written to a temporary file and renamed (never read half-written) |
| Switching applications (Go library) | **Automatic** | New certificates are used without a restart |
| Switching applications (nginx) | **Automatic** | Reloaded by the bundled `mtls-reload-nginx.path` |
| Switching applications (other) | **Automatic** (needs setup) | Put a reload/restart command in `hooks.post_renew` |
| CA's own TLS certificate | **Automatic** | Re-issued by the intermediate |
| Deleting expired records | **Automatic** | 7 days after expiry |
| Adding a server | Manual | `mtlsctl eab create` (or the admin UI) → deliver the EAB key → start mtls-agent |
| Removing a server | Manual | `mtlsctl eab revoke` (or the admin UI; plus revocation if needed) |
| Rotating the intermediate | Manual (every 2 years) | Needs signing on the offline machine with the root key |
| Rotating the root | Manual (every 10 years) | Distribute old and new roots to every server |
| Monitoring | Manual (periodic checks) | Admin UI, logs, `mtls-agent check` |

## 7. Designing the servers that receive certificates

- Use **one EAB key per server** by default (it is the unit of revocation). To share a key across a group of servers with the same role,
  use a pattern such as `*.batch.internal.example.com` (revoking that key stops all of them).
- Name certificates by FQDN. Decide which peers may connect by name (`AllowedPeers`, nginx `map`).
- Configure applications with `fullchain.pem` (certificate + intermediate).
- If the application runs as a different user than mtls-agent, create a shared group and set `output.key_mode: "0640"`.
- To handle several sets of names on one machine, run one mtls-agent per configuration (use a separate `account_key` file for each).

## 8. Switching between old and new certificates

The flow for 24-hour certificates:

```
 0h            16h (renewal)          24h (old certificate expires)
 |──── old certificate ───────────────|
               |──── new certificate ───────────────────────── 40h ──|
```

- At renewal time, **both the old and new certificates are valid**. Both chain to the same root, and peers only check
  "issued by the same CA, with an allowed name", so **no coordinated switchover is needed**.
- Existing connections continue; new connections use the new certificate.
- If renewal keeps failing, there is **about 8 hours of slack** before the old certificate expires (mtls-agent keeps retrying).

## 9. Admin web UI

### 9-1. Design

- Setting `admin.listen` makes mtls-ca start the admin UI on a port separate from ACME.
- It shows the overview, issued certificates, EAB keys and logs. Admins matching `admin.operators` can also **issue and revoke EAB keys and revoke certificates** ([9-6](#9-6-changes-from-the-admin-ui)). Without it, everyone is read-only.
- **Login is mTLS.** Only client certificates issued by this CA whose names match `admin.allowed_clients` get in. No passwords.
- **Revoked admin certificates cannot get in.** The admin UI runs in the same process as the CA and has the issuance records, so it checks them on every connection without using the CRL. Certificates with no issuance record at this CA are rejected too.
- Every page view and every change is recorded in the **audit log** (`category=audit`, with the admin name, path and source). Connections rejected
  by certificate (none, another CA, a name not allowed) are logged as warnings with source and reason.
- Secrets such as keys and HMACs are never shown (the one exception: the HMAC of a newly issued EAB key is shown once, right after issuing it). No external scripts or styles are loaded (enforced by CSP).
- The logs page shows **recent entries since mtls-ca started** (5000 by default). Use journald or similar for older entries.

### 9-2. Choosing the listen address

| Approach | Settings | How admins connect |
| --- | --- | --- |
| Directly from an admin subnet (recommended) | `listen: "10.0.100.5:9443"` (the CA's admin-subnet address), `allowed_cidrs: ["10.0.100.0/24"]` | `https://ca.internal.example.com:9443/` |
| SSH port forwarding | `listen: "127.0.0.1:9443"` | Open `ssh -L 9443:127.0.0.1:9443 <CA server>`, add `127.0.0.1 ca.internal.example.com` to the admin machine's hosts file, then open `https://ca.internal.example.com:9443/` |

The admin UI's TLS certificate is issued for the CA's host names (`hostnames`), so open it in the browser by that name, not by IP address or `localhost`.

### 9-3. Preparing an admin certificate

1. Choose a name per admin (e.g. `admin1.admins.internal.example.com`), add it to `admin.allowed_clients` and restart mtls-ca.
   **Put admin names in a subdomain separate from the servers (e.g. `admins.internal.example.com`)** (see the note below).
2. Create an EAB key that names it **without a wildcard** (`mtlsctl eab create -names admin1.admins.internal.example.com -note "admin 1"`).
   Certificates for admin names are issued only with EAB keys that permit that exact name.
3. Run mtls-agent on the admin machine (Linux / macOS) to obtain the certificate. The CA must be able to reach port 80 (or 443) on the admin machine.
4. Bundle it as PKCS#12 so the browser can import it:

   ```sh
   openssl pkcs12 -export -in fullchain.pem -inkey key.pem -name "mtls admin" -out admin.p12
   ```

   If the macOS keychain cannot import it, recreate it with `-legacy`.
5. Import `admin.p12` into the browser (or the OS certificate store), and **register the root CA (`root.crt`) as trusted**.

> **Note: keep admin names separate from server names**
> Admin certificates are issued through the same ACME path as server certificates. If a server's EAB key has a wildcard such as
> `*.internal.example.com`, whoever compromises that server could order a certificate for `admin1.internal.example.com`.
> mtls-ca therefore issues certificates for names matching `admin.allowed_clients` **only with EAB keys that permit that exact name without a wildcard**
> (orders with other keys are rejected with `rejectedIdentifier` and audit-logged). Issuing an EAB key from the admin UI also fails if a wildcard
> overlaps an admin name, and at startup mtls-ca warns about existing keys that overlap.
> On top of that, put admin names in a subdomain separate from the servers (e.g. `admins.internal.example.com`) and do not create EAB keys
> with wildcards covering that subdomain (such as `*.admins.internal.example.com`).

### 9-4. 24-hour certificates and browsers

Admin certificates also expire after 24 hours, so **they must be re-imported into the browser daily**. Ways to reduce the effort:

- Put the `openssl pkcs12 -export ...` command above in mtls-agent's `hooks.post_renew` so `admin.p12` is recreated on every renewal
  (pass the password from a file with `-passout file:<path>`). Only the import remains manual.
- Import it only when you need the admin UI (there is no need to stay logged in).

> There is currently no way to give admin certificates alone a longer lifetime (e.g. 7–30 days). It can be added as a feature if needed
> (it trades off against security, so decide the policy first).

### 9-5. Adding and removing admins

- Add: follow 9-3. With a pattern such as `*.admins.internal.example.com` in `admin.allowed_clients`, admins can be added without changing the configuration
  (each admin's EAB key must still name the exact name, e.g. `admin1.admins.internal.example.com`).
- Remove: revoke that admin's certificate (the admin UI's "Issued certificates" page or `mtls-ca revoke`); **the admin is locked out immediately**.
  Also revoke the EAB key (so no new certificate can be obtained) and, if names are listed individually, remove it from `admin.allowed_clients` (takes effect after a restart).

### 9-6. Changes from the admin UI

Admins matching `admin.operators` (who must also be in `admin.allowed_clients`) can do the following.

| Page | Action | Details |
| --- | --- | --- |
| EAB keys | Issue | Enter the allowed names (patterns) and a note. **The HMAC key is shown once, right after issuing** (it cannot be shown again). Copy it, carry it to the server over a secure channel and save it as `eab.hmac_file` (0600) |
| EAB keys | Revoke | Servers registered with that key can no longer obtain new certificates. Already issued certificates remain usable until they expire, so revoke them as well to stop them immediately |
| Issued certificates | Revoke | Choose a reason (unspecified, key compromise, affiliation changed, superseded, cessation of operation) and revoke. It is published in the CRL immediately. **This cannot be undone** |

- Revoking an EAB key or a certificate requires both a confirmation checkbox and a confirmation dialog.
- The EAB key issuing form carries a one-time token. Reloading the page right after issuing (resubmitting the form) never issues a second key.
- Result messages are fixed texts chosen by the server (arbitrary text placed in the URL is not displayed).
- Unlike `mtlsctl eab` / `mtls-ca revoke`, this works **without stopping the CA** (the CLI `mtls-ca revoke` requires the CA to be stopped).
- Every action is audit-logged (admin name, kid, serial, reason). HMAC keys are never logged.
- **To prevent forged requests (CSRF)**, each form carries a per-admin token and cross-site submissions (`Origin` / `Sec-Fetch-Site`) are rejected.
  This is needed because with mTLS the browser attaches the certificate automatically even to requests started by other sites. The token changes
  every time mtls-ca starts, so reload the page after a restart before making changes.
- Keep the number of operators small (e.g. two people responsible for operations). Put view-only staff in `admin.allowed_clients` only.

#### Where to put the EAB key file

Issuing or revoking EAB keys from the admin UI makes mtls-ca rewrite `eab_file`, so **mtls-ca must be able to write to the directory of `eab_file`**
(a temporary file and a lock file are created next to it). Otherwise mtls-ca stops with an error at startup.

The bundled systemd unit makes `/etc` read-only with `ProtectSystem=strict`, so when using `admin.operators` move `eab_file`
to mtls-ca's data directory (`/var/lib/mtls-ca`, writable through the unit's `StateDirectory`).

```sh
sudo systemctl stop mtls-ca
sudo mv /etc/mtls-ca/eab.json /var/lib/mtls-ca/eab.json
sudo rm -f /etc/mtls-ca/eab.json.lock
# config.yaml: eab_file: "/var/lib/mtls-ca/eab.json", and add admin.operators
sudo systemctl start mtls-ca
```

From then on, pass `-file /var/lib/mtls-ca/eab.json` to `mtlsctl eab` as well (using the CLI and the admin UI together is safe; a lock keeps either side's changes from being lost).
Adjust the location in your backups ([14.](#14-backup-and-restore)) accordingly.

## 10. Monitoring

| What | How | Healthy when |
| --- | --- | --- |
| CA liveness | `https://ca.internal.example.com:8443/healthz` (or whether the admin UI opens) | Returns `ok` |
| CA certificate expiry | The admin UI overview; log message `中間 CA の有効期限が近い` | Rotate the intermediate when fewer than 30 days remain |
| Late renewals | The "更新が遅れている" (late renewals) count in the admin UI | 0. Otherwise check mtls-agent on the affected server |
| Each server | `mtls-agent check` on each server (exit code 1 if renewal is needed) | Run periodically from your monitoring system |
| Validation failures | Log message `所有確認に失敗` | Check firewalls, name resolution, port conflicts |
| Suspicious connections | Logs with `category=audit`, `許可されていない送信元からの接続を拒否` | No unexpected sources or names |

## 11. Periodic tasks

| Frequency | Task |
| --- | --- |
| Weekly | Check warnings and late renewals on the admin UI overview |
| Monthly | Review EAB keys (revoke unused keys and keys of decommissioned servers). Review audit logs |
| Quarterly | Test restoring from backup (section 14, in a separate environment) |
| Every 2 years (before 30 days remain) | Rotate the intermediate ([operations guide](operations.md#rotating-the-intermediate-ca-before-it-expires)) |
| Every 10 years (plan from 1 year before) | Rotate the root ([operations guide](operations.md#rotating-the-root-ca)) |

## 12. Failure impact and response

| Event | Impact | Tolerable duration | Response |
| --- | --- | --- | --- |
| CA stopped | No new certificates. Issued certificates remain usable until expiry | **About 8 hours** (renewal starts at 16 h, expiry at 24 h) | Restart the CA. mtls-agent keeps retrying meanwhile and re-issues automatically after recovery |
| CA database corrupted | Same as above | Same as above | Restore from backup. If impossible, start empty: servers re-register automatically if their EAB key is still available (redeliver it to servers that deleted `eab.hmac_file`) |
| mtls-agent stopped on a server | That server's certificate expires | About 8 hours | Restart mtls-agent. The admin UI's late-renewal count shows it |
| Clock skew | Certificates judged "not yet valid" or "expired" | — | Fix NTP (the CA tolerates 5 minutes of skew when issuing) |
| Intermediate close to expiry | Issuance is refused once less than half the lifetime (12 hours) remains | — | Rotate the intermediate (warnings start 30 days ahead in logs and the admin UI) |

## 13. Security incident response

| Incident | Response |
| --- | --- |
| A server's key leaked / server compromised | ① Revoke its EAB key (stops the next renewal) ② Revoke the certificate if needed ③ Remove it from peers' allowlists ④ The certificate becomes unusable within 24 hours at most ⑤ Rebuild the server and register it with a new EAB key |
| An EAB key (HMAC) leaked | Revoke that EAB key and deliver a new one. Check the account count of the key on the admin UI's EAB page for unexpected registrations |
| Intermediate key leaked | ① Stop the CA ② Create a new intermediate and switch the CA ③ Certificates from the old intermediate expire within 24 hours ④ Assuming no certificates outside the name constraints can exist, investigate impersonation within them |
| Root key leaked | Rebuild everything. Create a new root and intermediate, and set every server's `ca_root` to the new root only (remove the old root from trust) |
| An admin certificate leaked | Revoke that admin's certificate (**locks them out immediately**) and EAB key. If names are listed individually, also remove it from `admin.allowed_clients`. If the admin was read-only, nothing could be changed (and no secrets are displayed). If the admin is in `admin.operators`, check the audit log (`category=audit`: `EAB 鍵を発行` (EAB key issued) / `EAB 鍵を取り消し` (EAB key revoked) / `証明書を失効` (certificate revoked)), revoke any EAB keys issued without authorization, and have servers whose certificates were revoked obtain new ones (`systemctl reload mtls-agent`) |

## 14. Backup and restore

| Item | Frequency | Method |
| --- | --- | --- |
| Root CA key and certificate | Once, at creation | Two copies on encrypted media, stored in separate places |
| Intermediate key and certificate | At creation and rotation | Store encrypted |
| EAB key file (`eab.json`) | On every change | Store encrypted |
| Database (`data_dir`) | Daily | Stop mtls-ca and copy it (a few seconds). Copies taken while running may be corrupt |
| Configuration files | On every change | Keep in configuration management (contains no secrets) |

Restore order: prepare the OS and users → restore the intermediate key/certificate, root certificate, EAB key file and configuration → restore the database → start mtls-ca.

## 15. Sizing

- Each issuance record is a few KB. With 24-hour certificates renewed about every 16 hours and records deleted 7 days after expiry,
  **1,000 servers mean roughly 10,000–15,000 records and a database of a few tens of MB.**
- CA load is just one or two issuances and validations per server per day, so a small server (about 1 vCPU, 1 GB RAM) is enough.
- The admin UI lists up to 1,000 certificates, newest first (use the filter to find others).

## 16. Pre-deployment checklist

- [ ] The CA server is in a private subnet with no internet egress
- [ ] Only the traffic in 3-2 is allowed
- [ ] The CA can resolve every server's FQDN
- [ ] The root key is on an offline machine, with two copies on encrypted media
- [ ] The intermediate has name constraints
- [ ] `allowed_client_cidrs` and `admin.allowed_cidrs` are set
- [ ] The CA server's disk is encrypted and its time is synchronized with NTP
- [ ] Backups are taken and the restore procedure has been verified
- [ ] Owners and frequency of monitoring (admin UI checks, `mtls-agent check`) are decided
- [ ] Contacts and procedures for incident response (section 13) are decided
