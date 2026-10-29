# Configuration reference

[日本語](../ja/configuration.md)

Configuration files are YAML. **Unknown keys are errors** (typos are never silently ignored).
Durations accept Go syntax such as `30s` / `10m` / `24h`, plus `7d` (days) and `2y` (365-day years).
Configuration files never contain secrets; keys are referenced by path.
Tests verify that the bundled `examples/ca.example.yaml` and `examples/agent.example.yaml` load as-is.

## mtls-ca

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `":8443"` | Listen address |
| `external_url` | (required) | CA URL as seen by clients (`https://host[:port]`). Used to build ACME URLs and to check the `url` of signed requests |
| `hostnames` | host of `external_url` | Names on the CA's own TLS server certificate, issued automatically by the intermediate and re-issued every 7 days. Must be within the intermediate's name constraints |
| `data_dir` | (required) | Directory for the database (bbolt) of accounts, orders and issued certificates. Created with 0700 |
| `root_cert` | (required) | Root CA certificate |
| `intermediate_cert` | (required) | Intermediate CA certificate |
| `intermediate_key` | (required) | Intermediate CA private key. **Must be 0600 or the CA refuses to start** |
| `eab_file` | (required) | EAB key file (managed with `mtlsctl eab`). **Must be 0600.** Changes take effect without a restart |
| `allowed_client_cidrs` | `[]` (no restriction) | Sources allowed to connect (CIDRs or IP addresses). Checked against the TCP peer; `X-Forwarded-For` is ignored |
| `policy.allowed_domains` | (required) | Domains that may be issued (the domain and its subdomains). Must be within the intermediate's name constraints |
| `policy.max_names_per_order` | `10` | Maximum names per certificate (1–100) |
| `cert.validity` | `"24h"` | Lifetime of issued certificates (10m–90d). Capped at the intermediate's expiry; if the capped lifetime would be less than half of this value, issuance is refused (a signal to rotate the intermediate) |
| `challenge.types` | `["http-01", "tls-alpn-01"]` | Accepted validation methods (duplicates are an error) |
| `challenge.http01_port` | `80` | Port used for http-01 |
| `challenge.tlsalpn01_port` | `443` | Port used for tls-alpn-01 |
| `challenge.resolver` | (OS resolver) | DNS server for validation lookups (`"10.0.0.2:53"`) |
| `challenge.timeout` | `"10s"` | Timeout per attempt |
| `challenge.attempts` | `3` | Attempts before failing (2 s apart, 1–10) |
| `crl.validity` | `"24h"` | CRL lifetime (`NextUpdate`). Regenerated after half the lifetime or when a certificate is revoked |
| `log.level` | `"info"` | `debug` / `info` / `warn` / `error` |
| `log.format` | `"text"` | `text` / `json` |
| `admin.listen` | (empty = disabled) | Listen address of the admin web UI. Use a port separate from ACME, bound to localhost or an admin-subnet address (e.g. `"127.0.0.1:9443"`) |
| `admin.allowed_clients` | (required when `admin.listen` is set) | Name patterns of admin certificates allowed in. Login is mTLS with client certificates issued by this CA; no passwords. **Use a subdomain separate from the servers** (e.g. `*.admins.internal.example.com`). Certificates for matching names are issued only with EAB keys that permit the exact name without a wildcard. Revoked certificates cannot get in |
| `admin.operators` | `[]` (everyone read-only) | Names (patterns) of admin certificates allowed to make changes from the admin UI (issue/revoke EAB keys, revoke certificates). They must also be in `admin.allowed_clients`. When set, mtls-ca rewrites `eab_file`, so it refuses to start unless it can write to that directory ([operations design guide 9-6](operations-design.md#9-6-changes-from-the-admin-ui)) |
| `admin.allowed_cidrs` | `[]` (no restriction) | Sources allowed to connect. A warning is logged at startup if empty while listening on a non-loopback address |
| `admin.log_buffer` | `5000` | Number of recent log entries viewable in the UI (100–100000). Kept in memory, since startup only |
| `federation.file` | (empty = federation off) | Federation records file (managed with `mtlsctl federation`; contains no secrets). When set, the trust bundle is served at `/federation/bundle`. **mtls-ca refuses to start with an intermediate without name constraints** (your own scope comes from them). See the [federation design](federation-design.md) |
| `federation.bundle_validity` | `"48h"` | Trust bundle expiry (1h–168h). Both "how long federation survives a CA outage" and "the worst-case time a suspension may fail to arrive" |

### Endpoints

| Path | Description |
| --- | --- |
| `/acme/directory` | ACME directory (configure clients with this URL) |
| `/crl` | CRL signed by the intermediate (DER) |
| `/healthz` | Health check (returns `ok`) |
| `/federation/bundle` | Trust bundle (JWS signed with the intermediate key; only when `federation.file` is set) |

The admin UI (`admin.listen`) runs on a separate port and shows the following pages.

| Path | Contents |
| --- | --- |
| `/` | Overview (CA certificate expiry, counts, warnings) |
| `/certs` | Issued certificates (operators in `admin.operators` can also revoke) |
| `/eab` | EAB keys (operators in `admin.operators` can also issue and revoke) |
| `/federation` | Federation (admins in `admin.operators` can also import, request, approve, suspend and remove). Only when `federation.file` is set |
| `/logs` | Logs |

It never shows secrets such as keys or HMACs (except the HMAC of a newly issued EAB key, shown once right after issuing). See the [operations design guide](operations-design.md#9-admin-web-ui) for usage.

### Administrative subcommands

These open the database directly, so **stop mtls-ca first**.

```sh
mtls-ca certs  -config /etc/mtls-ca/config.yaml [-all]               # list issued certificates (status: valid, revoked, expired, incomplete)
mtls-ca revoke -config /etc/mtls-ca/config.yaml -serial <hex> [-reason 1]
```

## mtls-agent

| Key | Default | Description |
| --- | --- | --- |
| `ca_url` | (required) | ACME directory URL (`https://.../acme/directory`) |
| `ca_root` | (required) | Root CA certificate, used to verify the CA connection and issued certificates. During a root rotation the file may contain both the old and new roots |
| `account_key` | (required) | ACME account key, created on first run (0600). Internal state is kept next to it in the key file name plus `.state.json` (e.g. `account.key.state.json`; time of issuance and intermediate CA, 0600) |
| `eab.kid` | | kid printed by `mtlsctl eab create`; used only for the first registration |
| `eab.hmac_file` | | HMAC key file (**must be 0600**). Can also be given via the `MTLS_AGENT_EAB_HMAC` environment variable. Not needed after registration |
| `names` | (required) | Names (FQDNs) on the certificate. Must be allowed by the EAB key |
| `key_type` | `"ecdsa-p256"` | `ecdsa-p256` / `ecdsa-p384` / `rsa-2048` / `rsa-3072` / `rsa-4096` / `ed25519` |
| `challenge.type` | `"http-01"` | `http-01` / `tls-alpn-01` |
| `challenge.listen` | http-01: `":80"`, tls-alpn-01: `":443"` | Address opened only during validation |
| `challenge.webroot` | | If set, http-01 writes response files into an existing web server's document root instead of listening |
| `output.cert` | (required) | Certificate (leaf only). Written last, so it can be used to detect renewals |
| `output.key` | (required) | Private key |
| `output.chain` | | Intermediate CA |
| `output.fullchain` | | Certificate + intermediate (configure applications with this) |
| `output.ca` | | Copy of the root CA(s) (`ca_root`) |
| `output.key_mode` | `"0600"` | Private key mode: `"0600"` or `"0640"` (readable by applications in the same group) |
| `output.trust_bundle` | | Federation trust bundle (signed). Point the `mtls` library's `TrustBundleFile` at it. Setting `output.trust_bundle` or `output.federation_dir` makes the agent fetch the trust bundle from the CA |
| `output.federation_dir` | | Per-partner root CA (`<id>.pem`) and scope (`<id>.domains`), for accepting partners in nginx etc. Suspended or expired partners are replaced with a "PEM that chains to nothing" (not deleted) |
| `renew.fraction` | `0.66` | Renew after this fraction of the lifetime has elapsed (0.1–0.9) |
| `renew.check_interval` | `"1m"` | Status check interval |
| `renew.timeout` | `"5m"` | Timeout for one issuance |
| `hooks.post_renew` | | Command run after renewal, **without a shell** (e.g. `["systemctl", "reload", "nginx"]`). Receives `MTLS_AGENT_NAMES` / `MTLS_AGENT_CERT` / `MTLS_AGENT_KEY` / `MTLS_AGENT_FULLCHAIN` |
| `hooks.timeout` | `"60s"` | Timeout for post-update commands (shared by `post_renew` / `post_bundle`) |
| `hooks.post_bundle` | | Command run after the trust bundle (partners) changes (e.g. `["/bin/sh", "-c", "nginx -t && systemctl reload nginx"]`). On failure it is retried with exponential backoff (30 seconds to 15 minutes) until it succeeds, and `check` returns exit code 1 meanwhile. Receives `MTLS_AGENT_TRUST_BUNDLE` / `MTLS_AGENT_FEDERATION_DIR` |
| `log.level` / `log.format` | `info` / `text` | Same as mtls-ca |

On failure, the agent retries starting at 30 seconds and doubling up to 15 minutes.

### Subcommands

```sh
mtls-agent run   -config FILE           # run continuously (SIGHUP renews immediately)
mtls-agent renew -config FILE [-force]  # check once, renew if needed, then exit
mtls-agent check -config FILE           # show the certificate and federation status (exit code 1 on problems)
```

## mtlsctl

```sh
mtlsctl root create -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p384] [-validity 10y]
mtlsctl intermediate csr  -out-dir DIR -cn NAME [-org ORG] [-key-type ecdsa-p256]
mtlsctl intermediate sign -root-cert F -root-key F -csr F -out F -permitted-domain D[,D...] [-validity 2y]
mtlsctl eab create -file F -names P[,P...] [-note TEXT] [-hmac-out F]
mtlsctl eab list   -file F
mtlsctl eab revoke -file F -kid KID
mtlsctl federation export  -config CA_CONFIG [-org ORG] [-contacts ..] [-domains ..] [-out F]
mtlsctl federation import  -config CA_CONFIG -in F -id ID
mtlsctl federation request -config CA_CONFIG -id ID -compared-with TEXT [-fingerprint FP] [-domains ..] [-validity 1y]
mtlsctl federation approve -config CA_CONFIG -id ID [-fingerprint FP]
mtlsctl federation suspend -config CA_CONFIG -id ID [-reason TEXT]
mtlsctl federation remove  -config CA_CONFIG -id ID
mtlsctl federation list    -config CA_CONFIG [-id ID]
mtlsctl inspect FILE
```

Key files are always created new; existing files are never overwritten.

### Name patterns (`eab create -names`, library `AllowedPeers`)

| Pattern | Matches |
| --- | --- |
| `web1.internal.example.com` | Exact match only |
| `*.batch.internal.example.com` | Exactly one label below `batch.internal.example.com` (`a.batch...` matches; `a.b.batch...` and `batch...` itself do not) |
