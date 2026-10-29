# Security design

[日本語](../ja/security.md)

What mtls_manager protects against, and what it does not. Please read this before deploying.

## Assumptions

- Everything runs **inside a private network**; no external service is contacted.
- A server's identity is its **FQDN**. The DNS names in a certificate tell who the peer is.
- Eligibility for a certificate is checked by both an **EAB key (prior authorization)** and **domain validation (http-01 / tls-alpn-01)**.

## What is protected

| Threat | Mitigation |
| --- | --- |
| Any device on the network obtains certificates | **EAB is required**; accounts cannot be created without a pre-shared key |
| A server with an EAB key obtains certificates for another server's name | **Each EAB key is bound to fixed names**, and the CA also validates by connecting to the name |
| Internal DNS is hijacked to pass validation | DNS alone is not enough: an EAB key that permits the name is also required |
| The intermediate key leaks and is used for outside domains | The intermediate carries **critical Name Constraints**; certificates outside the permitted domains fail verification |
| The root key leaks | The root key lives **only on an offline machine**, never on the CA server |
| A stolen certificate is used for a long time | **24-hour lifetime by default.** Revoking the EAB key prevents the next renewal |
| Replay of signed requests | Single-use nonces and checking the `url` header against the request target (RFC 8555) |
| Access to another account's orders or certificates | Every operation checks that the object belongs to the requesting account |
| Use of the CA from unexpected sources | `allowed_client_cidrs` restricts source addresses |
| Other local users reading keys | Services **refuse to start unless private key and EAB files are 0600**; keys are written as 0600 |
| Inconsistent state during renewal | Files are written to a temporary file and renamed; the library keeps the previous pair if certificate and key do not match |
| Accepting the wrong peer | The library's server configuration **requires a peer-name allowlist** (it does not default to "anyone with a certificate from this CA") |
| Validation redirection | http-01 does not follow redirects and ignores proxy environment variables |
| Unauthorized access to the admin UI | It listens on a port separate from ACME and can be restricted by source. Login is **mTLS** with certificates issued by this CA, restricted by name with `admin.allowed_clients` (no passwords to guess or reuse). Every access and rejection is audit-logged |
| Leakage or tampering via the admin UI | It is **read-only** and never shows secrets such as keys or HMACs. No external scripts are loaded (CSP). Log content is rendered as text, never interpreted as HTML |

## What is not protected (needs measures on your side)

| Item | Details and recommendations |
| --- | --- |
| Compromise of the CA server | The intermediate key can issue any certificate within the name constraints. Dedicate the CA server, restrict logins, keep the OS patched |
| Compromise of a server holding a certificate | Its key can impersonate that server. Revoke its EAB key and, if needed, its certificate |
| Immediate revocation | In v0.x the library and mtls-agent do not check the CRL; short lifetimes bound the exposure ([operations guide](operations.md#revoking-a-certificate)) |
| Key protection (HSM / KMS) | In v0.x keys are PEM files. Encrypt the CA server's disk. HSM / KMS support is planned |
| Delivery of EAB keys / HMACs | Use a secure channel (e.g. scp) and delete them from the server after the first registration |
| Storage of the root key | The file is not encrypted; store it on encrypted media |
| CA availability | Renewal stops while the CA is down. With 24-hour certificates, expirations begin after about 8 hours of downtime. Monitor the CA and consider a longer `cert.validity` if needed |
| Compromise of an admin machine | A stolen admin certificate and key allow viewing the admin UI (no changes are possible and no secrets are shown). Revoke that admin's EAB key and remove the name from `admin.allowed_clients` |
| Clock skew | Certificate verification depends on time; use NTP everywhere |

## Implementation choices

- **Keep the custom code small**: signing uses Go's standard `crypto/x509`, JWS parsing and verification use `go-jose`,
  storage uses `bbolt`, and the ACME client uses `golang.org/x/crypto/acme`.
- **Interoperability**: CI tests interoperability with Go's ACME client and with lego on every run.
- **Secure defaults**: EAB required, intermediates are not signed without name constraints (unless explicitly disabled),
  `allowed_domains` required, TLS 1.3 minimum (library), no wildcard certificates.
- **No secrets in the repository**: test keys are generated on the fly, and CI runs gitleaks over the full history.

## Reporting vulnerabilities

Please report privately as described in [SECURITY.md](../../SECURITY.md), not in a public issue.
