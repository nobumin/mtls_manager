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
| Unauthorized access to the admin UI | It listens on a port separate from ACME and can be restricted by source. Login is **mTLS** with certificates issued by this CA, restricted by name with `admin.allowed_clients` (no passwords to guess or reuse). Every access and rejection is audit-logged. Revoked admin certificates and certificates with no issuance record at this CA are rejected, as are certificates whose issuing EAB key no longer permits the admin name exactly (key revoked, or the configuration widened later) |
| Obtaining an admin certificate with a server's EAB key | Certificates for names matching `admin.allowed_clients` are issued only with EAB keys that permit that exact name without a wildcard (a server key such as `*.internal.example.com` is rejected). Issuing EAB keys from the admin UI also rejects wildcards overlapping admin names, and existing keys are warned about at startup |
| Leakage or tampering via the admin UI | It never shows secrets such as keys or HMACs (the HMAC of a newly issued EAB key is shown once; the response is not cached and the HMAC is never logged). Changes are limited to admins in `admin.operators`, POST only, with confirmation. No external scripts are loaded (CSP). Log content is rendered as text, never interpreted as HTML. Result messages are fixed texts chosen by the server; arbitrary text cannot be injected through the URL |
| Forged requests to the admin UI (CSRF) | With mTLS the browser attaches the certificate even to requests started by other sites. Change forms carry a per-admin token (an HMAC with a key that changes at every start) and requests whose `Origin` / `Sec-Fetch-Site` indicate another site are rejected. CSP `form-action 'self'` and `frame-ancestors 'none'` prevent redirecting form submissions and framing (clickjacking) |
| A partner CA issuing certificates for your names or names outside its scope (federation) | A partner's root CA is trusted only for names within the approved scope. Scopes need at least two labels, cannot be public suffixes, and cannot be approved if they overlap your scope or another partner's. Partner certificates with wildcards, non-DNS SANs or no DNS names are rejected |
| Substitution during the first federation exchange (federation) | The whole fingerprint is compared over a separate channel with a contact known independently of the file. Both request and approval require typing the whole fingerprint, and requester and approver must be different names |
| Man-in-the-middle against federated clients (federation) | Federated clients reject connections not made by host name (IP connections cannot have the host name checked). On the server side, `AllowAnyPeer` applies only to your own organization's peers, and partner peers must match `AllowedPeers` |
| Swapping your own organization's trust by compromising the CA server (federation) | Your own root CA and scope never come from the trust bundle (the root from `CAFile`, the scope from the name constraints of the intermediate signed by the offline root). Bundles are signed with the intermediate key, and receivers check the signature, your root fingerprints and scope overlaps |
| Replaying old trust bundles or suppressing suspensions (federation) | Bundles carry an epoch, sequence number and expiry (2 days by default), and older ones are rejected. Both mtls-agent and the `mtls` library compare them. On expiry only partners are dropped |
| Substitution during a partner's root CA rotation (federation) | Rotation announcements are accepted only when signed with the old root key currently trusted. Announcements cannot widen the scope, expire (180 days at most), and cannot be used for suspended partners. Announcements are not used for rotations due to key compromise (suspend and redo the comparison and two-person approval) |

## What is not protected (needs measures on your side)

| Item | Details and recommendations |
| --- | --- |
| Compromise of the CA server | The intermediate key can issue any certificate within the name constraints. Dedicate the CA server, restrict logins, keep the OS patched |
| Compromise of a server holding a certificate | Its key can impersonate that server. Revoke its EAB key and, if needed, its certificate |
| Immediate revocation | In v0.x the library and mtls-agent do not check the CRL, and nginx's `ssl_crl` cannot be used with this CA's CRL alone (there is no root CA CRL); short lifetimes bound the exposure ([operations guide](operations.md#revoking-a-certificate)) |
| Key protection (HSM / KMS) | In v0.x keys are PEM files. Encrypt the CA server's disk. HSM / KMS support is planned |
| Delivery of EAB keys / HMACs | Use a secure channel (e.g. scp) and delete them from the server after the first registration |
| Storage of the root key | The file is not encrypted; store it on encrypted media |
| CA availability | Renewal stops while the CA is down. With 24-hour certificates, expirations begin after about 8 hours of downtime. Monitor the CA and consider a longer `cert.validity` if needed |
| Compromise of an admin machine | A stolen admin certificate and key allow viewing the admin UI (no secrets are shown). For an admin in `admin.operators`, the attacker could also issue EAB keys (register new servers) or revoke certificates. Keep operators to a minimum. Revoking that admin's certificate or EAB key locks them out immediately; revoke both, remove the name from `admin.allowed_clients` / `admin.operators`, and review the audit log |
| Clock skew | Certificate verification depends on time; use NTP everywhere |
| Partners added by a compromised CA server (federation) | A compromised CA server can add "partners" whose names do **not** overlap your scope to the trust bundle (a stage 1 limitation). Restrict logins to the CA server, monitor `mtls-agent check` and the logs (list of partners) on each server, and keep application `AllowedPeers` to the peers actually needed |
| Identity of the two approvers (federation, CLI) | The admin UI checks the operating admin's name with the login certificate (mTLS). The `-by` name in `mtlsctl federation`, however, is self-declared, and only "requester and approver have different names" can be checked. Approval must use the same channel as the request (across channels, one person could appear as two names). Approve in the admin UI, and review the records of partners requested or approved via the CLI (marked "includes CLI (self-declared)" in the UI). Restrict logins to the CA server |
| Software that cannot check partner scopes (federation) | nginx etc. cannot check per-partner scopes. Use a separate port for partner connections, trust only that partner's root there, and limit the allowlist to exact names ([operations guide](operations.md#federating-with-another-organization)) |
| Delayed suspension (federation) | If traffic between the CA and the servers is blocked, a suspension does not arrive and the partner may stay trusted until the trust bundle expires (2 days by default) in the worst case. In urgent cases, also remove the partner from application `AllowedPeers` |

## Implementation choices

- **Keep the custom code small**: signing uses Go's standard `crypto/x509`, JWS parsing and verification use `go-jose`,
  storage uses `bbolt`, and the ACME client uses `golang.org/x/crypto/acme`.
- **Interoperability**: CI tests interoperability with Go's ACME client and with lego on every run.
- **Secure defaults**: EAB required, intermediates are not signed without name constraints (unless explicitly disabled),
  `allowed_domains` required, TLS 1.3 minimum (library), no wildcard certificates.
- **No secrets in the repository**: test keys are generated on the fly, and CI runs gitleaks over the full history.

## Reporting vulnerabilities

Please report privately as described in [SECURITY.md](../../SECURITY.md), not in a public issue.
