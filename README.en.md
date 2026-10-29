# mtls_manager

[日本語](README.md)

A private CA and automatic certificate renewal toolkit for protecting server-to-server traffic with **mTLS (mutual TLS)**.
It runs entirely inside a private network and never contacts any external service.

Let's Encrypt stopped issuing certificates for TLS client authentication in 2026, so mTLS can no longer be built on a public CA;
you need your own CA. mtls_manager aims to make in-house mTLS as easy to operate as server certificates with Let's Encrypt and certbot.

> **Status: v0.x (early development).** Interfaces may change. We recommend an independent security review
> before broad production use (see [SECURITY.md](SECURITY.md)).
> Log and CLI messages are currently in Japanese.

## Features

- **A CA in a single binary**: `mtls-ca` is an ACME (RFC 8555) server. Renewal can be automated with the bundled
  `mtls-agent` or with standard ACME clients such as `lego`.
- **Built for mTLS**: each certificate is valid for both server and client authentication. Lifetimes are short
  (24 hours by default), so the design does not depend on revocation.
- **Secure by default**
  - **External Account Binding (EAB) is required**: only servers holding a pre-shared key can request certificates.
  - Each key can be restricted to specific names (e.g. only `web1.internal.example.com`).
  - **The intermediate CA carries Name Constraints**: even if its key leaks, it cannot issue certificates outside the permitted domains.
  - The root CA key stays offline; only the intermediate key lives on the CA server.
  - Access to the CA can be restricted by source IP. Services refuse to start if private key files are not 0600.
- **Easy to integrate**: the Go library (`mtls` package) adds hot certificate reloading and a peer-name allowlist in a few lines.
  It also works with existing software such as nginx and curl.
- **Admin web UI (read-only)**: view the overview, issued certificates, EAB keys and logs in a browser. Login is mTLS with certificates issued by this CA, and every access is audit-logged.
- **Linux first, macOS supported**: example systemd units and launchd jobs are included.

## Architecture

```
 ┌────────────────────┐   sign CSR (about once a year)   ┌─────────────────────────────┐
 │ Offline machine    │ ───────────────────────────────▶ │ CA server                   │
 │  root CA key       │                                  │  mtls-ca (ACME server)      │
 │  mtlsctl root ...  │                                  │  intermediate key, EAB keys │
 └────────────────────┘                                  └──────────────┬──────────────┘
                                                                        │ ACME (HTTPS)
                                         ┌──────────────────────────────┼──────────────────────────────┐
                                         ▼                              ▼                              ▼
                                ┌────────────────┐            ┌────────────────┐            ┌────────────────┐
                                │ Server A       │    mTLS    │ Server B       │    mTLS    │ Server C       │
                                │  mtls-agent    │ ◀────────▶ │  mtls-agent    │ ◀────────▶ │  mtls-agent    │
                                │  app           │            │  app           │            │  nginx, etc.   │
                                └────────────────┘            └────────────────┘            └────────────────┘
```

| Command | Role |
| --- | --- |
| `mtlsctl` | Creates the root and intermediate CAs and manages EAB keys (per-server issuance permission) |
| `mtls-ca` | ACME server that issues certificates with the intermediate CA, with a read-only admin web UI; also lists and revokes issued certificates |
| `mtls-agent` | Runs on each server, obtains a certificate and renews it before it expires |
| `mtls` (Go package) | Library for adding mTLS to Go applications |

## Installation

Requires Go 1.26 or later.

```sh
go install github.com/nobumin/mtls_manager/cmd/...@latest
```

To build for another platform (e.g. Linux arm64):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/ ./cmd/...
```

## Getting started

Follow the [getting started guide](docs/en/getting-started.md):

1. Create the root CA on an offline machine
2. Create the intermediate CA on the CA server and start `mtls-ca`
3. Issue an EAB key for each server
4. Start `mtls-agent` on each server
5. Integrate with your applications

## Documentation

| Document | Contents |
| --- | --- |
| [Getting started](docs/en/getting-started.md) | From building the CA to integrating applications |
| [Configuration reference](docs/en/configuration.md) | Settings for `mtls-ca` and `mtls-agent` |
| [Operations guide](docs/en/operations.md) | Adding/removing servers, revocation, intermediate rotation, backup, monitoring, troubleshooting |
| [Operations design guide (detailed)](docs/en/operations-design.md) | Network design, what is automated, admin UI, monitoring, failure and incident response, backup, pre-deployment checklist |
| [Security design](docs/en/security.md) | Threat model, what is and is not protected, recommendations |
| [SECURITY.md](SECURITY.md) | How to report vulnerabilities |

## Handling of secrets

This repository contains **no secrets** — no keys, certificates or EAB keys.

- All secrets are read at runtime from files outside the repository (e.g. `/etc/mtls-ca`).
  Configuration files refer to secrets by path and never contain them.
- Only example configurations without values (`examples/`) are committed.
- Keys and certificates used by tests are generated on the fly.
- `.gitignore` excludes `*.key`, `*.pem`, `eab.json` and similar files, and CI runs gitleaks over the full history.

## Development

```sh
go test -race ./...                                           # unit and integration tests
go vet ./...
LEGO_BIN=$(which lego) go test -tags interop ./test/interop/  # interop test with lego (needs /etc/hosts entries)
```

CI (`.github/workflows/ci.yml`) runs formatting checks, static analysis (staticcheck), tests on Linux and macOS,
the lego interop test, cross builds for each OS/CPU, govulncheck and gitleaks.

## License

[MIT](LICENSE)
