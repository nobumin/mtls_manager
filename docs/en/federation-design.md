# Federation design (mTLS between servers managed by separate mtls-managers)

[日本語](../ja/federation-design.md)

> **Status: design proposal (not implemented).** It will be implemented in stages after review ([15.](#15-implementation-stages)).
> Some decisions must be made before implementation ([16.](#16-open-decisions)).

## 1. Purpose and scope

So far mtls_manager has assumed that **a single mtls-ca (a single root CA)** manages every server that talks to each other.
Server A and server B get certificates from the same CA, trust the same root CA, and check each other's names with an allowlist (`AllowedPeers`).

The federated version supports the following setup:

- Server A is managed by **A's mtls-ca** (root CA A) and server B by **B's mtls-ca** (root CA B)
- A and B live on different networks, and neither mtls-ca issues (or can issue) certificates for the other side's servers
- Server A and server B verify each other's certificates and connect with mTLS

This document defines **how trust is established between the two (federation)**, and the procedures, distribution, verification and shutdown.

Out of scope: meshes of three or more parties (each pair can federate individually), federation with public CAs, and the design of the network path between applications (VPN, leased lines, etc.).

## 2. Assumptions

- The design assumes the stricter case: **A and B are different organizations (companies)**. The other side's CA is treated as "not under our control".
  Simplifications for two networks within the same company are noted in the "In-house" remarks in each section.
- **A and B use different domains** (e.g. A uses `a.example.com`, B uses `b.example.net`). If they overlap, they cannot federate ([6-3.](#6-3-scopes-must-not-overlap)).
- Application traffic (mTLS) can flow between server A and server B. **CA-to-CA connectivity is not required** (the first federation can be done by hand).
- Each organization's internal setup (offline root CA, name-constrained intermediate, 24-hour certificates, etc.) stays as it is.

> **Alternative for in-house use**: within one organization, it is simpler to **share the root CA and run one intermediate CA per network**
> instead of federating. The root CA is offline, so sharing it adds little risk, and each intermediate's name constraints separate the networks' names.
> Every server just trusts the same root CA, with no federation procedures or distribution. This works with the current implementation
> (create two intermediates and give one to each mtls-ca). The federated version is needed when **the root CA cannot be shared**
> (different organizations, or when you want separate administrative boundaries).

## 3. Terms

| Term | Meaning |
| --- | --- |
| Federation | An agreement between two mtls-cas to trust each other's root CA within a scope |
| Federation partner | The other organization (and its mtls-ca) |
| Scope | For a partner's root CA, the range of certificate names that will be accepted (e.g. `b.example.net` and its subdomains) |
| Federation record | Per partner: root CA certificate, scope and state |
| Trust bundle | Your own root CA plus the approved federation records, distributed by mtls-ca to every server |
| Fingerprint | SHA-256 of the root CA certificate (DER). Compared by eye to confirm identity |

## 4. Requirements

### 4-1. Functional

| # | Requirement |
| --- | --- |
| F-1 | Export your own federation record (root CA certificate, fingerprint, your scope, contacts) |
| F-2 | Import a partner's record, compare the fingerprint, decide the scope and approve it |
| F-3 | Approved records are distributed automatically to every server (mtls-agent) |
| F-4 | Applications (`mtls` library) accept a partner's certificates **only for names within its scope** |
| F-5 | A federation can be suspended (revoked), and every server picks it up immediately |
| F-6 | A partner's root CA rotation can be followed without breaking the federation |
| F-7 | Adding, approving and suspending federations is always audit-logged |

### 4-2. Security

| # | Requirement |
| --- | --- |
| S-1 | Even if a partner's CA issues a certificate for **your organization's names** (your `allowed_domains`), it is not accepted |
| S-2 | Even if a partner's CA issues a certificate for names outside the approved scope, it is not accepted |
| S-3 | On first import, you can confirm the root CA was not substituted, without relying on the transport |
| S-4 | A federation is never established by a single admin's decision (two approvals; in-house this can be relaxed to one) |
| S-5 | No secrets (keys) are ever received from the partner, and none are ever given to it |
| S-6 | Servers do not keep using stale or tampered trust bundles |

### 4-3. Non-functional

- Per-connection verification cost stays roughly constant as partners increase (guideline: tens of partners)
- Can be operated entirely by hand where CAs cannot reach each other
- Existing setups (no federation) keep working with no configuration changes

## 5. Architecture

```
       Organization A                                      Organization B
┌──────────────────────────┐                    ┌──────────────────────────┐
│ Root CA A (offline)      │                    │      Root CA B (offline) │
│        │                 │                    │        │                 │
│  mtls-ca A ── record B   │ ◀── (1) exchange ──▶ │   record A ── mtls-ca B  │
│   │   (scope: b.example.net)  & compare      (scope: a.example.com) │   │
│   │ (2) trust bundle     │  (fingerprint via │   (2) trust bundle   │   │
│   ▼                      │   another channel)│                      ▼   │
│ mtls-agent (A1, A2...)   │                    │   mtls-agent (B1, B2...) │
│   │ cert + bundle        │                    │        cert + bundle │   │
│   ▼                      │                    │                      ▼   │
│ App A1 ◀════════════ (3) mTLS (verified within scope) ══════════▶ App B1 │
└──────────────────────────┘                    └──────────────────────────┘
```

1. The admins exchange federation records, compare fingerprints over a separate channel, decide the scope and approve ([7.](#7-first-federation-procedure))
2. Each mtls-ca distributes the trust bundle to its own mtls-agents ([8.](#8-distributing-the-trust-bundle))
3. Applications accept certificates that chain to their own root CA, or to a partner's root CA for names within its scope ([9.](#9-verification-at-connection-time))

Server certificates are still issued only by each organization's own mtls-ca.

## 6. Trust model

### 6-1. What is exchanged and what is not

| Exchanged | Not exchanged |
| --- | --- |
| Root CA certificate (public) | Private keys (root, intermediate, servers), EAB keys, HMACs |
| Fingerprint (for out-of-band comparison) | Individual server certificates or public keys |
| Your scope (the domains you use) | Configuration files, databases |
| Contacts (approvers, emergency contact) | |

**Individual server public keys are not exchanged.** Certificates rotate with new keys every 24 hours, so pinning public keys would mean
re-exchanging them daily, which defeats automatic renewal. Instead, you approve "the partner's root CA" and "the partner's server names".
Only certificates properly issued by the partner's CA for allowed names get through, which has the same effect as "approving the partner's
server public keys" while following key rotation automatically.

### 6-2. Scoped trust

Simply adding a partner's root CA to "trusted roots" is not enough. Technically the partner's CA can issue a certificate for any name
(name constraints on the partner's intermediate are set by the partner and cannot be enforced by you). So **the accepting side checks the scope**.

- Each federation record has a scope (a list of domains), e.g. partner B → `b.example.net`
- When verifying a connection, determine **which root CA the peer certificate chained to**, and check that **all** of the certificate's names fall within that root's scope
- A certificate with even one name outside the scope is rejected (S-1, S-2)
- Then, as before, `AllowedPeers` limits the peer names (the scope is "names that CA may vouch for"; `AllowedPeers` is "peers this application may talk to")

Your own root CA's scope is your `policy.allowed_domains`.

### 6-3. Scopes must not overlap

At approval time the following are checked, and an overlap blocks approval:

- The partner's scope does not overlap your `policy.allowed_domains` (otherwise S-1 cannot hold)
- The partner's scope does not overlap any other partner's scope (otherwise it is unclear which CA is responsible)

The partner's declared scope (included in its record) is an upper bound; you can **narrow it** when approving
(e.g. the partner declares `b.example.net`, you approve only `api.b.example.net`).

## 7. First federation procedure

### 7-1. Export your record (both organizations)

Export your federation record from the admin UI's "Federation" page (or `mtlsctl federation export`).

```json
{
  "format": "mtls-manager-federation/v1",
  "organization": "Example A Corp.",
  "root_cert": "-----BEGIN CERTIFICATE-----\n...",
  "root_sha256": "3F:9A:...:C2",
  "domains": ["a.example.com"],
  "contacts": ["security@a.example.com"],
  "created_at": "2026-11-01T00:00:00Z"
}
```

It contains no secrets. Email or file sharing is fine (substitution is caught by the comparison in 7-3).

### 7-2. Import

Import the partner's file in the admin UI (an admin in `admin.operators`) or with `mtlsctl federation import`.
At this point it is **pending approval** and not part of the trust bundle. On import, mtls-ca checks that:

- the certificate is a valid root CA (self-signed, CA:TRUE, within validity, acceptable key type and size)
- `root_sha256` matches the certificate
- the declared scope satisfies 6-3

### 7-3. Compare the fingerprint (over another channel)

Compare the fingerprint shown on screen with the partner's contact **over a channel different from the one the file came through**.

- e.g. read it aloud on a phone or video call, check in person, or include it in a document signed by both parties (such as a contract annex)
- The fingerprint is 32 bytes (64 hex digits), shown in groups of 4 for easy reading
- This is the same idea as checking a host fingerprint on first SSH connection: the transport itself need not be trusted

**So a "trusted network" is not required for the exchange.** The root CA certificate is public information; what must be protected is only
that it was not substituted (integrity), and that is confirmed by the fingerprint compared over another channel.

### 7-4. Approve (two people)

1. The first admin **enters the first and last 8 digits** of the compared fingerprint, sets the scope (narrowing it if needed) and the expiry, and "requests approval"
2. **Another** admin reviews and "approves" (the same admin cannot approve)
3. Once approved, the record becomes "active" and enters the trust bundle

- In-house: a setting (`federation.require_two_approvals: false`) allows a single approval
- Requests, approvals and rejections are all audit-logged (admin name, partner, fingerprint, scope)
- An expiry (default 1 year) is set; warnings appear in the admin UI and logs from 30 days before. Renewal repeats 7-3 and 7-4 (re-comparison)

### 7-5. The partner does the same

Federation is **separate in each direction**. mTLS works both ways only after A approves B and B approves A
(approval on one side only lets no connection through in either direction, because in mTLS both server and client verify each other's certificate).

## 8. Distributing the trust bundle

### 8-1. mtls-ca → mtls-agent

- mtls-ca serves the trust bundle (its own root CA plus active federation records) at `GET /federation/bundle` on the ACME port
- The content is public but **needs integrity**, so mtls-agent fetches it only over its existing connection to the CA (TLS verified with its own root CA)
- The bundle carries **a sequence number, issue time and expiry (default 7 days)** and is signed with the intermediate CA key (JWS).
  mtls-agent checks the signature and sequence number and rejects any bundle whose sequence goes backwards (replay of an old bundle) (S-6)
- mtls-agent checks for changes (ETag) every `renew.check_interval` (default 1 minute). If the CA is down, it keeps using its local bundle
  until expiry (so a CA outage does not break federation)

### 8-2. mtls-agent → applications

mtls-agent writes new outputs (the existing `output.ca` stays your own root CA only).

| Setting | Contents | Consumer |
| --- | --- | --- |
| `output.trust_bundle` | Trust bundle (JSON: certificate and scope per root CA) | `mtls` library |
| `output.trust_pem` | Your and partners' root CAs concatenated as PEM (no scope information) | nginx etc. ([9-2.](#9-2-other-than-the-mtls-library-nginx-etc)) |

As before, files are written to a temporary file and renamed, and a "command after bundle update" can be run in the same way as `hooks.post_renew`.

## 9. Verification at connection time

### 9-1. `mtls` library

- Add `TrustBundleFile` to `Config` (specified instead of `CAFile`; specifying both is an error)
- The trust bundle is **reloaded without a restart**, like certificates (today `CAFile` is read once at startup, so this changes;
  the current bundle is used via `GetConfigForClient` / `VerifyConnection`)
- Verification steps:
  1. Normal chain verification (every root CA in the trust bundle is a trust anchor)
  2. **Identify the root CA** of the verified chain and check that **all** DNS names of the peer certificate fall within that root's scope
  3. Check the peer names with `AllowedPeers` (as before)
- The client side (the connecting side) performs the same verification (step 2 in addition to the normal hostname verification)
- Rejection reasons (outside scope, unapproved root) are included in errors so logs show the cause

### 9-2. Other than the `mtls` library (nginx etc.)

nginx and similar software cannot check "a scope per root CA". Merely trusting `output.trust_pem` does not satisfy S-1 and S-2.
Compensate with one of the following (procedures will be in the operations design guide):

- **(Recommended)** Use a separate port for connections from partners, trust **only the partner's root CA** there, and check the peer names
  (`$ssl_client_s_dn` or SAN) against an allowlist. Connections from your own organization use another port that trusts only your own root CA
- Put a small relay (sidecar) built on the `mtls` library in front

### 9-3. Revocation

- Revocation of a partner's certificates relies, as before, on **short lifetimes** (24 hours by default) to bound exposure
- In urgent cases, suspend the federation itself (10.) or remove the peer from `AllowedPeers`
- (Stage 3) Consider having mtls-ca fetch the partner's CRL and include revoked serials in the trust bundle

## 10. Suspending a federation

- Suspend from the admin UI (or `mtlsctl federation suspend` / `remove`). **Suspension can be done immediately by one person** (unlike approval, it is a protective action)
- Suspension advances the trust bundle sequence; each mtls-agent picks it up at its next check (within 1 minute by default), and applications reject connections once they reload it
- Suspended records are kept; resuming requires repeating 7-3 and 7-4 (comparison and two approvals)
- The procedure for when a partner's CA is found compromised (suspend → contact → impact investigation → re-federate with a new root) will be added to the incident response section of the operations design guide

## 11. Root CA rotation (without breaking federation)

The root CA key is offline, so rotation can be planned ahead.

1. When the partner creates a new root CA, it creates **an announcement signed by the old root CA** (new root's fingerprint, planned switch date) with `mtlsctl root announce`
   (on the offline machine, using the old root key)
2. The announcement and the new root certificate are handed over like a federation record (in stage 3 the CAs fetch them automatically)
3. The receiving side **verifies the announcement's signature with the old root it currently trusts** and puts the new root into pending approval as "the next root of the same partner".
   If the signature is valid, no fingerprint comparison is needed (the old root vouches for the new one). One approval is enough
4. During the transition, both old and new roots are trusted with the same scope. Once the partner issues under the new root, it announces the retirement of the old root and the receiving side removes it

Intermediate CA rotation needs no partner action, since the root CA is unchanged (as today).

## 12. Automatic CA-to-CA updates (stage 3, optional)

Where CAs can reach each other, the following can be automated, so manual comparison is needed only the first time.

- Each mtls-ca publishes its federation record, root rotation announcements and CRL on a federation endpoint (separate port, mTLS)
- Connections to the endpoint are limited to **mTLS with certificates of already-approved partners** (the names are registered in the federation record)
- Fetched content is used only after verifying its signature (root CA or intermediate CA). **Changes that widen trust, such as a larger scope, are never applied automatically; they go to pending approval**
- Fetches run periodically (default every hour); repeated failures produce warnings in the admin UI and logs

## 13. Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| The partner's CA issues a certificate for your organization's names (compromise or mistake) | Scoped trust (6-2). Scopes overlapping your `allowed_domains` cannot be approved (6-3) |
| The partner's CA issues a certificate within its scope to an attacker | Cannot be prevented (the partner's responsibility). Keep `AllowedPeers` minimal and be able to suspend the federation (10.) |
| The root CA is substituted during the first exchange | Out-of-band fingerprint comparison (7-3). Part of the compared fingerprint must be entered on the approval screen (7-4) |
| A single admin approves a federation improperly | Two approvals (7-4). Audit log |
| A server is kept on a stale trust bundle (from before suspension) | Bundle sequence number, expiry and signature (8-1) |
| A partner compromise is noticed late | Suspension is immediate by one person (10.). Contacts are part of the record. Expiry forces periodic review |
| Software that cannot check scopes (nginx etc.) accepts names outside the scope | Separate ports that trust only the partner's root (9-2) |
| Partners increase and one is approved with the wrong scope | The approval screen mechanically checks overlaps with your domains and other partners (6-3) |

## 14. Impact on existing features

- Setups without federation keep working with no configuration changes (without the `federation` settings, the federation page and API are disabled)
- `CAFile` in the `mtls` library keeps working. `TrustBundleFile` is a new option
- The contents of mtls-agent's existing outputs (`output.ca` etc.) do not change. Federation output goes only to new settings
- Admin UI permissions (`admin.operators`) and audit logging are reused for federation operations
- A bucket for federation records is added to the database (no migration of existing data is needed)

## 15. Implementation stages

| Stage | Contents | What it enables |
| --- | --- | --- |
| 1 | Scoped verification and bundle reloading in the `mtls` library. `mtlsctl federation export / import / approve / suspend` (file-based). Bundle fetching and output in mtls-agent. The CA's `/federation/bundle` | A and B federate with a manual exchange |
| 2 | The admin UI's "Federation" page (import, comparison, two-person approval, suspension, expiry warnings). Audit logs. Operating procedures for nginx | Operators manage federation in the UI |
| 3 | Root rotation announcements (`mtlsctl root announce`) and following them. The CA-to-CA federation endpoint (automatic updates, CRL fetching) | No manual work after the first time |

Each stage adds tests to CI (rejecting names outside scope, rejecting overlaps, rejecting stale bundles, propagation of suspension, etc.).
Stage 1 also adds an integration test with two CAs (servers of A and B connect through federation, and fail outside the scope).

## 16. Open decisions

The following must be decided before implementation.

| # | Item | Options / recommendation |
| --- | --- | --- |
| 1 | Relationship between A and B | Different organizations (this document's assumption) or the same company. If the same company, also consider "sharing the root CA" in item 2 |
| 2 | Approach for in-house use | Use the federated version, or share the root CA with one intermediate per network (recommended: share; no implementation needed) |
| 3 | Two-person approval | Required by default? (recommended: required; can be turned off in-house) |
| 4 | Support for nginx etc. | Is the "separate ports" procedure in 9-2 enough, or should a sidecar be provided? |
| 5 | Automatic CA-to-CA updates (stage 3) | Needed? Does the network allow CA-to-CA traffic? |
| 6 | Revocation of partner certificates | Are short lifetimes enough, or should CRLs be fetched? |
| 7 | Federation expiry | Is the default of 1 year acceptable? |
