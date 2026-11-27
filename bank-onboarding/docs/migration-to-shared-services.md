# Moving the bank onto the shared credential services

**Status:** agreed design (the five decisions are settled; see the end). Covers #14 (issuance) and #15 (verification). Being built in the order below.

## Why

The bank (`hr.bank.darkedges.com`) runs its own credential stack. It embeds the issuer libraries to issue the staff credential, and
hand-rolls OpenID4VP to check passports and staff sign-ins. The platform now has a shared, multi-tenant issuer and verifier. Each
AuthStack environment is its own tenant, with its own keys certified by the tenant CA, managed from the console.

Moving the bank onto them gives the bank:
- tenant keys and certificates;
- `mso_mdoc` as well as SD-JWT;
- console management;
- one implementation of the protocols to keep conformant.

It also makes the bank the first real customer of the services, so it shows what a customer needs from them.

## What must not change

- **The bank decides.** Hiring status, superseded attempts, the holder key proved by the passport, issue-once, passport freshness
  (`passport_check_after`) and the evidence policy stay the bank's rules, in the bank's database. The shared services never learn
  what a hire is.
- **Authr's journeys.** `bank-applicant` and `bank-staff-signin` call the bank's Journey API. Its contract stays as it is; only what the
  bank does behind it changes.
- **The wallet's passport flow.** The wallet relies on today's request shape, including `passport_check_after` and `expires_at`.
- **Refusals are immediate.** A deactivated staff member is refused at once (#16, darkedges/pingone-authstack#148,
  darkedges/atlassian-adf-form-r#128). The migration must keep that.

## Target

```
              Authr journeys ──Journey API──▶  bank (hr.bank.darkedges.com)  ── its rules, its database
                                                 │                    ▲
                     tenant API (worker token)   │                    │ issuance hook (signed by the tenant)
                                                 ▼                    │
   wallet ◀── offer ── shared issuer, Risk E Bank tenant (issuer.bank.darkedges.com)
   wallet ── presentation ──▶ shared verifier, Risk E Bank tenant (bank.verifier.zkp.au)
```

- **Tenant:** the AuthStack environment **Risk E Bank** enables both Credential Issuance and Verification.
- **Issuer address:** `https://issuer.bank.darkedges.com`, the bank's own domain through Credential Domains (decision 1). The platform
addresses `bank.issuer.zkp.au` and `issuer.zkp.au/t/bank` reach the same tenant, but credentials are issued as the bank's domain.
- **Verifier address:** `https://bank.verifier.zkp.au`. The verifier can't serve customer domains on the current tunnel (only the issuer is the
  tunnel's catch-all).

## The bank calling the services: tenant API authentication

Both new APIs (below) are called by the bank's backend, as the Risk E Bank tenant.

**Decided:** a client-credentials token from a **dedicated** worker application in the Risk E Bank environment, `Risk E Bank credential
services`, with no roles (decision 3). The existing `Risk E Bank directory` worker holds Identity Data Admin, so its secret stays out of these calls.
- **The check:** the service verifies the token against that environment's AuthStack keys (`/<envId>/as/jwks`), and requires its
  `environmentId` to equal the tenant it's calling.
- **The result:** no new secrets, and a worker of another environment can't act for this tenant.
- **Rejected alternative:** a per-tenant API secret in the tenant settings. It's another secret to rotate, and it isn't tied to AuthStack.

## Part 1: issuance (#14)

### 1.1 A tenant offer API on the issuer

There's no way today for a tenant's backend to create an offer. Only the demo's `/demo/offer` does, through
`PreAuthorizedCodeService`.

```
POST /tenant-api/v1/offers                                   (on the tenant's address; worker token)
{
  "credentialConfigurationIds": ["BankStaffCredential", "BankStaffCredentialMdoc"],
  "claims": { "staff_id": "…", "bank_id": "…", "given_name": "…", "family_name": "…", "department": "…" },
  "holderKeyThumbprint": "…",            // the wallet must prove this key (RFC 7638): see 1.3
  "expiresIn": 600,
  "reference": "<hire id>"               // idempotency, and what the issuance hook is told
}
→ 201 { "offer": {…}, "offerUri": "openid-credential-offer://?credential_offer=…", "expiresAt": "…" }
```

- **Idempotency:** a second call with the same `reference` while an offer is live returns that offer.
- **Revocation:** `DELETE /tenant-api/v1/offers/{reference}` withdraws a live offer, for example when HR withdraws an approval.

### 1.2 Keeping the bank's rules: an issuance hook

Today the bank's rules run inside the bank's own `CredentialIssuanceService`, in one database transaction. On the shared issuer they have to
run in the bank, while the issuer is issuing.

**Decided (decision 2): the issuer calls the bank before it signs, and again after.** Both calls are configured per tenant
(`settings.issuanceHook.url`).
```
POST <bank>/api/issuer-hook/v1/authorize   { "reference", "credentialConfigurationId", "format", "holderKeyThumbprint" }
  → 200 { "allow": true }    |  409 { "allow": false, "reason": "staff_inactive" | "superseded" | "already_issued" }
POST <bank>/api/issuer-hook/v1/issued      { "reference", "credentialConfigurationId", "format", "credentialDigest" }
  → 204
```
- **Authentication:** each call carries a short-lived JWT signed with the tenant's own issuer key (audience the hook URL). The bank
  verifies it against the tenant's published keys, pinned as it pins the passport issuer today. That's no shared secret, and only the
  tenant's issuer can call the hook.
- **Failing closed:** if `authorize` is unreachable or slow (5 seconds), the issuer answers the wallet with a temporary error and issues
  nothing.
- **After issuing:** `issued` records the credential and its format, and triggers the bank's audit and directory update. If it fails, the
  credential is already in the wallet, so the issuer retries and the bank treats `issued` as idempotent per reference and format.
- **Rejected alternative: deciding everything in the offer, and revoking codes on change.** It leaves a race between a status change and
  redemption, and issue-once per format becomes the issuer's problem rather than the bank's.

### 1.3 Holder binding enforced by the issuer

The bank binds the staff credential to the key the passport presentation proved. That check belongs in the issuer, for every tenant:
- an offer may pin `holderKeyThumbprint`;
- the issuer refuses a proof of possession with any other key (`invalid_proof`).

This gives the hook less to do, and it's useful to other tenants too.

### 1.4 Formats: SD-JWT and mdoc

The Risk E Bank tenant's settings define two configurations:

| Id | Format | Type |
|---|---|---|
| `BankStaffCredential` | `dc+sd-jwt` | `vct` `/vct/BankStaffCredential` (tenant-relative: `https://issuer.bank.darkedges.com/vct/BankStaffCredential`) |
| `BankStaffCredentialMdoc` | `mso_mdoc` | doctype `com.darkedges.bank.staff.1`, namespace `com.darkedges.bank.staff.1` with the same elements (decision 4) |

- **Keys:** the shared issuer already issues `mso_mdoc` per tenant, signed with the tenant's own mdoc key and certified by the tenant CA.
- **Offers:** one offer carries both configurations, and the wallet collects both.
- **Issue-once:** applies per reference and per format, through the hook.

### 1.5 The issuer identity changes

| | Today | After |
|---|---|---|
| `iss` / `credential_issuer` | `https://hr.bank.darkedges.com` | `https://issuer.bank.darkedges.com` |
| signing key | `bank-staff-1` (`BANK_PRIVATE_JWK_FILE`) | the tenant's `issuer-signing` key, with an `x5c` chain to the tenant CA |
| `bank_id` claim | the bank's base URL | **the new issuer identifier**, so the wallet's rule `bank_id == iss` stays true |

- **mdoc:** an mdoc has no `iss`. Its `issuerAuth` certificate chains to the tenant CA, and the certificate names the environment
  (`O=<envId>`). The wallet's mdoc equivalent of `bank_id == iss`: the certificate's environment is the Risk E Bank environment, and
  the namespace's `bank_id` equals that tenant's issuer identifier.
- **The address is set before the first credential:** `issuer.bank.darkedges.com` must be verified on Credential Domains first.
  Changing the issuer identifier later means another reissue.

### 1.6 Cutover

1. **Trust both:** staff sign-in accepts the old issuer (pinned `bank-staff-1`) and the new one (tenant keys, chain to the tenant CA).
2. **New issuance on the shared issuer:** new approvals get offers from the shared issuer. `…/credential-offers` in the Journey API
   returns those.
3. **Reissue:** the bank re-offers to every active staff member and records when each has collected the new credential.
4. **Retire, 30 days after step 3 starts** (decision 5): staff credentials are valid for 30 days (`staffIssuance`), so by then every
   credential from the old issuer has expired. Stop trusting `bank-staff-1`, and remove the embedded issuer from the bank along with its
   `oid4vci_issuer_entry` table and `ISSUER_STORE_ENCRYPTION_KEY`. Anyone who hasn't collected a new credential gets a re-offer from HR.

Offers in flight at step 2 live for 10 minutes; let them drain.

## Part 2: verification (#15)

### 2.1 A tenant transaction API on the verifier

The verifier library is built to be embedded in a relying party (`Oid4vpLoginConfigurer`), which authenticates its *own* browser
session. A shared verifier needs a way for the tenant's backend to start a request and receive the verified claims:

```
POST /tenant-api/v1/transactions                             (on bank.verifier.zkp.au; worker token)
{ "registrationId": "passport" | "staff-sign-in",
  "expiresIn": 600,
  "requestParameters": { "passport_check_after": "2026-11-28T00:00:00Z" },   // per registration allow-list: see 2.3
  "reference": "<presentation id in the bank>" }
→ 201 { "transactionId", "requestUri", "walletUri": "openid4vp://?client_id=…&request_uri=…", "expiresAt" }

GET  /tenant-api/v1/transactions/{id}          → { "status": "pending" | "verified" | "rejected" | "expired" }
POST /tenant-api/v1/transactions/{id}/consume  → 200 { "credentials": { "<query id>": { "format", "issuer", "claims": {…},
                                                   "holderKey": {…} } } }   (once; 409 afterwards)
```
- **Polling plus consume** mirrors the bank's own Journey API, which Authr already polls.
- **A signed callback** to the bank can come later. It isn't needed for the first version.

### 2.2 What stays in the bank

The verifier says *the presentation is cryptographically valid and from an issuer this tenant trusts*. The bank then applies its own
policy to the consumed claims:
- passport freshness (`proofed_at` against `passport_check_after`) and `PassportEvidencePolicy`;
- the hire moving to `REVIEW`, and the holder key it stores;
- for staff sign-in: active, not superseded.

The bank's own presentation row keeps the outcome:
- `complete`, or `refused` with `refused_reason`, as since #16;
- the Journey API reports it exactly as today.

### 2.3 Request parameters per transaction

The wallet needs `passport_check_after` and `expires_at` in the request.
- **Registration allow-list:** each registration in the tenant settings lists the extra request parameters it accepts
  (`requestParameters: ["passport_check_after"]`).
- **Request object:** the verifier copies them into the signed request object. It validates them as strings of at most 256 characters;
  anything else is refused.
- **`expires_at`:** the verifier sets it from `expiresIn` itself.

### 2.4 The wallet contract

The shared verifier sends a **signed** request object with an `x509_hash` client id (the tenant's certificate). The bank's requests today are
unsigned, with `redirect_uri:` client ids. Before cutover, check:
- **The mobile wallet** (`oid4vci-wallet`) accepts signed request objects with `x509_hash`, and still finds `passport_check_after` and
  `expires_at` in them.
- **Its passport check** keys on the DCQL query (vct values of trusted passport issuers), not on the client id.
- **Its DCQL matching** presents one credential when `multiple` is false. `oid4vp-core` was fixed for this in darkedges/spring-boot-oid4vp#11;
  the mobile wallet has its own matcher.

### 2.5 The Risk E Bank verifier tenant

```json
{
  "registrations": {
    "passport":      { "dcqlQuery": { "credentials": [ { "id": "passport", "format": "dc+sd-jwt",
                                                         "meta": { "vct_values": ["https://issuer.zkp.au/vct/PassportCredential"] }, "claims": [ … ] } ] },
                       "responseMode": "direct_post", "requestParameters": ["passport_check_after"] },
    "staff-sign-in": { "dcqlQuery": { "credentials": [
                         { "id": "staff",      "format": "dc+sd-jwt", "meta": { "vct_values": ["https://issuer.bank.darkedges.com/vct/BankStaffCredential"] }, … },
                         { "id": "staff_mdoc", "format": "mso_mdoc",  "meta": { "doctype_value": "com.darkedges.bank.staff.1" }, … } ],
                       "credential_sets": [ { "options": [["staff"], ["staff_mdoc"]] } ] },
                       "responseMode": "direct_post" }
  },
  "trustedIssuers": [
    { "issuer": "https://issuer.zkp.au",      "jwksUri": "https://issuer.zkp.au/jwks" },
    { "issuer": "https://issuer.bank.darkedges.com", "x5cTrustAnchors": ["<tenant CA>"] }
  ]
}
```

During the issuance cutover (1.6), `staff-sign-in` also accepts the old `https://hr.bank.darkedges.com` staff credential type, and
`trustedIssuers` pins `bank-staff-1`.

### 2.6 Cutover

Move **staff sign-in first**, since it's simpler (no freshness or evidence rules), then **passport checks**.
- **Moving a flow:** a flag per flow (`BANK_VERIFY_STAFF_VIA=shared|embedded`, `BANK_VERIFY_PASSPORT_VIA=…`). The Journey API starts
  either kind of presentation without Authr noticing.
- **In flight:** presentations already started finish on the path they started on.
- **Afterwards:** remove `/vp/request` and `/vp/response`, and the bank's verification code.

## Order of work

| # | Repo | Work | Depends on |
|---|---|---|---|
| 1 | oid4vp (`oid4vc-tenancy`) | Tenant API authentication: AuthStack worker token, environment equals tenant | — |
| 2 | oid4vci | Issuer: tenant offer API (1.1), holder-key pinning (1.3), issuance hook (1.2) | 1 |
| 3 | AuthStack Terraform / console | Risk E Bank: the dedicated worker; slug; `issuer.bank.darkedges.com` on Credential Domains; enable issuance (SD-JWT and mdoc settings) | 2 |
| 4 | bank | Issuance through the shared issuer behind a flag; the hook endpoints; dual trust at sign-in | 2, 3 |
| 5 | wallet | mdoc staff credential; `bank_id` rule for mdoc; signed request objects (2.4) | 2 |
| 6 | oid4vp | Verifier: tenant transaction API (2.1), request parameters (2.3), `credential_sets` with mdoc | 1 |
| 7 | AuthStack / console | Risk E Bank: enable verification (2.5) | 6 |
| 8 | bank | Staff sign-in, then passport checks, through the shared verifier behind flags | 6, 7, 5 |
| 9 | bank | Reissue to active staff; retire the embedded issuer and verifier | 4, 8 |

Each step is its own PR and can ship without the next.

**Progress:**
- Steps 1 to 3 are done: oid4vp #12, spring-boot-oid4vci #18, pingone-authstack #150. The Risk E Bank tenant is enabled at
  `issuer.bank.darkedges.com`.
- Step 4 is built:
  - `SharedIssuer` and `IssuerHookController`, behind `BANK_ISSUE_VIA`;
  - the issued credentials recorded in `bank_issued_credential`, once per format;
  - the issuer's `issued` call now carries the credential itself.
- Step 5 is tracked as oid4vci-wallet#3. Until then the bank offers `BankStaffCredential` only.

## Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Issuer address | `https://issuer.bank.darkedges.com` | The identifier is in every credential and `vct`; on the bank's own domain it survives any change to the platform's hostnames without a reissue. Custom issuer domains already work end to end. |
| 2 | How the bank's rules run | The issuance hook (1.2) | Rules run at the moment of issuing, as today. Deciding in the offer leaves a window where a deactivated staff member could still redeem a live offer. |
| 3 | Worker for the tenant APIs | A dedicated worker with no roles | Least privilege: the directory worker can change users, so its secret stays out of these calls. |
| 4 | mdoc doctype and namespace | `com.darkedges.bank.staff.1` for both | The mdoc convention is the issuer's domain reversed plus a version (`org.iso.18013.5.1.mDL`, `eu.europa.ec.eudi.pid.1`). |
| 5 | How long to trust the old issuer | 30 days after reissue starts | Staff credentials are valid for 30 days, so by then every old one has expired anyway. |

## Risks

- **Wallet compatibility (2.4)** is the most likely surprise, especially signed request objects and the passport flow in the mobile
  wallet. Check it before step 8.
- **The hook puts the bank in the issuance path.** If the bank is down, staff can't collect credentials. That's no worse than today,
  where the bank *is* the issuer.
- **Key custody moves to the shared issuer.** Losing its `TENANT_KEY_ENCRYPTION_KEY` loses the bank's issuing keys, and means another
  reissue.
