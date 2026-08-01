# attribute-qa

A QA harness for the Privasys attribute model. It drives a **real** deployment —
real IdP, real management-service, real credit registry — and reports what the
platform actually did.

```bash
go build -o attribute-qa .

./attribute-qa test            # headless suite against dev (exit 0 = green)
./attribute-qa test --prod     # against production
./attribute-qa test --json     # machine-readable report for CI
./attribute-qa serve           # browser console for the wallet-approved tiers
```

It needs a platform bearer. By default it borrows the `privasys` CLI's, forcing
a refresh first (`privasys auth login` if you have none); `--token` or
`PRIVASYS_TOKEN` override.

## What it can and cannot automate

Attributes reach the IdP exactly one way: the wallet POSTs them to
`/session/complete` after authenticating the session. A FIDO2 ceremony on its
own carries none.

So the harness plays **both** parts a sign-in needs:

- the **authenticator**, via a software P-256 passkey (`fido2.go`) — the same
  approach the portal's Playwright suite uses, and the reason no phone is
  required;
- the **wallet's attribute delivery** (`wallet.go`).

That covers the self-asserted tier completely. It stops at the government tier,
and deliberately: a `_id` attribute is not a string but an SD-JWT disclosure
signed by the identity-verifier enclave after it read a passport chip and
matched a live face. There is no software stand-in for that, and building one
would put a forgery path inside a QA tool. Those tiers run through
`attribute-qa serve` against a real wallet holding a real credential.

The suite says so out loud rather than quietly passing 11 cases and implying
coverage it does not have.

## The console (`serve`)

Registers one relying party whitelisted for the whole referential, then serves
a picker on `localhost:8099`. Choose any attributes, approve in the wallet, and
the page reports per key: the assurance the referential claims, whether the
value arrived as a raw string or an **enclave-signed disclosure**, and the
achieved `acr` for the set. `GET /last.json` returns the same thing for
scripting.

Distinguishing the two forms is the point. A relying party that cannot tell a
typed value from a signed one has no assurance at all.

## Design notes

**Everything derives from the live referential.** No attribute list is
hard-coded, so adding an attribute widens the suite instead of silently leaving
it behind. Cases are written as "the government twin of a dual-tier key" rather
than "birthdate_id".

**Environment gaps are skips, not failures.** Dev carries no `privasys`
attribute provider, so nothing there is buyable. Those cases report `skip` with
the reason. A suite that cries wolf on a fresh environment is one people learn
to ignore.

**Presence is asserted before absence.** Several cases assert that a key was
*not* requested, which is vacuously true if the response parsed to an empty
list. Each such case first proves a key it *does* expect. This is not
hypothetical: the first run reported five green cases while reading the wrong
JSON field, and every one of them was meaningless.

## What it caught on the first real run

- `privasys:age_band` and `privasys:document_valid` were declared billable in
  the canonical referential with no row in the credit registry. `/authorize`
  reserves every key the referential prices and refuses an unknown one, failing
  the whole authorization — so a **billable** relying party asking for either
  could not sign anyone in. Invisible to a non-billable client, which reserves
  nothing. Fixed by migrations 078 and 079.
- The dev management-service was still on the pre-rollout binary, so the
  attribute-billing-grant endpoints 404'd there.

## Layout

| file | what it holds |
|---|---|
| `main.go` | CLI, flags, token discovery, the test runner |
| `idp.go` | the OIDC leg: authorize, session, token, claim decoding |
| `fido2.go` | the software authenticator (WebAuthn, COSE, minimal CBOR) |
| `wallet.go` | the wallet's attribute delivery, and where it stops |
| `referential.go` | the live canonical list and the relations over it |
| `platform.go` | management-service: clients, quotes, billing grants |
| `suite.go` | the assertions, each with why it matters |
| `console.go` | the browser console for wallet-approved tiers |
