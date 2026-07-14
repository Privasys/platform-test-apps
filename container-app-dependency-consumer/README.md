# container-app-dependency-consumer (app A)

A test fixture for **attested cross-enclave dependencies**. It depends on
[`container-app-dependency-provider`](../container-app-dependency-provider) (app B)
and demonstrates the fail-closed enforcement a dependent runs before it will talk
to a dependency enclave.

## Flow

`POST /ask {"prompt": "..."}`:

1. Open an RA-TLS connection to the provider (`PROVIDER_URL`), challenge-bound.
2. **Verify** the provider two ways, both fail-closed:
   - ordinary RA-TLS (challenge-bound quote + report-data), so the certificate is
     a genuine, freshly-attested enclave bound to this session; and
   - the **dependency pin** ([`depcheck`](depcheck/depcheck.go)): the provider must
     match the identity this app has pinned for its app-id. A genuine-but-undeclared
     enclave is refused.
3. Only then forward the prompt to the provider's `/infer`.

## The pinned set

The platform seals this app's attested-dependency set into its own certificate
(OID `1.3.6.1.4.1.65230.6.1`) and injects it as `PRIVASYS_ATTESTED_DEPENDENCIES`
(JSON). The app cannot write the set itself; the app owner updates it out-of-band:

```sh
privasys apps dependencies container-app-dependency-consumer --data @deps.json
```

where `deps.json` pins the provider by measurement + required OIDs:

```json
{ "entries": [ {
  "app_id": "<provider app-id>",
  "measurements": [ { "tdx": { "mrtd": "<hex>", "rtmr1": "<hex>", "rtmr2": "<hex>" } } ],
  "required_oids": [ { "OID": "1.3.6.1.4.1.65230.3.2", "ExpectedValue": "<base64 code hash>" } ]
} ] }
```

## Tests

[`depcheck/e2e_test.go`](depcheck/e2e_test.go) is a runnable end-to-end test of the
enforcement: it builds a real X.509 provider certificate carrying the RA-TLS
extensions (TDX quote + app-id + code hash + the OID 6.1 dependency set), parses
it exactly as the SDK does over the wire, and asserts the consumer accepts the
pinned provider and fails closed on a rogue measurement, an undeclared app-id, and
a code-hash mismatch — plus that the provider's advertised dependency set round-trips.

```sh
go test ./depcheck/
```
