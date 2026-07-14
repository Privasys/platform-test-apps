# Privasys test apps (monorepo)

A monorepo of confidential-app fixtures used by platform integration and e2e
tests. Not published to the store. Each subdirectory is a self-contained app; add
new fixtures as sibling directories.

Checked out alongside the other platform repos (the consumer's `go.mod` uses a
`replace` to the sibling `ra-tls-clients/go` SDK).

## Attested cross-enclave dependencies

A matched pair demonstrating one enclave depending on another and enforcing the
dependency fail-closed over RA-TLS:

- [`container-app-dependency-provider`](container-app-dependency-provider) — app B,
  the dependency (stands in for e.g. a Confidential AI enclave).
- [`container-app-dependency-consumer`](container-app-dependency-consumer) — app A,
  depends on B; verifies B's enclave identity is in its pinned attested-dependency
  set (certificate OID `1.3.6.1.4.1.65230.6.1`) before sending any data.

The consumer's [`depcheck/e2e_test.go`](container-app-dependency-consumer/depcheck/e2e_test.go)
runs the enforcement end-to-end against a real X.509 certificate (`go test ./depcheck/`).
