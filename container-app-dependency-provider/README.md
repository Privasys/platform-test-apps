# container-app-dependency-provider (app B)

A test fixture for **attested cross-enclave dependencies**. It stands in for a
dependency such as a Confidential AI enclave: a minimal confidential service that
boots ready and exposes a stand-in `/infer` endpoint.

It is paired with [`container-app-dependency-consumer`](../container-app-dependency-consumer)
(app A), which depends on this app and will only call `/infer` after verifying,
over RA-TLS, that this exact enclave identity is in its pinned attested-dependency
set (certificate extension OID `1.3.6.1.4.1.65230.6.1`).

## Endpoints

| Method | Path       | Purpose |
|--------|------------|---------|
| GET    | `/health`  | Liveness (manager readiness probe). |
| GET    | `/version` | App version. |
| GET    | `/`        | App info. |
| POST   | `/infer`   | Stand-in inference; echoes the prompt. |

## Identity

The platform terminates RA-TLS in front of this container and stamps its identity
into the served certificate: the TEE measurement, the app-id (OID `…3.6`), the
image code hash (OID `…3.2`), and — if this app itself declares dependencies —
its own dependency set (OID `…6.1`). A dependent pins this app by that identity.

The container serves plain HTTP on the injected `$PORT`; it never sees TLS.
