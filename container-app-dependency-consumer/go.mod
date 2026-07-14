module container-app-dependency-consumer

go 1.22

require enclave-os-mini/clients/go v0.0.0

// Monorepo test fixture: use the in-tree RA-TLS SDK.
replace enclave-os-mini/clients/go => ../../../ra-tls-clients/go
