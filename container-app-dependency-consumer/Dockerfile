# Single-arch linux/amd64, no provenance/SBOM attestations, so the image manifest
# digest the enclave pins at OID 1.3.6.1.4.1.65230.3.2 stays stable across
# rebuilds. The RA-TLS SDK is vendored from the monorepo at build time.
FROM golang:1.24-bookworm AS build
WORKDIR /src
# The SDK lives one level up in the monorepo; the build context must include it.
COPY ra-tls-clients/go /ra-tls-clients/go
COPY apps/test/container-app-dependency-consumer /src
RUN go mod edit -replace enclave-os-mini/clients/go=/ra-tls-clients/go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /consumer .

FROM gcr.io/distroless/static-debian12
COPY --from=build /consumer /consumer
# No EXPOSE: the app binds the platform-injected $PORT under host networking.
ENTRYPOINT ["/consumer"]
