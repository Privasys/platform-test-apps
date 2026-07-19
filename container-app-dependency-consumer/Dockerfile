# Single-arch linux/amd64, no provenance/SBOM attestations, so the image manifest
# digest the enclave pins at OID 1.3.6.1.4.1.65230.3.2 stays stable across
# rebuilds.
#
# Built with the Privasys/go fork and -tags ratls: the consumer presents an
# ingress mutual-RA-TLS client certificate via ratls.EgressClientCert, which
# reads the per-session channel binder (a fork-only TLS field).
#
# Self-contained build context (this app directory): the public RA-TLS SDK is
# cloned at build time and wired in via a go.mod replace, so the image builds
# both from CI (this repo) and from the platform's github-source builder.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# Privasys Go fork (adds tls.CertificateRequestInfo.RATLSChannelBinder etc.).
RUN curl -fsSL https://github.com/Privasys/go/releases/download/privasys-v0.5.2-go1.26.5/go-ratls-privasys-v0.5.2-go1.26.5-linux-amd64.tar.gz \
    | tar -C /usr/local -xz
ENV PATH=/usr/local/go-ratls/bin:$PATH
ENV GOTOOLCHAIN=local GOFLAGS=-mod=mod
# Public RA-TLS SDK. Its module path (enclave-os-mini/clients/go) is a vanity
# path, so it is consumed via a replace to the cloned tree rather than go get.
RUN git clone --depth 1 https://github.com/Privasys/ra-tls-clients /ra-tls-clients
WORKDIR /src
COPY . /src
RUN go mod edit -replace enclave-os-mini/clients/go=/ra-tls-clients/go
RUN CGO_ENABLED=0 GOOS=linux go build -tags ratls -trimpath -ldflags="-s -w" -o /consumer .

FROM gcr.io/distroless/static-debian12
COPY --from=build /consumer /consumer
# No EXPOSE: the app binds the platform-injected $PORT under host networking.
ENTRYPOINT ["/consumer"]
