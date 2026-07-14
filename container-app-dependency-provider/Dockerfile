# Build a static binary, then run it on a distroless base. Single-arch
# linux/amd64, no provenance/SBOM attestations, so the image manifest digest the
# enclave pins at OID 1.3.6.1.4.1.65230.3.2 stays stable across rebuilds.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY main.go .
RUN go mod init provider >/dev/null 2>&1 || true
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /provider main.go

FROM gcr.io/distroless/static-debian12
COPY --from=build /provider /provider
# No EXPOSE: the app binds the platform-injected $PORT under host networking.
ENTRYPOINT ["/provider"]
