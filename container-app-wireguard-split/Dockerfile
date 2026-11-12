# Build a static binary, then run it on a distroless base. Single-arch
# linux/amd64, no provenance/SBOM attestations, so the image manifest digest
# stays stable across rebuilds.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /wireguard-split .

FROM gcr.io/distroless/static-debian12
COPY --from=build /wireguard-split /wireguard-split
# The WireGuard settings arrive through POST /configure; until then the platform
# keeps every other path closed.
LABEL org.privasys.config_api="POST /configure"
# No EXPOSE: the app binds the platform-injected $PORT.
ENTRYPOINT ["/wireguard-split"]
