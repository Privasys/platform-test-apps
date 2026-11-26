# Dev-only fixture: proves the runtime's security fixes from inside a
# container. Deleted after the proofs. Single-arch, no attestations.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /fixproof .

FROM gcr.io/distroless/static-debian12
COPY --from=build /fixproof /fixproof
# Must be REFUSED at load: no model disk is assigned to this deployment.
LABEL ai.privasys.volume="/mnt:/models:ro"
ENTRYPOINT ["/fixproof"]
