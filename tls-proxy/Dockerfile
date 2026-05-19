FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Copy both modules (tls-proxy depends on icap-server packages via replace)
COPY icap-server ./icap-server
COPY tls-proxy   ./tls-proxy

WORKDIR /build/tls-proxy
# GOFLAGS=-mod=mod allows go to fetch and update go.sum during build
RUN GOFLAGS=-mod=mod go build -trimpath -ldflags="-s -w" -o /tls-proxy .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /tls-proxy /tls-proxy
ENTRYPOINT ["/tls-proxy"]
