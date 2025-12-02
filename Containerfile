# syntax=docker/dockerfile:1.20

FROM docker.io/library/golang:1.25.5 AS builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ipv6relayd ./cmd/ipv6relayd

FROM docker.io/library/alpine:3.22.2

WORKDIR /

COPY --from=builder /out/ipv6relayd /usr/local/sbin/ipv6relayd

ENTRYPOINT ["/usr/local/sbin/ipv6relayd"]
CMD ["run"]
