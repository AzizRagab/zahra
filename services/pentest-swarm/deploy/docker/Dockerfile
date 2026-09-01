# syntax=docker/dockerfile:1.7
#
# Build stage — statically-linked Go binary, no cgo.
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/pentestswarm ./cmd/pentestswarm/

# Runtime stage — non-root, minimal, read-only-friendly.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S swarm && adduser -S -G swarm -h /home/swarm swarm

COPY --from=builder /out/pentestswarm /usr/local/bin/pentestswarm
COPY --chown=swarm:swarm playbooks/ /usr/local/share/pentestswarm/playbooks/

USER swarm
WORKDIR /home/swarm

EXPOSE 8080

LABEL org.opencontainers.image.title="Pentest Swarm AI" \
      org.opencontainers.image.source="https://github.com/Armur-Ai/Pentest-Swarm-AI" \
      org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["pentestswarm"]
CMD ["serve"]
