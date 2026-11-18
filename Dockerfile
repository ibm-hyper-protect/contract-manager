# syntax=docker/dockerfile:1.29

# ── Stage 1: Build ──────────────────────────────────────────────────
FROM docker.io/golang:1.27-alpine AS builder

WORKDIR /src

# Install golang-migrate from source (no pre-built s390x binary available).
ARG MIGRATE_VERSION=v4.18.3
RUN CGO_ENABLED=0 go install -tags 'postgres' -ldflags="-s -w" \
    github.com/golang-migrate/migrate/v4/cmd/migrate@${MIGRATE_VERSION} \
    && mv $(go env GOPATH)/bin/migrate /usr/local/bin/migrate

# Cache Go module dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build server binary.
COPY . .
ARG TARGETOS
ARG TARGETARCH
# BuildKit supplies these arguments; legacy native builders do not.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ── Stage 2: Runtime ───────────────────────────────────────────────
FROM docker.io/golang:1.27-alpine

RUN apk add --no-cache ca-certificates tzdata openssl \
  && addgroup -S app \
  && adduser -S -G app -h /app app

WORKDIR /app

# Copy server binary.
COPY --from=builder /out/server /app/server

# Copy golang-migrate binary.
COPY --from=builder /usr/local/bin/migrate /usr/local/bin/migrate

# Embed migration SQL files.
COPY migrations/ /migrations/

# Source checkout permissions must not prevent the non-root migration service
# from traversing the directory and reading SQL. Keep application files root-owned.
RUN find /migrations -type d -exec chmod 0755 {} + \
  && find /migrations -type f -name '*.sql' -exec chmod 0644 {} + \
  && chmod 0755 /app /app/server /usr/local/bin/migrate

ARG VCS_REF
LABEL org.opencontainers.image.source="https://github.com/ibm-hyper-protect/contract-manager" \
      org.opencontainers.image.revision="${VCS_REF}"

USER app
EXPOSE 8080

ENTRYPOINT ["/app/server"]
