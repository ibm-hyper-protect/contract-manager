# syntax=docker/dockerfile:1.7

# ── Stage 1: Build ──────────────────────────────────────────────────
FROM docker.io/golang:1.26-alpine AS builder

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
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ── Stage 2: Runtime ───────────────────────────────────────────────
FROM docker.io/golang:1.26-alpine

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

USER app
EXPOSE 8080

ENTRYPOINT ["/app/server"]
