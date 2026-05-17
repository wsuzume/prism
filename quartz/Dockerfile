# syntax=docker/dockerfile:1.7

# =========================================
# Builder
# =========================================
FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/quartz ./quartz


# =========================================
# Runner (debug-friendly)
# =========================================
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/quartz /app/quartz

EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/quartz"]

# =========================================
# Product (final, minimal)
# =========================================
FROM gcr.io/distroless/static-debian12:nonroot AS product

WORKDIR /app
COPY --from=builder /out/quartz /app/quartz

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/quartz"]
