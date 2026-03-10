# syntax=docker/dockerfile:1.7

# =========================================
# Builder
# =========================================
FROM golang:1.25-bookworm AS builder

WORKDIR /src

# 依存解決のキャッシュを効かせるため、まず go.mod/go.sum のみ
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# リポジトリ全体をコピー（flitleap は root module 配下パッケージなので）
COPY . .

# Makefile 相当:
#   go -C flitleap build -o ../bin/flitleap
# runner に渡すのは 1 バイナリだけでいいので /out に出す
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/prism ./prism


# =========================================
# Runner (debug-friendly)
# =========================================
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
      # ca-certificates curl iproute2 netcat-traditional procps tini \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/prism /app/prism

EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/prism"]

# =========================================
# Product (final, minimal)
# =========================================
FROM gcr.io/distroless/static-debian12:nonroot AS product

WORKDIR /app
COPY --from=builder /out/prism /app/prism

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/prism"]