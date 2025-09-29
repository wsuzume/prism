FROM golang:1.24-bookworm AS builder

ARG TARGET

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*

COPY go.work ./
COPY api/go.mod api/go.sum ./api/
COPY pkg/go.mod ./pkg/
COPY client/go.mod client/go.sum ./client/
COPY proxy/go.mod proxy/go.sum ./proxy/

# 依存を更新せずに取得（ワークスペース内の各モジュール）
RUN --mount=type=cache,target=/go/pkg/mod \
    go work sync

# ソース投入
COPY ${TARGET}/ ./${TARGET}/
COPY pkg/ ./pkg/

# バージョン更新を防ぐため readonly でビルド
ENV GOFLAGS="-mod=readonly"
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go -C ./${TARGET} build -trimpath -ldflags="-s -w" -o /out/${TARGET} .

# ★ 最終段で使う空ディレクトリをここで作成＆権限設定
RUN install -d -m 700 /var/lib/prism/certs

FROM gcr.io/distroless/static:nonroot

ARG TARGET

# nonroot は distroless の UID/GID=65532
COPY --from=builder --chown=65532:65532 /var/lib/prism /var/lib/prism
COPY --from=builder /out/${TARGET} /opt/prism/${TARGET}
COPY react/dist /opt/prism/dist

WORKDIR /opt/prism

USER nonroot:nonroot
