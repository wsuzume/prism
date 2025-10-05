FROM golang:1.24-bookworm AS builder

ARG TARGET
ARG TARGET_GOARCH=amd64

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY go.work ./
COPY api/go.mod api/go.sum ./api/
COPY pkg/go.mod ./pkg/
COPY client/go.mod client/go.sum ./client/
COPY proxy/go.mod proxy/go.sum ./proxy/

RUN --mount=type=cache,target=/go/pkg/mod go work sync

# ソース投入
COPY ${TARGET}/ ./${TARGET}/
COPY pkg/ ./pkg/

ENV GOFLAGS="-mod=readonly"
# RUN --mount=type=cache,target=/root/.cache/go-build \
#     --mount=type=cache,target=/go/pkg/mod \
#     CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
#     go -C ./${TARGET} build -trimpath -ldflags="-s -w" -o /out/${TARGET} .

# Mac でまずはこれを使って動作確認
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=1 GOOS=linux GOARCH=${TARGET_GOARCH} \
    go -C ./${TARGET} build -trimpath -ldflags="-s -w" -tags "${BUILD_TAG}" -o /out/${TARGET} .

# ランタイム用ディレクトリ作成（nonroot が書けるように）
RUN install -d -m 770 /var/lib/prism/data /var/lib/prism/certs && \
    chown -R 65532:65532 /var/lib/prism

# ---- Runtime ----
FROM gcr.io/distroless/cc-debian12:nonroot

ARG TARGET

# data/certs を nonroot 所有で配置
COPY --from=builder --chown=65532:65532 /var/lib/prism /var/lib/prism
COPY --from=builder /out/${TARGET} /opt/prism/${TARGET}

WORKDIR /opt/prism
USER nonroot:nonroot

# DB の保存先（アプリ側で参照）
ENV PRISM_DB=/var/lib/prism/data/users.db
