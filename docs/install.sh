#!/bin/bash
# wsuzume/prism の最新リリースから prism バイナリをダウンロードするスクリプト

set -euo pipefail

REPO="wsuzume/prism"
BINARY_NAME="prism"
INSTALL_DIR="${1:-/usr/local/bin}"

echo "最新タグを取得中..."
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
  echo "エラー: タグの取得に失敗しました" >&2
  exit 1
fi

echo "最新タグ: ${LATEST_TAG}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"

echo "ダウンロード中: ${DOWNLOAD_URL}"
curl -fsSL -o "/tmp/${BINARY_NAME}" "${DOWNLOAD_URL}"

chmod +x "/tmp/${BINARY_NAME}"

echo "インストール先: ${INSTALL_DIR}/${BINARY_NAME}"
mkdir -p "${INSTALL_DIR}"
mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

echo "完了: $(${INSTALL_DIR}/${BINARY_NAME} --version 2>/dev/null || echo 'インストール成功')"