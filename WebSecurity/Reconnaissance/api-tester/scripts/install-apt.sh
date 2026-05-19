#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "" ]]; then
  echo "Usage: $0 <version> [repo]"
  echo "Example: $0 1.0.0 leedale1981/infosec"
  exit 1
fi

VERSION="$1"
REPO="${2:-leedale1981/infosec}"

if command -v dpkg >/dev/null 2>&1; then
  ARCH="$(dpkg --print-architecture)"
else
  echo "dpkg is required to detect architecture"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DEB_FILE="api-tester_${VERSION}_${ARCH}.deb"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${DEB_FILE}"

echo "Downloading ${URL}"
curl -fsSL "$URL" -o "${TMP_DIR}/${DEB_FILE}"

echo "Installing ${DEB_FILE} via apt"
sudo apt update
sudo apt install -y "${TMP_DIR}/${DEB_FILE}"

echo "Installed api-tester ${VERSION}"
api-tester --help >/dev/null 2>&1 && echo "api-tester is available in PATH"
