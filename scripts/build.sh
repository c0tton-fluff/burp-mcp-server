#!/bin/bash
# Cross-compile burp-mcp-server and package burp-cli for release.
# Usage: ./scripts/build.sh [VERSION]
# Output: dist/

set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT}/dist"
CLI_SRC="${ROOT}/Burp-CLI/burp"
PLATFORMS=("darwin/amd64" "darwin/arm64" "linux/amd64" "linux/arm64")

rm -rf "$DIST"
mkdir -p "$DIST"

echo "Building $VERSION for ${#PLATFORMS[@]} targets..."

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  suffix="${GOOS}-${GOARCH}"

  echo "  ${suffix}"

  # MCP server (root Go module)
  GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -C "$ROOT" -ldflags="-s -w -X github.com/c0tton-fluff/burp-mcp-server/cmd.version=${VERSION}" \
    -o "${DIST}/burp-mcp-server-${suffix}" .

  # CLI (Python script - platform independent, copy per target for uniform install)
  cp "$CLI_SRC" "${DIST}/burp-cli-${suffix}"
done

echo ""
echo "Binaries in ${DIST}/:"
ls -lh "$DIST/"
