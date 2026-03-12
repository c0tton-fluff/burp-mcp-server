#!/bin/bash
# Burp MCP Server & CLI Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/burp-mcp-server/main/install.sh | bash
#   curl -fsSL ... | TOOL=cli bash

set -e

REPO="c0tton-fluff/burp-mcp-server"
VERSION="v1.1.0"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
TOOL="${TOOL:-mcp}"

case "$TOOL" in
    mcp|server) TOOL_NAME="burp-mcp-server" ;;
    cli)        TOOL_NAME="burp-cli" ;;
    *)          echo "Unknown TOOL: $TOOL (use 'mcp' or 'cli')"; exit 1 ;;
esac

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    darwin) OS="darwin" ;;
    linux) OS="linux" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BINARY="${TOOL_NAME}-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
    BINARY="${BINARY}.exe"
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

echo "Installing ${TOOL_NAME} ${VERSION}..."
echo "  OS: ${OS}, Arch: ${ARCH}"
echo "  URL: ${URL}"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download binary
if command -v curl &> /dev/null; then
    curl -fsSL "$URL" -o "${INSTALL_DIR}/${TOOL_NAME}"
elif command -v wget &> /dev/null; then
    wget -q "$URL" -O "${INSTALL_DIR}/${TOOL_NAME}"
else
    echo "Error: curl or wget required"
    exit 1
fi

chmod +x "${INSTALL_DIR}/${TOOL_NAME}"

echo ""
echo "Installed to: ${INSTALL_DIR}/${TOOL_NAME}"
echo ""

if [ "$TOOL_NAME" = "burp-mcp-server" ]; then
    echo "Next steps:"
    echo "  1. Add ${INSTALL_DIR} to your PATH (if not already)"
    echo "  2. Enable MCP in Burp Suite: MCP tab > toggle Enabled (port 9876)"
    echo "  3. Add to your MCP config (see README)"
else
    echo "Next steps:"
    echo "  1. Add ${INSTALL_DIR} to your PATH (if not already)"
    echo "  2. Start Burp Suite with proxy listener on 127.0.0.1:8080"
    echo "  3. Run: burp-cli send GET https://target.com"
fi
