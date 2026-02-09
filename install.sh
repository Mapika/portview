#!/bin/sh
set -e

# portview installer
# Usage: curl -fsSL https://raw.githubusercontent.com/mapika/portview/main/install.sh | sh

REPO="mapika/portview"
BINARY="portview"
INSTALL_DIR="/usr/local/bin"

# ── Detect platform ───────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *)      echo "Error: This installer supports Linux and macOS. For Windows, use install.ps1."; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64)   arch="x86_64" ;;
    aarch64|arm64)   arch="aarch64" ;;
    *)               echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARGET="${os}-${arch}"

# ── Fetch latest release ─────────────────────────────────────────────

echo "→ Detecting latest release..."

if command -v curl > /dev/null 2>&1; then
    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
elif command -v wget > /dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
else
    echo "Error: curl or wget is required."; exit 1
fi

if [ -z "$LATEST" ]; then
    echo "Error: Could not determine latest version."; exit 1
fi

URL="https://github.com/${REPO}/releases/download/v${LATEST}/portview-${TARGET}.tar.gz"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${LATEST}/SHA256SUMS"

echo "→ Downloading portview v${LATEST} for ${TARGET}..."

# ── Download and verify ──────────────────────────────────────────────

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if command -v curl > /dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TMPDIR/portview.tar.gz"
    curl -fsSL "$CHECKSUM_URL" -o "$TMPDIR/SHA256SUMS" 2>/dev/null || true
else
    wget -q "$URL" -O "$TMPDIR/portview.tar.gz"
    wget -q "$CHECKSUM_URL" -O "$TMPDIR/SHA256SUMS" 2>/dev/null || true
fi

# Pick a sha256 tool: sha256sum (Linux) or shasum -a 256 (macOS)
if command -v sha256sum > /dev/null 2>&1; then
    SHA256CMD="sha256sum"
elif command -v shasum > /dev/null 2>&1; then
    SHA256CMD="shasum -a 256"
else
    SHA256CMD=""
fi

# Verify checksum if SHA256SUMS was downloaded and a sha256 tool is available
if [ -f "$TMPDIR/SHA256SUMS" ] && [ -n "$SHA256CMD" ]; then
    echo "→ Verifying checksum..."
    EXPECTED=$(grep "portview-${TARGET}.tar.gz" "$TMPDIR/SHA256SUMS" | awk '{print $1}')
    ACTUAL=$($SHA256CMD "$TMPDIR/portview.tar.gz" | awk '{print $1}')
    if [ -z "$EXPECTED" ]; then
        echo "⚠ Warning: No checksum found for portview-${TARGET}.tar.gz in SHA256SUMS"
    elif [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "Error: Checksum verification failed!"
        echo "  Expected: $EXPECTED"
        echo "  Actual:   $ACTUAL"
        exit 1
    else
        echo "✓ Checksum verified"
    fi
elif [ ! -f "$TMPDIR/SHA256SUMS" ]; then
    echo "⚠ Warning: SHA256SUMS not available, skipping integrity verification"
fi

tar xzf "$TMPDIR/portview.tar.gz" -C "$TMPDIR"

# ── Install ──────────────────────────────────────────────────────────

if [ -w "$INSTALL_DIR" ] || [ "$(id -u)" = "0" ]; then
    mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    chmod +x "$INSTALL_DIR/$BINARY"
    echo "✓ Installed portview to $INSTALL_DIR/$BINARY"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    chmod +x "$INSTALL_DIR/$BINARY"
    echo "✓ Installed portview to $INSTALL_DIR/$BINARY"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) echo "  Add to PATH: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac
fi

echo "  Run 'portview' to get started."
