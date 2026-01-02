#!/bin/bash
#
# LogChat Installer
# Usage: curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/logchat/main/install.sh | bash
#

set -e

REPO="YOUR_USERNAME/logchat"
BINARY_NAME="logchat"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════╗"
echo "║         LogChat Installer             ║"
echo "║   Secure P2P Terminal Messenger       ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux*)  OS="linux" ;;
    darwin*) OS="darwin" ;;
    *)
        echo -e "${RED}Error: Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    amd64)   ARCH="amd64" ;;
    arm64)   ARCH="arm64" ;;
    aarch64) ARCH="arm64" ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo "Detected: ${OS}/${ARCH}"

# Get latest release
echo "Fetching latest release..."
LATEST_RELEASE=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo -e "${RED}Error: Could not fetch latest release${NC}"
    echo "Please check if the repository exists and has releases."
    exit 1
fi

echo "Latest version: ${LATEST_RELEASE}"

# Download URL
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${BINARY_NAME}-${OS}-${ARCH}"

echo "Downloading ${BINARY_NAME}..."
TEMP_FILE=$(mktemp)
if ! curl -sSL -o "$TEMP_FILE" "$DOWNLOAD_URL"; then
    echo -e "${RED}Error: Failed to download from ${DOWNLOAD_URL}${NC}"
    rm -f "$TEMP_FILE"
    exit 1
fi

# Make executable
chmod +x "$TEMP_FILE"

# Install
echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
if [ -w "$INSTALL_DIR" ]; then
    mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo -e "${YELLOW}Need sudo to install to ${INSTALL_DIR}${NC}"
    sudo mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
fi

# Verify installation
if command -v "$BINARY_NAME" &> /dev/null; then
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════╗"
    echo "║     Installation successful! 🎉       ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Run '${BINARY_NAME}' to start chatting!"
    echo ""
else
    echo -e "${YELLOW}Installed, but ${BINARY_NAME} not found in PATH.${NC}"
    echo "You may need to add ${INSTALL_DIR} to your PATH."
fi
