#!/bin/bash

# 🌸 Git Envware installer
# This script detects your OS/Arch, download the latest binary from GitHub,
# and installs it to your local system.

set -e

REPO="envware/envware-go"
BINARY_NAME="envw"

# 1. Detectar OS e Arquitetura
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# 2. Buscar última versão via GitHub API
echo "🔍 Checking for the latest version of Git Envware..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "❌ Could not find latest release. Please check the repository: https://github.com/$REPO"
    exit 1
fi

echo "🚀 Downloading Git Envware $LATEST_TAG for $OS ($ARCH)..."

# 3. Nome do arquivo
FILENAME="envware-$OS-$ARCH"
if [ "$OS" = "windows" ]; then
    FILENAME="$FILENAME.exe"
fi

URL="https://github.com/$REPO/download/$LATEST_TAG/$FILENAME"

# 4. Download
curl -L -o $BINARY_NAME $URL
chmod +x $BINARY_NAME

# 5. Instalação
echo "📦 Installing to /usr/local/bin (may require sudo)..."
if [ -w "/usr/local/bin" ]; then
    mv $BINARY_NAME /usr/local/bin/
    ln -sf /usr/local/bin/envw /usr/local/bin/git-envware
else
    sudo mv $BINARY_NAME /usr/local/bin/
    sudo ln -sf /usr/local/bin/envw /usr/local/bin/git-envware
fi

echo ""
echo "✅ Git Envware $LATEST_TAG installed successfully!"
echo "✨ Run 'envw --help' to get started."
echo "🚀 You can now use 'git envware pull' and 'git envware push'!"
