#!/bin/bash

# 🌸 envware installer
# This script detects your OS/Arch, downloads the latest binary from GitHub,
# and installs it to your local system.

set -e

REPO="envware/envware-go" # Nome oficial do repositório
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
echo "🔍 Checking for the latest version of envware-go..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "❌ Could not find latest release. Please check the repository: https://github.com/$REPO"
    echo "💡 Make sure you have created at least one Release on GitHub!"
    exit 1
fi

echo "🚀 Downloading envware $LATEST_TAG for $OS ($ARCH)..."

# 3. Nome do arquivo (Seguindo o padrão do build-all.sh)
FILENAME="envware-$OS-$ARCH"
if [ "$OS" = "windows" ]; then
    FILENAME="$FILENAME.exe"
fi

URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$FILENAME"

# 4. Download
curl -L -o $BINARY_NAME $URL
chmod +x $BINARY_NAME

# 5. Instalação
echo "📦 Installing to /usr/local/bin (may require sudo)..."
if [ -w "/usr/local/bin" ]; then
    mv $BINARY_NAME /usr/local/bin/
    ln -sf /usr/local/bin/envw /usr/local/bin/git-envware
    ln -sf /usr/local/bin/envw /usr/local/bin/git-envw
else
    sudo mv $BINARY_NAME /usr/local/bin/
    sudo ln -sf /usr/local/bin/envw /usr/local/bin/git-envware
    sudo ln -sf /usr/local/bin/envw /usr/local/bin/git-envw
fi

echo ""
echo "🌸 envware 2.1.5 (Go Engine) installed successfully!"
echo "✨ Run 'envw status <team>' to get started."
echo "🚀 Git Integration: You can now use 'git envware pull' and 'git envware push'!"
echo "💎 Welcome to the Zero-Trust future."
