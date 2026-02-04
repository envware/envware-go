#!/bin/bash

# Script para gerar binários do envware 2.0 para múltiplas plataformas
# 🌸 Foco: Mac (Intel/Apple) e Linux (x64/ARM)

set -e

APP_NAME="envware"
OUT_DIR="./dist"

mkdir -p $OUT_DIR

echo "🚀 Building for macOS (Apple Silicon)..."
GOOS=darwin GOARCH=arm64 go build -o $OUT_DIR/$APP_NAME-darwin-arm64 main.go

echo "🚀 Building for macOS (Intel)..."
GOOS=darwin GOARCH=amd64 go build -o $OUT_DIR/$APP_NAME-darwin-amd64 main.go

echo "🚀 Building for Linux (x64)..."
GOOS=linux GOARCH=amd64 go build -o $OUT_DIR/$APP_NAME-linux-amd64 main.go

echo "🚀 Building for Linux (ARM64)..."
GOOS=linux GOARCH=arm64 go build -o $OUT_DIR/$APP_NAME-linux-arm64 main.go

echo "🚀 Building for Windows (x64)..."
GOOS=windows GOARCH=amd64 go build -o $OUT_DIR/$APP_NAME-windows-amd64.exe main.go

echo "✨ All binaries are in $OUT_DIR/ 🌸"
ls -lh $OUT_DIR
