#!/bin/bash

# AnalysisAI Quick Start Script
# This script sets up and builds AnalysisAI on Linux systems

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AnalysisAI - Quick Start Installation Script           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This script is designed for Linux systems only."
    exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    echo "[*] Detected Debian/Ubuntu system"
    PACKAGE_MANAGER="apt"
    INSTALL_CMD="sudo apt-get install -y"
    UPDATE_CMD="sudo apt-get update"
elif command -v yum &> /dev/null; then
    echo "[*] Detected CentOS/RHEL system"
    PACKAGE_MANAGER="yum"
    INSTALL_CMD="sudo yum install -y"
    UPDATE_CMD="sudo yum update -y"
else
    echo "Error: Unsupported package manager. Please install dependencies manually."
    exit 1
fi

# Check for required tools
echo ""
echo "[*] Checking for required development tools..."

PACKAGES_TO_INSTALL=""

# Check gcc
if ! command -v gcc &> /dev/null; then
    echo "  - gcc not found"
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL build-essential"
else
    echo "  ✓ gcc found"
fi

# Check uuid
if ! pkg-config --exists uuid 2>/dev/null; then
    echo "  - libuuid not found"
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL uuid-dev"
    else
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL util-linux-ng-devel"
    fi
else
    echo "  ✓ libuuid found"
fi

# Check curl
if ! pkg-config --exists libcurl 2>/dev/null; then
    echo "  - libcurl not found"
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL libcurl4-openssl-dev"
    else
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL libcurl-devel"
    fi
else
    echo "  ✓ libcurl found"
fi

# Check cjson
if ! pkg-config --exists libcjson 2>/dev/null; then
    echo "  - libcjson not found"
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL libcjson-dev"
    else
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL cjson-devel"
    fi
else
    echo "  ✓ libcjson found"
fi

# Check ltrace
if ! command -v ltrace &> /dev/null; then
    echo "  - ltrace not found"
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL ltrace"
else
    echo "  ✓ ltrace found"
fi

# Install missing packages
if [[ -n "$PACKAGES_TO_INSTALL" ]]; then
    echo ""
    echo "[*] Installing missing packages..."
    echo "    Running: $UPDATE_CMD"
    eval $UPDATE_CMD
    echo "    Running: $INSTALL_CMD $PACKAGES_TO_INSTALL"
    eval $INSTALL_CMD $PACKAGES_TO_INSTALL
    echo "[✓] Packages installed"
else
    echo "[✓] All dependencies are already installed"
fi

# Build the project
echo ""
echo "[*] Building AnalysisAI..."
make clean
make

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                Installation Complete!                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Usage:"
echo "  ./AnalysisAI -b <binary_path> -m <model_type> -k <api_key>"
echo ""
echo "Examples:"
echo "  ./AnalysisAI -b /bin/ls -m openai -k sk-..."
echo "  ./AnalysisAI -b /usr/bin/curl -m claude -k sk-ant-..."
echo ""
echo "For more information, see README.md"
echo ""
