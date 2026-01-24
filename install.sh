#!/bin/bash

# CTFHunter Ultimate - Installation Script for Kali Linux
# This script installs all required dependencies and sets up CTFHunter

echo "================================================================"
echo "CTFHunter Ultimate - Installation Script"
echo "================================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (use sudo ./install.sh)"
    exit 1
fi

echo "[*] Updating package lists..."
apt-get update -qq

echo ""
echo "[*] Installing system dependencies..."

# Core tools
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-magic \
    file \
    binwalk \
    exiftool \
    strings \
    foremost

# Steganography tools
echo ""
echo "[*] Installing steganography tools..."
apt-get install -y -qq \
    steghide \
    stegseek \
    zsteg

# Archive tools
echo ""
echo "[*] Installing archive tools..."
apt-get install -y -qq \
    unzip \
    tar \
    gzip \
    bzip2 \
    p7zip-full \
    unrar

# Network analysis tools
echo ""
echo "[*] Installing network analysis tools..."
apt-get install -y -qq \
    tshark \
    wireshark-common \
    tcpdump

# Binary analysis tools
echo ""
echo "[*] Installing binary analysis tools..."
apt-get install -y -qq \
    binutils \
    checksec \
    gdb \
    radare2 \
    ltrace \
    strace

# PDF tools
echo ""
echo "[*] Installing PDF analysis tools..."
apt-get install -y -qq \
    poppler-utils \
    pdfinfo

# Web tools (optional)
echo ""
echo "[*] Installing web reconnaissance tools..."
apt-get install -y -qq \
    curl \
    wget \
    nikto \
    dirsearch 2>/dev/null || echo "[!] dirsearch not available in repos (install manually if needed)"

# Python dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --quiet

# Make scripts executable
echo ""
echo "[*] Setting executable permissions..."
chmod +x ctfhunter.py
chmod +x ctf-ai.py

# Create symbolic links for global access
echo ""
echo "[*] Creating global commands..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ln -sf "$SCRIPT_DIR/ctfhunter.py" /usr/local/bin/ctfhunter
ln -sf "$SCRIPT_DIR/ctf-ai.py" /usr/local/bin/ctf-ai

# Create output directory
mkdir -p output
mkdir -p playbooks

echo ""
echo "================================================================"
echo "✅ Installation Complete!"
echo "================================================================"
echo ""
echo "You can now use CTFHunter with:"
echo ""
echo "  🤖 ctf-ai                   # Interactive AI assistant (NEW!)"
echo "  🔧 ctfhunter <file_or_url>  # Direct file analysis"
echo ""
echo "Examples:"
echo "  ctf-ai                      # Start interactive mode"
echo "  ctf-ai --solve challenge.png"
echo "  ctfhunter capture.pcap"
echo ""
echo "🤖 AI Setup (Optional but Recommended):"
echo "Edit config.json to set your AI provider:"
echo "  - OpenAI (GPT-4): Set 'openai_api_key'"
echo "  - Ollama (FREE): Install from https://ollama.ai"
echo "  - Claude: Set 'claude_api_key'"
echo "  - Groq: Set 'groq_api_key'"
echo "  - None: Works without AI (manual mode)"
echo ""
echo "================================================================"
