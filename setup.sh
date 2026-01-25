#!/bin/bash
# CTF-AI Ultimate - Complete Setup Script for Linux/Kali
# Run this after: git clone https://github.com/Prudhvisiva03/ctf-ai-ultimate

set -e  # Exit on error

echo "🚀 CTF-AI Ultimate - Automated Setup"
echo "======================================"
echo ""

# 1. Install system dependencies
echo "[1/5] Installing system dependencies..."
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-magic \
    binwalk \
    foremost \
    libimage-exiftool-perl \
    steghide \
    binutils \
    file \
    p7zip-full \
    sleuthkit \
    ruby \
    ruby-dev \
    build-essential

# Install zsteg via gem (Ruby package manager)
echo "   Installing zsteg..."
sudo gem install zsteg 2>/dev/null || echo "   ⚠️  zsteg install failed (optional)"

# 2. Install Python packages
echo "[2/5] Installing Python packages..."
pip install --break-system-packages \
    groq \
    python-magic \
    Pillow \
    pytesseract

# 3. Create config.json from example
echo "[3/5] Creating config.json..."
if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "⚠️  Please edit config.json and add your API keys!"
else
    echo "✅ config.json already exists"
fi

# 4. Copy config for sudo access
echo "[4/5] Setting up sudo access..."
sudo cp config.json /root/ 2>/dev/null || true

# 5. Install the tool
echo "[5/5] Installing ctf-ai command..."
sudo pip install --break-system-packages -e .

echo ""
echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Edit config.json and add your Groq API key"
echo "2. Test: ctf-ai --solve <challenge_file>"
echo ""
echo "🎯 Example:"
echo "   ctf-ai --solve challenge.dd.gz"
echo ""
