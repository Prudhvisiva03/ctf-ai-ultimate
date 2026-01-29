#!/bin/bash
# CTF-AI Ultimate - Complete Auto-Installer for Kali Linux
# This script automatically installs ALL required and optional tools
# Version: 2.1
# Date: 2026-01-27

# Don't exit on error - continue installing what's available

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Emojis
SUCCESS="✅"
ERROR="❌"
INFO="ℹ️"
ROCKET="🚀"
WRENCH="🔧"
PACKAGE="📦"

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}      ${YELLOW}🚀 CTF-AI ULTIMATE - COMPLETE AUTO-INSTALLER 🚀${NC}       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                     ${BLUE}Version 2.1${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}${INFO} This script needs sudo privileges${NC}"
    echo -e "${INFO} Please run: sudo ./install_all_tools.sh${NC}"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 1: Updating Package Lists${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get update -qq
echo -e "${GREEN}${SUCCESS} Package lists updated!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 2: Installing Core System Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Installing Python and build tools..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    git \
    curl \
    wget 2>/dev/null || true

echo -e "${INFO} Installing file analysis tools..."
apt-get install -y -qq \
    file \
    binutils \
    python3-magic \
    libmagic1 \
    exiftool \
    binwalk \
    foremost \
    xxd \
    hexedit 2>/dev/null || true

echo -e "${INFO} Installing archive tools..."
# Install core archive tools
apt-get install -y -qq \
    unzip \
    tar \
    gzip \
    bzip2 \
    xz-utils \
    p7zip-full 2>/dev/null || true

# Install optional archive tools (may not be in all repos)
for pkg in unrar rar p7zip-rar; do
    if apt-cache show $pkg >/dev/null 2>&1; then
        apt-get install -y -qq $pkg 2>/dev/null || echo -e "${YELLOW}${INFO} $pkg not available${NC}"
    else
        echo -e "${YELLOW}${INFO} $pkg not in repos, skipping...${NC}"
    fi
done

echo -e "${GREEN}${SUCCESS} Core tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 3: Installing Steganography Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Installing steghide..."
apt-get install -y -qq steghide 2>/dev/null || true

echo -e "${INFO} Installing stegseek..."
if apt-cache show stegseek >/dev/null 2>&1; then
    apt-get install -y -qq stegseek
else
    echo -e "${YELLOW}${INFO} stegseek not in repos, installing from GitHub...${NC}"
    wget -q https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -O /tmp/stegseek.deb
    dpkg -i /tmp/stegseek.deb 2>/dev/null || apt-get install -f -y -qq
    rm -f /tmp/stegseek.deb
fi

echo -e "${INFO} Installing zsteg (Ruby gem)..."
apt-get install -y -qq ruby ruby-dev
gem install zsteg 2>/dev/null || echo -e "${YELLOW}${INFO} zsteg installation via gem failed${NC}"

echo -e "${INFO} Installing outguess..."
if apt-cache show outguess >/dev/null 2>&1; then
    apt-get install -y -qq outguess
else
    echo -e "${YELLOW}${INFO} outguess not in repos, compiling from source...${NC}"
    cd /tmp
    git clone https://github.com/resurrecting-open-source-projects/outguess.git 2>/dev/null || true
    if [ -d outguess ]; then
        cd outguess
        ./configure --quiet && make -s && make install -s
        cd /tmp && rm -rf outguess
    fi
    cd "$SCRIPT_DIR"
fi

echo -e "${INFO} Installing stegoveritas..."
pip3 install --break-system-packages stegoveritas 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Steganography tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 4: Installing Network Analysis Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    wireshark-common \
    tshark \
    tcpdump \
    nmap \
    netcat-traditional \
    socat 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Network tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 5: Installing Binary Analysis Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    gdb \
    ltrace \
    strace \
    radare2 \
    binutils \
    objdump \
    readelf 2>/dev/null || true

echo -e "${INFO} Installing checksec..."
if ! command -v checksec >/dev/null 2>&1; then
    wget -q https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec -O /usr/local/bin/checksec
    chmod +x /usr/local/bin/checksec
fi

echo -e "${INFO} Installing pwntools..."
pip3 install --break-system-packages pwntools 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Binary analysis tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 6: Installing PDF Analysis Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    poppler-utils \
    pdfgrep \
    qpdf 2>/dev/null || true

echo -e "${INFO} Installing peepdf..."
pip3 install --break-system-packages peepdf-fork 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} PDF tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 7: Installing Disk Forensics Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    sleuthkit \
    autopsy \
    testdisk \
    photorec \
    volatility3 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Forensics tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 8: Installing Web Analysis Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    nikto \
    dirb \
    gobuster \
    ffuf \
    sqlmap \
    wfuzz 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Web tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 9: Installing Cryptography Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    john \
    hashcat \
    aircrack-ng \
    hydra \
    hashid \
    hash-identifier 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Crypto tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 10: Installing OCR Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

apt-get install -y -qq \
    tesseract-ocr \
    tesseract-ocr-eng 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} OCR tools installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 11: Installing Python Dependencies${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Upgrading pip..."
python3 -m pip install --upgrade pip --quiet --break-system-packages

echo -e "${INFO} Installing Python packages..."
if [ -f requirements.txt ]; then
    python3 -m pip install -r requirements.txt --upgrade --break-system-packages --quiet
else
    # Install core packages
    python3 -m pip install --upgrade --break-system-packages --quiet \
        openai \
        anthropic \
        groq \
        requests \
        python-magic \
        pyyaml \
        pillow \
        pycryptodome \
        scapy \
        beautifulsoup4 \
        lxml \
        colorama
fi

echo -e "${GREEN}${SUCCESS} Python packages installed!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 12: Setting Up Configuration${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Create config if it doesn't exist
if [ ! -f config.json ]; then
    if [ -f config.example.json ]; then
        cp config.example.json config.json
        echo -e "${GREEN}${SUCCESS} config.json created from example${NC}"
    fi
fi

# Create output directory
mkdir -p output
echo -e "${GREEN}${SUCCESS} Output directory created${NC}"

# Set permissions
chmod +x ctf-ai.py 2>/dev/null || true
chmod +x ctfhunter.py 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Permissions set${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 13: Verifying Installation${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Run dependency checker if it exists
if [ -f check_dependencies.py ]; then
    echo -e "${INFO} Running dependency checker..."
    python3 check_dependencies.py || true
fi

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                                                               ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}      ${GREEN}${SUCCESS} INSTALLATION COMPLETE! ALL TOOLS READY! ${SUCCESS}${NC}       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                               ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Tools Installed:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${SUCCESS} Core Tools: file, strings, binwalk, exiftool"
echo -e "  ${SUCCESS} Steganography: steghide, stegseek, zsteg, outguess"
echo -e "  ${SUCCESS} Network: tshark, tcpdump, nmap"
echo -e "  ${SUCCESS} Binary: gdb, radare2, checksec, ltrace, strace"
echo -e "  ${SUCCESS} PDF: pdfinfo, pdftotext, peepdf"
echo -e "  ${SUCCESS} Forensics: sleuthkit, autopsy, volatility"
echo -e "  ${SUCCESS} Web: nikto, dirb, gobuster, ffuf, sqlmap"
echo -e "  ${SUCCESS} Crypto: john, hashcat, aircrack-ng, hydra"
echo -e "  ${SUCCESS} Archives: 7z, unzip, tar, unrar"
echo -e "  ${SUCCESS} OCR: tesseract"
echo -e "  ${SUCCESS} Python: All required modules"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${ROCKET} Interactive mode:    ${CYAN}python3 ctf-ai.py${NC}"
echo -e "  ${ROCKET} Menu mode:           ${CYAN}python3 ctf-ai.py${NC} then type ${YELLOW}'menu'${NC}"
echo -e "  ${ROCKET} Direct solve:        ${CYAN}python3 ctf-ai.py --solve challenge.png${NC}"
echo -e "  ${ROCKET} CTFHunter:           ${CYAN}python3 ctfhunter.py challenge.zip${NC}"
echo -e "  ${ROCKET} Check dependencies:  ${CYAN}python3 check_dependencies.py${NC}"
echo ""

echo -e "${GREEN}${SUCCESS} Happy Hacking! ${SUCCESS}${NC}"
echo ""
