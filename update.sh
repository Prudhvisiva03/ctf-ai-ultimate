#!/bin/bash
# CTF-AI Ultimate - Kali Linux Update Script
# Version: 2.1
# Date: 2026-01-27

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Emojis
SUCCESS="✅"
ERROR="❌"
INFO="ℹ️"
ROCKET="🚀"
WRENCH="🔧"
PACKAGE="📦"

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}           ${YELLOW}🚀 CTF-AI ULTIMATE UPDATE SCRIPT 🚀${NC}             ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                     ${BLUE}Version 2.1${NC}                          ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running on Kali Linux
if [ ! -f /etc/os-release ] || ! grep -q "Kali" /etc/os-release; then
    echo -e "${YELLOW}${INFO} Warning: This script is designed for Kali Linux${NC}"
    echo -e "${INFO} It may work on other Debian-based systems${NC}"
    echo ""
fi

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 1: Pulling Latest Changes from Git${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if git repository
if [ -d .git ]; then
    echo -e "${INFO} Fetching latest changes..."
    git fetch origin
    
    echo -e "${INFO} Checking for updates..."
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")
    
    if [ -z "$REMOTE" ]; then
        echo -e "${YELLOW}${INFO} No remote branch configured${NC}"
        echo -e "${INFO} Skipping git update${NC}"
    elif [ "$LOCAL" = "$REMOTE" ]; then
        echo -e "${GREEN}${SUCCESS} Already up to date!${NC}"
    else
        echo -e "${YELLOW}${INFO} Updates available, pulling changes...${NC}"
        git pull origin main || git pull origin master
        echo -e "${GREEN}${SUCCESS} Git repository updated!${NC}"
    fi
else
    echo -e "${YELLOW}${INFO} Not a git repository${NC}"
    echo -e "${INFO} If you want to use git updates, clone the repository:${NC}"
    echo -e "${CYAN}    git clone https://github.com/yourusername/ctf-ai-ultimate.git${NC}"
fi

echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 2: Updating System Packages${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Updating package lists..."
sudo apt-get update -qq

echo -e "${INFO} Installing/updating system dependencies..."
sudo apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    python3-magic \
    libmagic1 \
    exiftool \
    binwalk \
    foremost \
    steghide \
    zsteg \
    stegseek \
    outguess \
    tesseract-ocr \
    wireshark-common \
    tshark \
    tcpdump \
    nmap \
    sqlmap \
    john \
    hashcat \
    aircrack-ng \
    hydra \
    nikto \
    dirb \
    gobuster \
    ffuf \
    git \
    curl \
    wget

echo -e "${GREEN}${SUCCESS} System packages updated!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 3: Updating Python Dependencies${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Upgrading pip..."
python3 -m pip install --upgrade pip --quiet

echo -e "${INFO} Installing/updating Python packages..."
if [ -f requirements.txt ]; then
    # Use --break-system-packages for Kali Linux (externally managed environment)
    python3 -m pip install -r requirements.txt --upgrade --break-system-packages --quiet
    echo -e "${GREEN}${SUCCESS} Python dependencies updated from requirements.txt!${NC}"
else
    echo -e "${YELLOW}${INFO} requirements.txt not found, installing core packages...${NC}"
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
        lxml
    echo -e "${GREEN}${SUCCESS} Core Python packages installed!${NC}"
fi

echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 4: Updating Configuration${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if config.json exists
if [ ! -f config.json ]; then
    if [ -f config.example.json ]; then
        echo -e "${INFO} Creating config.json from example..."
        cp config.example.json config.json
        echo -e "${GREEN}${SUCCESS} config.json created!${NC}"
        echo -e "${YELLOW}${INFO} Please edit config.json to add your API keys${NC}"
    else
        echo -e "${YELLOW}${INFO} No config file found${NC}"
    fi
else
    echo -e "${GREEN}${SUCCESS} config.json already exists${NC}"
fi

# Create output directory if it doesn't exist
if [ ! -d output ]; then
    echo -e "${INFO} Creating output directory..."
    mkdir -p output
    echo -e "${GREEN}${SUCCESS} output directory created!${NC}"
fi

echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 5: Setting Permissions${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Making scripts executable..."
chmod +x ctf-ai.py 2>/dev/null || true
chmod +x ctfhunter.py 2>/dev/null || true
chmod +x install.sh 2>/dev/null || true
chmod +x update.sh 2>/dev/null || true
chmod +x setup.sh 2>/dev/null || true

echo -e "${GREEN}${SUCCESS} Permissions set!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 6: Verifying Installation${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Checking Python version..."
PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}${SUCCESS} $PYTHON_VERSION${NC}"

echo -e "${INFO} Checking core modules..."
python3 -c "import magic; print('${SUCCESS} python-magic: OK')" 2>/dev/null || echo -e "${ERROR} python-magic: FAILED"
python3 -c "import yaml; print('${SUCCESS} PyYAML: OK')" 2>/dev/null || echo -e "${ERROR} PyYAML: FAILED"
python3 -c "import PIL; print('${SUCCESS} Pillow: OK')" 2>/dev/null || echo -e "${ERROR} Pillow: FAILED"

echo -e "${INFO} Checking CTF-AI modules..."
python3 -c "import sys; sys.path.insert(0, 'modules'); from colors import *; print('${SUCCESS} colors module: OK')" 2>/dev/null || echo -e "${ERROR} colors module: FAILED"

echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 7: Testing CTF-AI${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${INFO} Running quick test..."
python3 ctf-ai.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}${SUCCESS} CTF-AI is working correctly!${NC}"
else
    echo -e "${YELLOW}${INFO} CTF-AI test returned non-zero exit code${NC}"
    echo -e "${INFO} This might be normal, check manually with: python3 ctf-ai.py --help${NC}"
fi

echo ""

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                                                               ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}           ${GREEN}${SUCCESS} UPDATE COMPLETE! ${SUCCESS}${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                               ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}What's New in v2.1:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${SUCCESS} Interactive Menu Mode - 9 challenge categories"
echo -e "  ${SUCCESS} AI-Powered Guidance - Tips for each type"
echo -e "  ${SUCCESS} File Type Detection - Auto-detect and analyze"
echo -e "  ${SUCCESS} Challenge Descriptions - Add context for AI"
echo -e "  ${SUCCESS} Beautiful Colors - Professional interface"
echo -e "  ${SUCCESS} 40+ Emojis - Visual feedback everywhere"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${ROCKET} Interactive mode:    ${CYAN}python3 ctf-ai.py${NC}"
echo -e "  ${ROCKET} Menu mode:           ${CYAN}python3 ctf-ai.py${NC} then type ${YELLOW}'menu'${NC}"
echo -e "  ${ROCKET} Direct solve:        ${CYAN}python3 ctf-ai.py --solve challenge.png${NC}"
echo -e "  ${ROCKET} CTFHunter:           ${CYAN}python3 ctfhunter.py challenge.zip${NC}"
echo -e "  ${ROCKET} Test colors:         ${CYAN}python3 test_colors.py${NC}"
echo -e "  ${ROCKET} Demo menu:           ${CYAN}python3 demo_menu.py${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Configuration:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${WRENCH} Edit config:         ${CYAN}nano config.json${NC}"
echo -e "  ${WRENCH} Add API keys:        Set openai_api_key, anthropic_api_key, etc."
echo -e "  ${WRENCH} Change AI provider:  Set ai_provider to 'openai', 'ollama', 'claude', or 'groq'"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Documentation:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${PACKAGE} README.md                    - Main documentation"
echo -e "  ${PACKAGE} QUICKSTART.md                - Quick start guide"
echo -e "  ${PACKAGE} MENU_MODE_DOCUMENTATION.md   - Menu feature guide"
echo -e "  ${PACKAGE} FINAL_UPDATE_SUMMARY.md      - Complete changelog"
echo ""

echo -e "${GREEN}${SUCCESS} Happy Hacking! ${SUCCESS}${NC}"
echo ""
