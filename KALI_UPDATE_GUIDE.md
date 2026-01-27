# 🚀 How to Update CTF-AI Ultimate on Kali Linux

**Version:** 2.1  
**Date:** January 27, 2026  
**Platform:** Kali Linux (also works on Debian/Ubuntu)

---

## 📋 Quick Update (Recommended)

### **Method 1: Using the Update Script** ⚡

```bash
cd /path/to/ctfhunter
chmod +x update.sh
./update.sh
```

**That's it!** The script will automatically:
- ✅ Pull latest changes from Git
- ✅ Update system packages
- ✅ Update Python dependencies
- ✅ Verify installation
- ✅ Test the tool

---

## 📝 Manual Update (Step by Step)

If you prefer to update manually or the script doesn't work:

### **Step 1: Navigate to Project Directory**

```bash
cd /path/to/ctfhunter
```

### **Step 2: Pull Latest Changes (if using Git)**

```bash
# Check current status
git status

# Pull latest changes
git pull origin main
# or
git pull origin master
```

**Not using Git?** Download the latest version:
```bash
# Backup your config first
cp config.json config.json.backup

# Download latest version
wget https://github.com/yourusername/ctf-ai-ultimate/archive/main.zip
unzip main.zip
cp -r ctf-ai-ultimate-main/* .

# Restore your config
cp config.json.backup config.json
```

### **Step 3: Update System Packages**

```bash
# Update package lists
sudo apt-get update

# Install/update required packages
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-magic \
    exiftool \
    binwalk \
    steghide \
    zsteg \
    tesseract-ocr \
    wireshark-common \
    tshark \
    nmap \
    sqlmap \
    john \
    hashcat
```

### **Step 4: Update Python Dependencies**

```bash
# Upgrade pip
python3 -m pip install --upgrade pip

# Install/update Python packages
python3 -m pip install -r requirements.txt --upgrade --break-system-packages
```

**Note:** The `--break-system-packages` flag is needed on Kali Linux because it uses an externally managed Python environment.

### **Step 5: Verify Installation**

```bash
# Test CTF-AI
python3 ctf-ai.py --help

# Test colors
python3 test_colors.py

# Test menu
python3 demo_menu.py
```

---

## 🎯 What's New in v2.1

### **New Features:**
- ✅ **Interactive Menu Mode** - 9 challenge categories
- ✅ **AI-Powered Guidance** - Tips for each challenge type
- ✅ **File Type Detection** - Auto-detect and analyze
- ✅ **Challenge Descriptions** - Add context for better AI analysis
- ✅ **Beautiful Colors** - Professional colorful interface
- ✅ **40+ Emojis** - Visual feedback everywhere

### **Try the New Menu:**
```bash
python3 ctf-ai.py
🤖 You: menu
```

---

## 🔧 Configuration

### **Edit Config File:**
```bash
nano config.json
```

### **Add Your API Keys:**
```json
{
  "ai_provider": "openai",
  "ai_model": "gpt-4",
  "openai_api_key": "sk-your-key-here",
  "anthropic_api_key": "your-claude-key",
  "groq_api_key": "your-groq-key"
}
```

### **AI Provider Options:**
- `openai` - GPT-4 (best, costs money)
- `ollama` - Local AI (free, needs setup)
- `claude` - Claude by Anthropic
- `groq` - Fast inference (free tier)
- `none` - Manual mode (no AI)

---

## 🐛 Troubleshooting

### **Problem: "externally-managed-environment" Error**

**Solution:** Use `--break-system-packages` flag:
```bash
python3 -m pip install -r requirements.txt --break-system-packages
```

### **Problem: Permission Denied**

**Solution:** Make scripts executable:
```bash
chmod +x ctf-ai.py ctfhunter.py update.sh
```

### **Problem: Module Not Found**

**Solution:** Install missing module:
```bash
python3 -m pip install module-name --break-system-packages
```

### **Problem: Git Conflicts**

**Solution:** Stash changes and pull:
```bash
git stash
git pull origin main
git stash pop
```

### **Problem: Colors Not Showing**

**Solution:** Ensure terminal supports ANSI colors:
```bash
# Test colors
python3 -c "from modules.colors import *; print_success('Colors work!')"
```

---

## 📦 Dependencies

### **System Packages:**
```
python3, python3-pip, python3-magic, exiftool, binwalk,
steghide, zsteg, tesseract-ocr, wireshark-common, tshark,
nmap, sqlmap, john, hashcat, aircrack-ng, hydra, nikto,
dirb, gobuster, ffuf
```

### **Python Packages:**
```
openai, anthropic, groq, requests, python-magic, pyyaml,
pillow, pycryptodome, scapy, beautifulsoup4, lxml
```

---

## 🚀 Quick Start After Update

### **1. Interactive Mode:**
```bash
python3 ctf-ai.py
```

### **2. Menu Mode:**
```bash
python3 ctf-ai.py
🤖 You: menu
# Select challenge type, enter file, get AI guidance!
```

### **3. Direct Solve:**
```bash
python3 ctf-ai.py --solve challenge.png
```

### **4. CTFHunter:**
```bash
python3 ctfhunter.py challenge.zip
```

### **5. Test Colors:**
```bash
python3 test_colors.py
```

---

## 📚 Documentation

### **Available Guides:**
- `README.md` - Main documentation
- `QUICKSTART.md` - Quick start guide
- `MENU_MODE_DOCUMENTATION.md` - Menu feature guide
- `FINAL_UPDATE_SUMMARY.md` - Complete changelog
- `FAQ.md` - Frequently asked questions

### **View Documentation:**
```bash
cat README.md
cat MENU_MODE_DOCUMENTATION.md
```

---

## 🔄 Update Frequency

### **Recommended:**
- **Weekly** - Check for updates
- **Before CTF** - Update before competitions
- **After Issues** - Update if you encounter bugs

### **Check for Updates:**
```bash
cd /path/to/ctfhunter
git fetch origin
git status
```

---

## 🎯 Advanced: Ollama Setup (Local AI)

If you want to use **free local AI** instead of paid APIs:

### **1. Install Ollama:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### **2. Download a Model:**
```bash
ollama pull llama3
# or
ollama pull codellama
```

### **3. Update Config:**
```json
{
  "ai_provider": "ollama",
  "ai_model": "llama3",
  "ollama_base_url": "http://localhost:11434"
}
```

### **4. Test:**
```bash
python3 ctf-ai.py --solve test.png
```

---

## 📊 Verification Checklist

After updating, verify everything works:

- [ ] `python3 ctf-ai.py --help` works
- [ ] `python3 test_colors.py` shows colors
- [ ] `python3 demo_menu.py` displays menu
- [ ] Config file exists (`config.json`)
- [ ] Output directory exists (`output/`)
- [ ] All modules import correctly
- [ ] AI provider is configured
- [ ] Colors display in terminal

---

## 🆘 Getting Help

### **Check Logs:**
```bash
python3 ctf-ai.py --solve test.png 2>&1 | tee debug.log
```

### **Test Individual Components:**
```bash
# Test color module
python3 -c "from modules.colors import *; print_success('OK')"

# Test AI engine
python3 -c "from modules.ai_engine import AIEngine; print('OK')"
```

### **Community Support:**
- GitHub Issues: Report bugs
- Discord: Ask questions
- Documentation: Read guides

---

## ✅ Post-Update Tasks

### **1. Update API Keys** (if needed)
```bash
nano config.json
```

### **2. Test with Sample Challenge**
```bash
# Download a test challenge
wget https://example.com/test-challenge.png

# Solve it
python3 ctf-ai.py --solve test-challenge.png
```

### **3. Try New Menu Mode**
```bash
python3 ctf-ai.py
🤖 You: menu
```

### **4. Read Changelog**
```bash
cat FINAL_UPDATE_SUMMARY.md
```

---

## 🎉 You're All Set!

Your CTF-AI Ultimate is now updated to **v2.1** with:

- ✅ Interactive menu mode
- ✅ AI-powered guidance
- ✅ Beautiful colors
- ✅ 9 challenge categories
- ✅ Latest features

**Happy Hacking!** 🚀

---

## 📝 Quick Reference

### **Update Command:**
```bash
cd /path/to/ctfhunter && ./update.sh
```

### **Run CTF-AI:**
```bash
python3 ctf-ai.py
```

### **Use Menu:**
```bash
python3 ctf-ai.py
🤖 You: menu
```

### **Get Help:**
```bash
python3 ctf-ai.py --help
```

---

**Last Updated:** January 27, 2026  
**Version:** 2.1  
**Platform:** Kali Linux
