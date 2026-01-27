# 🚀 Complete Auto-Installer for All Tools

## ⚡ One Command to Install Everything!

```bash
cd ~/ctf-ai-ultimate
chmod +x install_all_tools.sh
sudo ./install_all_tools.sh
```

**That's it!** This will automatically install **ALL** tools needed for CTF-AI Ultimate!

---

## 📦 What Gets Installed

### **Core Tools:**
- ✅ Python 3, pip, build tools
- ✅ file, strings, binwalk, exiftool
- ✅ Archive tools (7z, unzip, tar, unrar)

### **Steganography Tools:**
- ✅ steghide - Hide/extract data from images
- ✅ stegseek - Fast steghide cracker
- ✅ zsteg - PNG/BMP steganography detector
- ✅ outguess - JPEG steganography
- ✅ stegoveritas - Image analysis

### **Network Analysis:**
- ✅ tshark - Command-line Wireshark
- ✅ tcpdump - Packet capture
- ✅ nmap - Network scanner

### **Binary Analysis:**
- ✅ gdb - GNU Debugger
- ✅ radare2 - Reverse engineering
- ✅ checksec - Security checker
- ✅ ltrace, strace - System call tracers
- ✅ pwntools - Exploit development

### **PDF Analysis:**
- ✅ pdfinfo, pdftotext - PDF utilities
- ✅ peepdf - PDF analysis framework
- ✅ qpdf - PDF transformation

### **Disk Forensics:**
- ✅ sleuthkit - File system analysis
- ✅ autopsy - Digital forensics
- ✅ testdisk, photorec - File recovery
- ✅ volatility - Memory forensics

### **Web Analysis:**
- ✅ nikto - Web scanner
- ✅ dirb, gobuster, ffuf - Directory bruteforce
- ✅ sqlmap - SQL injection
- ✅ wfuzz - Web fuzzer

### **Cryptography:**
- ✅ john - Password cracker
- ✅ hashcat - Hash cracker
- ✅ aircrack-ng - WiFi cracking
- ✅ hydra - Login bruteforcer
- ✅ hashid - Hash identifier

### **OCR:**
- ✅ tesseract - Text recognition

### **Python Packages:**
- ✅ openai, anthropic, groq - AI providers
- ✅ requests, beautifulsoup4 - Web scraping
- ✅ python-magic - File type detection
- ✅ pillow - Image processing
- ✅ pycryptodome - Cryptography
- ✅ scapy - Packet manipulation
- ✅ pyyaml - YAML parsing

---

## 🎯 Installation Steps

The script automatically:

1. ✅ Updates package lists
2. ✅ Installs core system tools
3. ✅ Installs steganography tools (including zsteg via gem)
4. ✅ Installs network analysis tools
5. ✅ Installs binary analysis tools
6. ✅ Installs PDF analysis tools
7. ✅ Installs disk forensics tools
8. ✅ Installs web analysis tools
9. ✅ Installs cryptography tools
10. ✅ Installs OCR tools
11. ✅ Installs Python dependencies
12. ✅ Sets up configuration
13. ✅ Verifies installation

---

## ✅ After Installation

### **Test Everything:**
```bash
python3 check_dependencies.py
```

### **Try CTF-AI:**
```bash
python3 ctf-ai.py
🤖 You: menu
```

### **Solve a Challenge:**
```bash
python3 ctf-ai.py --solve challenge.png
```

---

## 🐛 If Something Fails

The script handles errors gracefully:
- ✅ Skips packages not in repos
- ✅ Tries alternative installation methods
- ✅ Continues even if optional tools fail
- ✅ Shows clear error messages

### **Manual Fix:**
```bash
# If a specific tool failed, install manually:
sudo apt-get install tool-name

# Or for Python packages:
python3 -m pip install package-name --break-system-packages
```

---

## 📊 Disk Space Required

- **Minimum:** ~500 MB
- **Recommended:** ~1 GB (with all optional tools)

---

## ⏱️ Installation Time

- **Fast connection:** ~5-10 minutes
- **Slow connection:** ~15-20 minutes

---

## 🎉 You're Ready!

After installation, you'll have:
- ✅ **50+ security tools** installed
- ✅ **All Python dependencies** ready
- ✅ **CTF-AI Ultimate** fully functional
- ✅ **Interactive menu mode** working
- ✅ **AI-powered guidance** available

**Happy Hacking!** 🚀
