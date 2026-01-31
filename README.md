# 🏴‍☠️ CTFHunter Ultimate

**The World's First AI-Powered CTF Solver with IN-DEPTH Analysis** 🐉

[![Version](https://img.shields.io/badge/version-2.5-blue.svg)](https://github.com/Prudhvisiva03/ctfhunter)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Kali](https://img.shields.io/badge/Kali-Linux-557C94.svg)](https://kali.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

---

## 🔬 IN-DEPTH Analysis Mode

CTFHunter v2.5 introduces **comprehensive in-depth analysis** that examines files at every layer:

| Deep Module | What It Does |
|-------------|--------------|
| 🔍 **DeepAnalyzer** | Byte-level hex analysis, entropy detection, multi-layer decoding (Base64→Hex→ROT13→etc), embedded file extraction, pattern recognition |
| 🖼️ **DeepStego** | PNG chunk parsing, JPEG marker analysis, LSB extraction on all 8 bit planes, color channel separation, data-after-EOF detection |
| 🔐 **DeepCrypto** | Tries 25+ cipher types automatically: Caesar, Vigenere, Affine, Playfair, XOR (single/multi-byte), Rail Fence, Columnar, Beaufort, Bacon, Morse, A1Z26 |
| 🕵️ **DeepForensics** | File structure analysis, metadata extraction, hidden data detection, anomaly detection, timestamp analysis |
| 📡 **DeepNetwork** | TCP stream analysis, HTTP/DNS/FTP/SMTP extraction, credential hunting, file export, DNS tunneling detection |

---

## 🚀 Quick Start

```bash
# Interactive menu mode (recommended)
python3 ctfhunter.py

# AI Auto-Solve mode (tries all techniques)
python3 ctfhunter.py --solve challenge.png

# Quick scan
python3 ctfhunter.py challenge.png

# Web reconnaissance
python3 ctfhunter.py https://target.com
```

---

## 🛠️ Installation on Kali Linux

```bash
# Clone the repository
git clone https://github.com/Prudhvisiva03/ctfhunter.git
cd ctfhunter

# Install Python dependencies
pip3 install -r requirements.txt

# Install CTF tools (run from menu or manually)
sudo apt install steghide stegseek binwalk foremost exiftool
sudo gem install zsteg

# Run CTFHunter
python3 ctfhunter.py
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🤖 **AI Auto-Solve** | Automatically tries multiple techniques to find flags |
| 🔬 **IN-DEPTH Analysis** | Byte-level, multi-layer, comprehensive analysis |
| 🔍 **Manual Mode** | Choose specific techniques (30+ CTF challenge types) |
| 🖼️ **Steganography** | PNG, JPG, GIF, Audio, Video stego analysis |
| 📦 **Forensics** | File analysis, archives, PDF, disk images, memory dumps |
| 📡 **Network** | PCAP analysis, network recon |
| 💻 **Reverse Engineering** | ELF, PE, APK, .NET/Java analysis |
| 🔐 **Cryptography** | Encoding, classical/modern ciphers, hash cracking |
| 🌐 **Web** | Recon, SQLi, XSS, directory busting |
| 🔎 **OSINT** | Image, username, domain OSINT |
| 🛠️ **Auto-Install** | One-click install all CTF tools |
| 💾 **Memory Forensics** | Volatility integration for memory dumps |
| 🎬 **Video Stego** | Extract hidden data from video files |
| 📋 **Log Analysis** | Parse and analyze log files for CTF clues |
| 🦠 **Malware Analysis** | Basic static analysis for suspicious files |
| 🔐 **Advanced Ciphers** | Playfair, Beaufort, Affine, Bacon, Bifid, etc. |

---

## 📁 Project Structure

```
ctfhunter/
├── ctfhunter.py        # 🎯 Main entry point
├── ctf-ai.py           # 🤖 AI-powered solver
├── ctf.py              # 📋 Interactive menu mode
├── install_tools.py    # 🛠️ Auto-install all tools
├── modules/            # Analysis modules
│   ├── ai_solver.py    # AI auto-solve engine
│   ├── file_scan.py
│   ├── stego_scan.py
│   ├── cipher_cracker.py
│   ├── deep_analyzer.py     # NEW: In-depth byte-level analysis
│   ├── deep_stego.py        # NEW: In-depth steganography
│   ├── deep_crypto.py       # NEW: In-depth cryptanalysis
│   ├── deep_forensics.py    # NEW: In-depth forensics
│   ├── deep_network.py      # NEW: In-depth network analysis
│   ├── advanced_ciphers.py  # Playfair, Affine, Bacon, etc.
│   ├── memory_forensics.py  # Volatility integration
│   ├── video_stego.py       # Video steganography
│   ├── log_analyzer.py      # Log file analysis
│   ├── malware_analyzer.py  # Basic malware analysis
│   └── ...
├── playbooks/          # Auto-analysis playbooks
├── config/             # Configuration files
├── tools/              # Installation scripts
└── output/             # Analysis results
```

---

## 🎯 Usage Examples

### AI Auto-Solve Mode
```bash
$ python3 ctfhunter.py --solve challenge.png

🤖 CTFHunter AI SOLVER - Automatic Challenge Analysis
======================================================================

📋 STEP 1: Universal Analysis Techniques
  [+] Found 1523 strings
  [+] Found interesting strings: flag, password, secret

🖼️ STEP 2: Image Steganography Analysis
  [+] Running zsteg...
  [+] LSB data found!

🚩 FLAGS FOUND:
  1. flag{h1dd3n_1n_pl41n_s1ght}
  ║  digitalcyberhunt{y0u_f0und_1t}
  ╚════════════════════════════════════════════════════════════╝
```

### Menu Mode
```
$ python ctf.py --menu

    ┌─────────────────────────────────────────┐
    │   [1]  🔍  Quick Scan                   │
    │   [2]  🎯  Full Analysis                │
    │   [3]  🔗  Decode Text/Encoding         │
    │   [4]  🔓  Crack Cipher                 │
    │   [5]  📦  Extract Files                │
    │   [6]  🔮  Check File Type              │
    │   [7]  ⚙️   Settings                     │
    │   [0]  🚪  Exit                         │
    └─────────────────────────────────────────┘
```

---

## 🔧 Supported Challenges

- 🖼️ Image Steganography (PNG, JPEG, GIF, BMP)
- 🎵 Audio Steganography (WAV, MP3, FLAC)
- 📄 PDF Forensics
- 📦 Archive Analysis (ZIP, TAR, 7Z, RAR)
- 🌐 Network/PCAP Analysis
- 🔐 Cryptography
- 💻 Binary/ELF Analysis
- 📷 QR Code Detection
- 🗺️ OSINT/Geolocation

---

## 📦 Installation

```bash
# Clone
git clone https://github.com/Prudhvisiva03/ctf-ai-ultimate.git
cd ctf-ai-ultimate

# Install Python dependencies
pip install -r requirements.txt

# Run
python ctf.py
```

---

## 🤝 Author

**Prudhvi** - [GitHub](https://github.com/Prudhvisiva03)

---

## 📜 License

MIT License - See [LICENSE](LICENSE)
