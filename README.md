# 🏴‍☠️ CTFHunter

**The World's First AI-Powered CTF Assistant**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/Prudhvisiva03/ctf-ai-ultimate)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

---

## 🚀 Quick Start

```bash
# Simple interactive mode (recommended)
python ctf.py

# Menu-based GUI
python ctf.py --menu

# Quick scan
python ctf.py challenge.png

# With custom flag format
python ctf.py image.png -f "digitalcyberhunt{}"
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔗 **Chain Decoder** | Auto-decode nested encodings (Base64→Base32→Hex→Flag) |
| 🔓 **Cipher Cracker** | Auto-crack Caesar, ROT13, Vigenere, XOR |
| 🔮 **Magic Checker** | Detect fake file extensions |
| 🔎 **Pattern Extractor** | Find flags, URLs, IPs, hashes |
| 📦 **Auto-Install** | Missing tools? Auto-install them! |
| 🎨 **Beautiful UI** | Clean prompts and menu system |

---

## 📁 Project Structure

```
ctfhunter/
├── ctf.py              # 🎯 Main entry point (USE THIS!)
├── modules/            # Analysis modules
│   ├── chain_decoder.py
│   ├── cipher_cracker.py
│   ├── encoding_detector.py
│   ├── magic_checker.py
│   ├── pattern_extractor.py
│   └── ...
├── playbooks/          # Auto-analysis playbooks
├── config/             # Configuration files
├── docs/               # Documentation
├── tools/              # Installation scripts
└── output/             # Analysis results
```

---

## 🎯 Usage Examples

### Interactive Mode
```
$ python ctf.py

  File path ➜  challenge.png
  ✓  File: challenge.png

  Flag format (e.g., flag{}, CTF{}) ➜  digitalcyberhunt{}
  ✓  Looking for: digitalcyberhunt{}

  Challenge description (optional) ➜  Find the hidden message

  Starting analysis...

  🚩 FLAG FOUND!
  ╔════════════════════════════════════════════════════════════╗
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
