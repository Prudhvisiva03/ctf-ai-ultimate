# 🏴‍☠️ CTFHunter

**Professional Kali Linux CTF Automation Tool**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Prudhvisiva03/ctfhunter)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Kali](https://img.shields.io/badge/Kali-Linux-557C94.svg)](https://kali.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

CTFHunter is a modular CLI tool that **automatically detects CTF challenge file types**, runs the correct tools in the best order, and **extracts possible flags** using regex patterns.

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Prudhvisiva03/ctfhunter.git
cd ctfhunter

# Install dependencies
pip3 install -r ctfhunter/requirements.txt

# Install the tool
pip3 install -e .

# Run CTFHunter
ctfhunter --target challenge.png --mode auto
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Auto Detection** | Automatically detects file types using magic bytes and extensions |
| 🖼️ **Steganography** | Analyzes images (PNG, JPG, GIF, BMP) and audio files for hidden data |
| 📦 **Forensics** | Extracts and analyzes archives (ZIP, TAR, GZ, 7Z, RAR), PDFs, and disk images |
| 📡 **Network** | Analyzes PCAP/PCAPNG files for credentials and hidden data |
| 💻 **Reverse Engineering** | Analyzes ELF, PE, APK, and Java binaries |
| 🔐 **Cryptography** | Detects and decodes Base64, Hex, Binary, ROT13, Caesar, Morse code |
| 🌐 **Web** | Reconnaissance, robots.txt, sitemap.xml, common file checks |
| 🚩 **Flag Finder** | Automatically searches for flag patterns: `flag{...}`, `HTB{...}`, `CTF{...}` |
| 📁 **Organized Output** | All results saved to timestamped directories |

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- **Kali Linux** (recommended) or any Debian-based Linux
- **pip3** package manager

### Step 1: Clone Repository

```bash
git clone https://github.com/Prudhvisiva03/ctfhunter.git
cd ctfhunter
```

### Step 2: Install Python Dependencies

```bash
pip3 install -r ctfhunter/requirements.txt
```

### Step 3: Install CTFHunter

```bash
# Install in development mode
pip3 install -e .

# Or install directly
pip3 install .
```

### Step 4: Install Required Tools (Recommended)

```bash
# Essential tools
sudo apt install file binutils exiftool binwalk foremost steghide tshark

# Steganography tools
sudo apt install stegseek pngcheck
sudo gem install zsteg

# Forensics tools
sudo apt install p7zip-full unrar sleuthkit

# Reverse engineering tools
sudo apt install checksec gdb radare2

# Web tools
sudo apt install whatweb gobuster dirb
```

---

## 🎯 Usage

### Basic Usage

```bash
# Analyze a file (auto mode)
ctfhunter --target challenge.png --mode auto

# Quick scan
ctfhunter --target challenge.png --mode quick

# Deep analysis
ctfhunter --target binary.elf --mode deep

# Specify output directory
ctfhunter --target capture.pcap --output ./results

# Analyze a URL
ctfhunter --target https://target.com --mode auto
```

### Command Options

```
Usage: ctfhunter [OPTIONS]

Options:
  --target, -t FILE/URL    Target file or URL to analyze
  --mode, -m MODE          Analysis mode: auto, quick, deep (default: auto)
  --output, -o DIR         Output directory (default: ./output)
  --detect, -d FILE        Quick file type detection only
  --list-tools, -l         List available tools and their status
  --quiet, -q              Minimal output (only show flags)
  --verbose                Verbose output (show all tool outputs)
  --version, -v            Show version
  --help, -h               Show help message
```

### Examples

#### Analyze an Image
```bash
$ ctfhunter --target challenge.png --mode auto

   ██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ...

🎯 Target: challenge.png
📁 Output: output/challenge_20260130_123456
⚙️  Mode: auto

╭──────────────────── STEP 1: File Detection ────────────────────╮
│ Name: challenge.png                                             │
│ Type: PNG image                                                 │
│ Category: Image                                                 │
╰─────────────────────────────────────────────────────────────────╯

╭──────────────────── STEP 2: Running Tools ─────────────────────╮
│ ✓ file                                                          │
│ ✓ exiftool                                                      │
│ ✓ strings                                                       │
│ ✓ zsteg                                                         │
│ ✓ binwalk                                                       │
╰─────────────────────────────────────────────────────────────────╯

╭──────────────────── STEP 3: Flag Search ───────────────────────╮
│ Searching original file...                                      │
│ Searching tool outputs...                                       │
│ Searching extracted files...                                    │
╰─────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────────────────────────────╮
│                    🚩 FOUND 1 FLAG(S)!                          │
╰─────────────────────────────────────────────────────────────────╯

┏━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ # ┃ Flag                    ┃ Source          ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ 1 │ flag{h1dd3n_1n_png}     │ zsteg           │
└───┴─────────────────────────┴─────────────────┘
```

#### Analyze a Network Capture
```bash
$ ctfhunter --target traffic.pcap --mode deep
```

#### Quick File Detection
```bash
$ ctfhunter --detect mystery_file

┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property           ┃ Value                                      ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Name               │ mystery_file                               │
│ Extension          │ (none)                                     │
│ Size               │ 1,234,567 bytes                            │
│ MIME Type          │ application/zip                            │
│ Description        │ ZIP archive                                │
│ Category           │ Archive                                    │
└────────────────────┴────────────────────────────────────────────┘

Suggested tools:
  • file
  • strings
  • binwalk
  • unzip
  • foremost
```

#### List Available Tools
```bash
$ ctfhunter --list-tools

┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool               ┃ Status        ┃ Install Command                   ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ file               │ ✓ Installed   │                                   │
│ strings            │ ✓ Installed   │                                   │
│ exiftool           │ ✓ Installed   │                                   │
│ binwalk            │ ✓ Installed   │                                   │
│ zsteg              │ ✗ Missing     │ gem install zsteg                 │
│ steghide           │ ✓ Installed   │                                   │
│ tshark             │ ✓ Installed   │                                   │
│ checksec           │ ✗ Missing     │ apt install checksec              │
└────────────────────┴───────────────┴───────────────────────────────────┘

Tools installed: 15/21
```

---

## 📁 Project Structure

```
ctfhunter/
├── ctfhunter/
│   ├── __init__.py         # Package initialization
│   ├── cli.py              # Command-line interface
│   ├── core.py             # Main orchestration engine
│   ├── detector.py         # File type detection
│   ├── flag_finder.py      # Flag pattern matching
│   ├── modules/
│   │   ├── __init__.py     # Module initialization
│   │   ├── steg.py         # Steganography analysis
│   │   ├── crypto.py       # Cryptography analysis
│   │   ├── forensics.py    # Forensic analysis
│   │   ├── web.py          # Web security analysis
│   │   ├── reverse.py      # Reverse engineering
│   │   └── network.py      # Network analysis
│   ├── requirements.txt    # Python dependencies
│   └── setup.py            # Installation script
├── output/                  # Analysis results
├── examples/               # Example files
├── README.md               # This file
└── LICENSE                 # MIT License
```

---

## 🔧 Supported File Types

### Images
- PNG (zsteg, binwalk, exiftool, pngcheck)
- JPEG (steghide, stegseek, exiftool, binwalk)
- GIF (frame extraction, exiftool)
- BMP (zsteg, binwalk)

### Audio
- WAV (steghide, spectrogram analysis)
- MP3 (exiftool, strings)
- FLAC, OGG (metadata analysis)

### Archives
- ZIP (unzip, password cracking)
- TAR, TAR.GZ, TGZ (tar)
- GZIP (gunzip)
- 7Z (7z)
- RAR (unrar)

### Documents
- PDF (pdftotext, pdfimages, binwalk)

### Network
- PCAP/PCAPNG (tshark, protocol analysis, credential extraction)

### Binaries
- ELF (checksec, readelf, objdump, strings)
- PE/EXE (strings, analysis tips)
- APK (apktool, jadx)
- JAR (extraction, analysis)

### Text/Encoded
- Base64, Base32, Base85
- Hexadecimal
- Binary
- ROT13, Caesar cipher
- Morse code

---

## 🚩 Supported Flag Formats

CTFHunter automatically searches for these flag patterns:

- `flag{...}`
- `FLAG{...}`
- `ctf{...}`
- `CTF{...}`
- `htb{...}`
- `HTB{...}`
- `picoCTF{...}`
- `THM{...}`
- `HACK{...}`
- Custom patterns (configurable)

---

## 📊 Output

All analysis results are saved to the output directory:

```
output/
└── challenge_20260130_123456/
    ├── report.json          # Full JSON report
    ├── report.txt           # Human-readable summary
    ├── file_output.txt      # file command output
    ├── strings_output.txt   # strings output
    ├── exiftool_output.txt  # exiftool output
    ├── zsteg_output.txt     # zsteg output
    ├── binwalk_output.txt   # binwalk output
    └── extracted/           # Extracted files
        ├── binwalk/
        ├── foremost/
        └── ...
```

---

## 🛠️ Development

### Running from Source

```bash
# Clone the repository
git clone https://github.com/Prudhvisiva03/ctfhunter.git
cd ctfhunter

# Install in development mode
pip3 install -e .

# Run
python3 -m ctfhunter.cli --help
```

### Adding Custom Modules

1. Create a new module in `ctfhunter/modules/`
2. Implement the `analyze()` method
3. Register in `ctfhunter/core.py`

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and CTF competitions only**. 

**Do NOT use this tool for:**
- Unauthorized system access
- Illegal activities
- Attacking systems without permission

Always obtain proper authorization before testing.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Prudhvisiva03/ctfhunter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Prudhvisiva03/ctfhunter/discussions)

---

**Made with ❤️ for the CTF Community**
