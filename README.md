# 🏴‍☠️ CTFHunter - AI-Powered CTF Solver

<div align="center">

```
   ██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██║        ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██║        ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                    🤖 World's First AI-Powered CTF Assistant 🤖
```

**🌟 The Ultimate Open-Source CTF Automation Tool with AI Intelligence 🌟**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-blue)](https://www.kali.org/)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-green)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-2.1.0-orange)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-purple)]()
[![Competition Ready](https://img.shields.io/badge/Status-Competition%20Ready-brightgreen)]()

<img src="https://img.shields.io/badge/Digital%20Cyberhunt-Ready-red?style=for-the-badge" alt="Digital Cyberhunt Ready">

</div>

---

> 🎯 **Just say:** *"solve challenge.png"* — Watch AI + 25+ tools find the flag automatically!

---

## 🚀 Why CTFHunter is UNIQUE

**🌍 World's First** open-source tool that combines:

| Feature | CTFHunter | Others |
|---------|-----------|--------|
| 🤖 Multi-AI Support | ✅ 4 providers (OpenAI, Ollama, Claude, Groq) | ❌ Single or none |
| 🆓 Free Local AI | ✅ Ollama (100% offline) | ❌ Cloud only |
| 🔧 Tool Integration | ✅ 25+ Kali tools | ❌ Limited |
| 🗺️ OSINT & Geolocation | ✅ GPS, metadata, coordinates | ❌ Not available |
| 🔐 Crypto Analysis | ✅ Auto-decode 15+ encodings | ❌ Manual |
| 📚 Educational Mode | ✅ Shows reasoning | ❌ Black box |
| 💬 Natural Language | ✅ "solve challenge.png" | ❌ Complex CLI |

---

## 🎯 Built for Digital Cyberhunt CTF

<div align="center">

| Category | CTFHunter Support | Tools Used |
|----------|------------------|------------|
| 🗺️ **Geolocation & OSINT** | ✅ Full Support | exiftool, GPS extraction, metadata analysis |
| 🌐 **Web & AI Security** | ✅ Full Support | curl, requests, web scanning |
| 🔐 **Cyber & Cryptography** | ✅ Full Support | 15+ encoding decoders, cipher crackers |
| 📸 **Metadata Forensics** | ✅ Full Support | exiftool, strings, binwalk, steghide |

</div>

---

## ✨ Key Features

### 🧠 **AI-Powered Intelligence**
- **Multi-AI Support**: OpenAI (GPT-4), Ollama (FREE), Claude, Groq
- **Deep Scan Mode**: Exhaustive analysis with recursive extraction
- **Smart Challenge Analysis**: AI determines the best approach
- **Adaptive Execution**: Tries different methods if first approach fails
- **Learning Mode**: Shows reasoning so you understand what's happening

### 🎯 **Challenge-Specific Deep Scans**
Every CTF type has its own battle-tested workflow:
- **PNG Steganography** → zsteg + chunks check + metadata + strings + binwalk + foremost + steghide
- **JPEG Stego** → steghide + stegseek + EXIF + brute-force
- **📱 QR Codes** → zbarimg + zxing + image enhancement + multiple decode attempts
- **🎵 Audio Stego** → spectrogram analysis + Morse detection + LSB + metadata
- **🔢 Hash Cracking** → Auto-identify + common password crack + hashcat integration
- **PCAP Analysis** → tshark + HTTP objects + TCP streams
- **Binary Analysis** → checksec + strings + dangerous functions
- **Archive Analysis** → recursive extraction + nested archives
- **PDF Forensics** → metadata + hidden text + embedded files
- **OSINT/Geolocation** → GPS extraction + coordinate decoding + metadata
- **Cryptography** → Auto-decode Base64, Hex, Caesar, Morse, XOR + more

### 💬 **Natural Language Interface**
```bash
🤖 You: solve mystery.png
🤖 AI: Analyzing PNG image... Running zsteg... Found flag!
✅ FLAG FOUND: digitalcyberhunt{st3g4n0gr4phy_m4st3r}

🤖 You: decode qr from image.png
🤖 AI: QR Code detected! Content: flag{qr_c0d3_m4st3r}

🤖 You: crack hash 5d41402abc4b2a76b9719d911017c592
🤖 AI: Hash type: MD5 | Cracked: hello

🤖 You: extract gps from photo.jpg
🤖 AI: Extracting EXIF... GPS found!
📍 Location: 17.3850, 78.4867 (Hyderabad, India)
```

### 🔧 **25+ Integrated Tools**
- **Steganography**: zsteg, steghide, stegseek, stegoveritas
- **Forensics**: binwalk, exiftool, strings, foremost
- **Network**: tshark, wireshark
- **Binary**: checksec, gdb, radare2, ltrace, strace
- **PDF**: pdfinfo, pdftotext
- **Web**: curl, dirsearch, nikto
- **QR**: zbarimg, zxing, pyzbar
- **Audio**: sox, ffmpeg, ffprobe
- **Hash**: hashcat, john

### 📊 **Beautiful HTML Reports**
Generate professional HTML reports for your CTF analysis - perfect for presentations and documentation!

---

## 📦 Quick Start

### **Installation (One Command!)**

```bash
# Clone the repository
git clone https://github.com/Prudhvisiva03/ctfhunter
cd ctfhunter

# Install everything (Kali Linux)
sudo ./install.sh

# Done! Start using it
ctf-ai
```

### **Documentation & Guides**
- 🐳 **[Docker Guide](DOCKER.md)** - Run in a container
- ❓ **[FAQ](FAQ.md)** - Frequently Asked Questions
- 🛡️ **[Security Policy](SECURITY.md)** - Responsible use
- 🏫 **[Examples](examples/README.md)** - Learn with walkthroughs

### **First Run**

```bash
# Interactive mode (recommended)
ctf-ai

🤖 You: solve challenge.png
```

```bash
# Direct solve
ctf-ai --solve challenge.png
```

```bash
# Legacy mode (no AI)
ctfhunter challenge.png
```

---

## 🤖 AI Setup (Choose Your Provider)

Edit `config.json`:

### **Option 1: OpenAI (Best Quality, Costs Money)**
```json
{
    "ai_provider": "openai",
    "ai_model": "gpt-4",
    "openai_api_key": "sk-your-key-here"
}
```
Get API key: https://platform.openai.com/api-keys

### **Option 2: Ollama (100% FREE, Local)**
```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3

# Start Ollama
ollama serve
```
```json
{
    "ai_provider": "ollama",
    "ai_model": "llama3"
}
```

### **Option 3: Claude (Anthropic)**
```json
{
    "ai_provider": "claude",
    "ai_model": "claude-3-sonnet-20240229",
    "claude_api_key": "sk-ant-your-key"
}
```

### **Option 4: Groq (Fast & Free Tier)**
```json
{
    "ai_provider": "groq",
    "ai_model": "mixtral-8x7b-32768",
    "groq_api_key": "gsk-your-key"
}
```

### **Option 5: No AI (Manual Mode)**
```json
{
    "ai_provider": "none"
}
```

---

## 📚 Usage Examples

### **Interactive Mode** (Best Experience)
```bash
$ ctf-ai

🤖 CTF-AI Ultimate v1.0
✅ AI Engine: openai (gpt-4)
✅ Playbooks loaded: 8

🤖 You: solve stego.png
🎯 Target: stego.png

🔍 Step 1: Analyzing target...
🤖 Step 2: AI analyzing challenge type...
   Challenge Type: png_stego
   Confidence: 95%
   Reasoning: PNG image with suspicious file size
   Recommended Playbook: png_stego

🚀 Step 3: Executing playbook 'png_stego'...
[1/7] Executing: File Type Verification
[2/7] Executing: Zsteg Analysis
    🔥 Found flag(s): ['flag{z5t3g_p0w3r}']
[3/7] Executing: EXIF Metadata Extraction

🎉 SUCCESS! Found 1 flag(s):
   1. flag{z5t3g_p0w3r}

📄 Methods executed: 3
✅ Done! Check the 'output' directory for detailed reports.
```

### **Direct Solve Mode**
```bash
# Solve with AI
ctf-ai --solve challenge.zip

# Use specific AI provider
ctf-ai --ai=ollama --solve file.pcap

# Manual mode (no AI)
ctf-ai --ai=none --solve binary.elf
```

### **Legacy CTFHunter Mode**
```bash
# Original CTFHunter (still works!)
ctfhunter challenge.png
ctfhunter capture.pcap
ctfhunter https://target.com
```

---

## 🎯 Supported Challenge Types

| Type | File Extensions | Playbook | Tools Used |
|------|----------------|----------|------------|
| **PNG Steganography** | `.png`, `.bmp` | `png_stego` | zsteg, exiftool, binwalk, steghide |
| **JPEG Steganography** | `.jpg`, `.jpeg` | `jpg_stego` | steghide, stegseek, exiftool |
| **� QR Codes** | `.png`, `.jpg`, images | `qr_analysis` | zbarimg, zxing, pyzbar |
| **🎵 Audio Stego** | `.wav`, `.mp3`, `.flac` | `audio_stego` | sox, ffmpeg, spectrogram |
| **🔢 Hash Cracking** | hashes | `hash_crack` | hashcat, john, rainbow tables |
| **🗺️ OSINT/Geolocation** | `.jpg`, `.png`, images | `osint_geolocation` | exiftool, GPS extraction, metadata |
| **🔐 Cryptography** | `.txt`, `.enc`, `.cipher` | `crypto_analysis` | Base64, Hex, Caesar, Morse, XOR |
| **Archives** | `.zip`, `.tar`, `.gz`, `.rar`, `.7z` | `archive_analysis` | unzip, tar, 7z, binwalk |
| **Network Captures** | `.pcap`, `.pcapng` | `pcap_analysis` | tshark, wireshark |
| **Binaries** | `.elf`, `.bin` | `binary_analysis` | checksec, strings, gdb |
| **PDF Files** | `.pdf` | `pdf_forensics` | pdfinfo, pdftotext, exiftool |
| **Web Challenges** | URLs | `web_recon` | curl, requests, beautifulsoup |
| **Generic** | Any file | `generic` | file, strings, binwalk, exiftool |

### 🔐 Supported Encodings & Ciphers
- Base64, Base32, Base16 (Hex)
- ROT13, Caesar Cipher (all shifts)
- Morse Code, Binary
- URL Encoding
- XOR (common keys)
- Vigenère Cipher
- Atbash Cipher

### 🚩 Supported Flag Formats
```
digitalcyberhunt{...}  DCH{...}
flag{...}              FLAG{...}
CTF{...}               ctf{...}
picoCTF{...}           HTB{...}
THM{...}               OSCTF{...}
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│         Natural Language Interface          │
│  "solve challenge.png" "find flag in X"    │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│            AI Engine (Multi-Provider)        │
│  OpenAI│Ollama│Claude│Groq│None            │
│  • Analyzes Challenge                       │
│  • Selects Playbook                         │
│  • Interprets Results                       │
│  • Suggests Next Steps                      │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│           Playbook Executor                 │
│  • Loads challenge-specific playbook        │
│  • Executes method sequence                 │
│  • Sequential/Parallel/Adaptive modes       │
└────────────────┬────────────────────────────┘
                 │
         ┌───────┼───────┐
         ▼       ▼       ▼
    ┌─────┐  ┌─────┐  ┌─────┐
    │Tools│  │Modules│ │Scripts│
    │zsteg│  │stego  │ │custom │
    │tshark  │pcap   │ │      │
    │checksec│binary │ │      │
    └──────┘ └──────┘ └──────┘
         │       │       │
         └───────┼───────┘
                 ▼
┌─────────────────────────────────────────────┐
│        Flag Discovery & Reporting           │
│  • Regex pattern matching                   │
│  • Results saved to output/                 │
│  • TXT + JSON reports                       │
└─────────────────────────────────────────────┘
```

---

## 🎓 Learning Mode

CTF-AI is designed for **learning**, not just solving:

```bash
🤖 You: solve mystery.elf

🔍 Step 1: Analyzing target...
   File Type: ELF 64-bit executable

🤖 Step 2: AI analyzing challenge type...
   Challenge Type: binary
   Confidence: 85%
   Reasoning: ELF binary detected with standard security features.
              Likely contains hardcoded flag or requires reverse engineering.
   
🚀 Step 3: Executing playbook 'binary_analysis'...

[1/7] Executing: Security Checks
    Running: checksec --file=mystery.elf
    ✅ Output shows: NX enabled, PIE disabled, No canary
    💡 This means: Stack is not executable, binary is not position-independent

[2/7] Executing: Strings Analysis
    Running: strings mystery.elf
    ✅ Found interesting strings: "Enter password:", "Correct!", "flag{"
    
[3/7] Executing: Symbols Check
    Running: nm -D mystery.elf
    ⚠️  Dangerous functions detected: strcpy, system
    💡 Potential vulnerability: Buffer overflow via strcpy

🤖 AI Interpretation:
   "The binary likely has a hardcoded flag. The presence of 'flag{' 
    in strings suggests checking for the complete flag pattern.
    Alternative: Dynamic analysis with ltrace to see function calls."

🎉 Found 1 flag(s): flag{b1n4ry_str1ngs}

📚 Recommended next steps:
   1. Use 'ltrace ./mystery.elf' to trace library calls
   2. Use 'gdb ./mystery.elf' for dynamic analysis
   3. Try 'radare2 mystery.elf' for deeper reverse engineering
```

---

## 📊 Comparison with Other Tools

| Feature | CTF-AI Ultimate | CAI | SWE-Agent | Manual Tools |
|---------|----------------|-----|-----------|--------------|
| **Open Source** | ✅ | ❌ | ❌ | ✅ |
| **Natural Language** | ✅ | ✅ | ✅ | ❌ |
| **Multi-AI Support** | ✅ (4 providers) | ❌ | ❌ | N/A |
| **Local AI Option** | ✅ (Ollama) | ❌ | ❌ | N/A |
| **Kali Tools Integration** | ✅ | ❌ | ❌ | ✅ |
| **Smart Playbooks** | ✅ | Partial | Partial | ❌ |
| **Educational Mode** | ✅ | ❌ | ❌ | ✅ |
| **Free to Use** | ✅ | ❌ | ❌ | ✅ |
| **CLI Interface** | ✅ | ❌ | ❌ | ✅ |
| **Adaptive Execution** | ✅ | ✅ | Partial | ❌ |

**Result:** CTF-AI Ultimate is the **only** tool with all these features! 🏆

---

## 🛠️ Development

### **Project Structure**
```
ctfhunter/
├── ctf-ai.py                 # Main AI assistant
├── ctfhunter.py              # Legacy direct scanner
├── config.json               # Configuration
├── playbooks/                # Challenge-specific playbooks
│   ├── png_stego.json
│   ├── jpg_stego.json
│   ├── pcap_analysis.json
│   ├── binary_analysis.json
│   ├── archive_analysis.json
│   ├── pdf_forensics.json
│   ├── web_recon.json
│   └── generic.json
├── modules/
│   ├── ai_engine.py          # Multi-provider AI engine
│   ├── playbook_executor.py  # Playbook execution
│   ├── file_scan.py          # File analysis
│   ├── stego_scan.py         # Steganography
│   ├── pcap_scan.py          # Network analysis
│   ├── elf_scan.py           # Binary analysis
│   ├── pdf_scan.py           # PDF forensics
│   ├── zip_scan.py           # Archive extraction
│   ├── web_scan.py           # Web reconnaissance
│   └── reporter.py           # Report generation
├── requirements.txt          # Python dependencies
├── install.sh                # One-click installer
└── README.md                 # This file
```

### **Adding Custom Playbooks**

Create `playbooks/custom.json`:
```json
{
    "name": "My Custom Analysis",
    "description": "Custom workflow for specific challenges",
    "category": "custom",
    "file_types": [".custom"],
    "execution_strategy": "sequential",
    "methods": [
        {
            "name": "Custom Tool",
            "description": "Run my custom tool",
            "type": "tool",
            "tool": "my-tool",
            "args": ["{target}"],
            "timeout": 60
        }
    ]
}
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add New Playbooks** - Create workflows for specific CTF types
2. **Improve AI Prompts** - Better prompts = smarter analysis
3. **Add Tool Integrations** - More tools = more capability
4. **Bug Fixes** - Report or fix issues
5. **Documentation** - Improve guides and examples

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

## ⚠️ Disclaimer

This tool is designed for:
- ✅ Authorized CTF competitions
- ✅ Educational purposes
- ✅ Cybersecurity learning
- ✅ Authorized penetration testing

**Do NOT use for:**
- ❌ Unauthorized access to systems
- ❌ Illegal activities
- ❌ Attacking systems without permission

**Always obtain proper authorization before testing any system.**

---

## 🎯 Roadmap

- [ ] GUI Dashboard (Web interface)
- [ ] Docker support
- [ ] Cloud deployment options
- [ ] More playbooks (crypto, forensics, OSINT)
- [ ] Integration with CTF platforms (HTB, TryHackMe)
- [ ] Team collaboration features
- [ ] Multi-file batch analysis
- [ ] Custom plugin system
- [ ] Mobile app support

---

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/Prudhvisiva03/ctfhunter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Prudhvisiva03/ctfhunter/discussions)
- **Documentation**: Check `docs/` folder

---

## 🌟 Star History

If this tool helped you solve CTF challenges, please ⭐ star the repository!

---

## 🙏 Acknowledgments

- All the amazing open-source CTF tools we integrate
- The CTF community for inspiration
- OpenAI, Anthropic, Groq, and Ollama for AI capabilities

---

## 📧 Contact

Created by cybersecurity enthusiasts, for cybersecurity enthusiasts.

**Happy Hacking! 🔥🎯**

---

<div align="center">

Made with ❤️ for the CTF Community

**[⬆ Back to Top](#ctf-ai-ultimate-)**

</div>
