# CTF-AI Ultimate - Quick Start Guide

## 🚀 One-Command Setup (Linux/Kali)

```bash
# Clone the repository
git clone https://github.com/Prudhvisiva03/ctf-ai-ultimate
cd ctf-ai-ultimate

# Run automated setup
chmod +x setup.sh
./setup.sh

# Add your API key
nano config.json
# Replace YOUR_GROQ_API_KEY_HERE with your actual key

# Test it!
ctf-ai --solve challenge.dd.gz
```

---

## ✅ What the Setup Does

1. ✅ Installs all system dependencies (binwalk, foremost, etc.)
2. ✅ Installs Python packages (groq, python-magic, etc.)
3. ✅ Creates config.json from template
4. ✅ Sets up sudo access
5. ✅ Installs ctf-ai command globally

---

## 🎯 Usage

```bash
# Solve a challenge
ctf-ai --solve challenge.dd.gz

# With AI analysis
ctf-ai --ai=groq --solve challenge.png

# Manual mode (no AI)
ctf-ai --ai=none --solve challenge.pcap

# Interactive mode
ctf-ai
```

---

## 🔑 Get a Free Groq API Key

1. Go to: https://console.groq.com/
2. Sign up (free)
3. Go to API Keys
4. Create new key
5. Copy and paste into `config.json`

---

## 📊 Features

- ✅ **Fully Autonomous** - Finds flags automatically
- ✅ **AI-Powered** - Uses Groq/Ollama for intelligent analysis
- ✅ **Comprehensive** - Supports all CTF categories
- ✅ **Unique Output** - Each challenge gets its own directory
- ✅ **Auto-Scan** - Automatically scans extracted files

---

## 🎓 Example

```bash
$ ctf-ai --solve disko-1.dd.gz

[*] Auto-scanning extracted files for flags...
   ↳ Scanning directory: output/_extracted
   ✅ Found flag(s) in: disko-1.dd
🎉 FOUND 1 FLAG(S) IN EXTRACTED FILES!
   🚩 picoCTF{1t5_ju5t_4_5tr1n9_be6031da}

✅ Done! Check the 'output' directory.
```

---

## 📁 Output Structure

```
output/
└── disko-1_dd_2026-01-25_18-00-00/
    ├── report.txt          # Human-readable report
    ├── report.json         # Machine-readable data
    ├── results.txt         # FLAGS ONLY
    └── strings.txt         # All extracted strings
```

---

## 🛠️ Troubleshooting

### Config not found when using sudo
```bash
sudo cp config.json /root/
```

### Python package errors
```bash
pip install groq --break-system-packages
```

### Strings command not found
```bash
sudo apt install binutils
```

---

## 📚 Full Documentation

See [README.md](README.md) for complete documentation.

---

**Happy Hacking!** 🔥
