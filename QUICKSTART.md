# CTFHunter Ultimate - Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Installation
```bash
cd ctfhunter
chmod +x install.sh
sudo ./install.sh
```

### Step 2: Verify Installation
```bash
ctfhunter --version
```

### Step 3: Run Your First Scan

#### Example 1: Scan an Image
```bash
# Download a sample CTF image
wget https://example.com/challenge.png

# Analyze it
ctfhunter challenge.png
```

#### Example 2: Scan a Web Challenge
```bash
ctfhunter https://ctf-challenge.example.com
```

#### Example 3: Scan a PCAP File
```bash
ctfhunter network_capture.pcap
```

### Step 4: Review Results
```bash
# Check the output directory
ls -la output/

# View the report
cat output/report.txt

# Check if flags were found
cat output/results.txt
```

---

## 🎯 Common Workflows

### Workflow 1: Image Steganography
```bash
ctfhunter suspicious_image.png
# CTFHunter will:
# ✓ Run zsteg (PNG)
# ✓ Try steghide extraction
# ✓ Check for embedded files
# ✓ Extract metadata
```

### Workflow 2: Archive Analysis
```bash
ctfhunter challenge.zip
# CTFHunter will:
# ✓ Extract contents
# ✓ Scan each file recursively
# ✓ Find nested archives
# ✓ Look for flag.txt, secret.txt
```

### Workflow 3: Network Forensics
```bash
ctfhunter capture.pcap
# CTFHunter will:
# ✓ Analyze protocols
# ✓ Extract HTTP objects
# ✓ Follow TCP streams
# ✓ Search for credentials
# ✓ Scan for flags in packets
```

### Workflow 4: Binary Analysis
```bash
ctfhunter binary.elf
# CTFHunter will:
# ✓ Run checksec
# ✓ Extract strings
# ✓ Find dangerous functions
# ✓ Provide reversing hints
```

### Workflow 5: Web Recon
```bash
ctfhunter https://target.com
# CTFHunter will:
# ✓ Download & analyze HTML
# ✓ Check JavaScript
# ✓ Find hidden comments
# ✓ Test common paths
# ✓ Check robots.txt
```

---

## 🔧 Configuration Tips

### Enable AI Hints
1. Get API key from: https://platform.openai.com/api-keys
2. Edit config.json:
   ```json
   {
       "openai_api_key": "sk-your-key-here"
   }
   ```
3. Run with AI:
   ```bash
   ctfhunter --ai-hint mystery.zip
   ```

### Customize Flag Patterns
Edit `config.json`:
```json
{
    "flag_patterns": [
        "flag\\{[^}]+\\}",
        "FLAG\\{[^}]+\\}",
        "CUSTOM\\{[^}]+\\}"
    ]
}
```

### Add Custom Web Paths
```json
{
    "web_paths": [
        "/admin",
        "/secret",
        "/custom-endpoint",
        "/api/flag"
    ]
}
```

---

## 🐛 Troubleshooting

### Issue: "Command not found: ctfhunter"
**Solution:**
```bash
# Add to PATH manually
export PATH=$PATH:/usr/local/bin

# Or run directly
python3 ctfhunter.py <target>
```

### Issue: "Module not found"
**Solution:**
```bash
pip3 install -r requirements.txt --force-reinstall
```

### Issue: "Permission denied"
**Solution:**
```bash
chmod +x ctfhunter.py
# Or run as:
python3 ctfhunter.py <target>
```

### Issue: Tool warnings (zsteg, stegseek, etc.)
**Solution:**
```bash
# Install missing tools
sudo apt-get update
sudo apt-get install -y zsteg stegseek steghide binwalk exiftool
```

---

## 📊 Understanding Output

### Terminal Output Symbols
- ✅ Success / Found something important
- ⚠️  Warning / Potential finding
- ❌ Error / Not found
- 🔥 Major success (extraction, etc.)
- 🤖 AI hint
- [*] Information
- [+] Positive result

### Output Files
- `output/report.txt` - Human-readable report
- `output/report.json` - Machine-readable data
- `output/results.txt` - All discovered flags
- `output/_extracted/` - Extracted files from archives
- `output/_http_objects/` - HTTP objects from PCAP
- `output/page_source.html` - Downloaded web pages

---

## 🎓 Learning Tips

1. **Read the reports** - Don't just look for flags, understand what was found
2. **Check all extracted files** - Flags might be in nested locations
3. **Learn the tools** - Try running the underlying tools manually
4. **Use AI hints wisely** - Use them to learn, not just get answers
5. **Experiment** - Try different challenge types

---

## 🏆 Pro Tips

- Always check `output/` directory for extracted files
- Use `--ai-hint` when stuck for learning guidance
- Combine with manual analysis for best results
- Read the full report, not just the summary
- Keep your tools updated: `sudo apt-get update && sudo apt-get upgrade`

---

## 📚 Next Steps

1. Try CTFHunter on real CTF challenges
2. Learn the underlying tools (binwalk, steghide, etc.)
3. Contribute new modules or improvements
4. Share your experience with the community

---

**Happy Hunting! 🔥**
