# Frequently Asked Questions

## Installation

### Q: Does this work on systems other than Kali Linux?

**A:** Yes, but Kali is recommended. The tool works on any Debian-based system (Ubuntu, Debian, etc.). For other distributions, you'll need to manually install the required tools.

For macOS: Install tools via Homebrew  
For Windows: Use WSL2 with Kali/Ubuntu or Docker

### Q: Can I use this without any AI provider?

**A:** Absolutely! Set `"ai_provider": "none"` in `config.json`. The tool will still run all the analysis tools, you just won't get AI-powered insights and playbook selection.

### Q: Which AI provider is recommended?

**A:** 
- **Best Quality**: OpenAI GPT-4 (costs money, ~$0.03 per challenge)
- **Best Free Option**: Ollama with llama3 (100% free, runs locally)
- **Best Speed**: Groq (fast inference, free tier available)
- **Best Privacy**: Ollama (all processing stays on your machine)

## Usage

### Q: How do I analyze multiple files at once?

**A:** Currently, analyze files one at a time. Batch processing is planned for v3.0. For now, use a shell loop:
```bash
for file in challenges/*; do
  ctf-ai --solve "$file"
done
```

### Q: Where are the results saved?

**A:** All results go to the `output/` directory:
- `report.txt` - Full human-readable report
- `report.json` - Machine-readable JSON data
- `results.txt` - Just the discovered flags
- `_extracted/` - Extracted files
- `_http_objects/` - HTTP objects from PCAPs

### Q: Can I customize the flag patterns?

**A:** Yes! Edit `config.json` and modify the `flag_patterns` array. Use regex patterns:
```json
"flag_patterns": [
  "flag\\{[^}]+\\}",
  "YOUR_CTF\\{[^}]+\\}",
  "custom_pattern_here"
]
```

## Troubleshooting

### Q: I get "command not found" errors for tools

**A:** Run the dependency checker:
```bash
python3 check_dependencies.py
```

Install missing tools:
```bash
sudo apt-get install zsteg steghide binwalk exiftool tshark
```

### Q: Python import errors?

**A:** Reinstall Python dependencies:
```bash
pip3 install -r requirements.txt --force-reinstall
```

### Q: AI provider not working?

**A:** Check:
1. API key is correct in `config.json`
2. You have internet connection (except for Ollama)
3. For Ollama: Is the server running? (`ollama serve`)
4. Check API quotas and billing

### Q: Tool finds nothing in my challenge?

**A:** This can happen because:
- Some CTF methods aren't implemented yet (crypto, OSINT, etc.)
- The challenge requires manual dynamic analysis
- The flag is obfuscated beyond regex detection
- Use `--verbose` to see what was tried

## Features

### Q: Does this solve all CTF challenges automatically?

**A:** No. CTF-AI Ultimate automates the initial reconnaissance and common analysis techniques, but:
- Complex crypto challenges require manual work
- Binary exploitation needs manual reverse engineering
- Web exploitation requires manual testing
- It's a powerful assistant, not a silver bullet

### Q: What challenge types are supported?

**A:** ✅ Supported:
- Steganography (PNG, JPG, BMP)
- Archives (ZIP, TAR, GZ, 7Z, RAR)
- Network forensics (PCAP)
- Basic binary analysis (strings, checksec)
- PDF forensics
- Web reconnaissance
- File forensics

❌ Not yet supported:
- Advanced cryptography
- Binary exploitation (ROP, shellcode)
- OSINT challenges
- Memory forensics
- Blockchain/smart contracts

### Q: Can I add custom tools or playbooks?

**A:** Yes! Create custom playbooks in `playbooks/` directory. See `playbooks/generic.json` as a template. Custom tool integration requires modifying the modules.

## AI & Privacy

### Q: Is my data sent to AI providers?

**A:** Only if you use cloud AI (OpenAI, Claude, Groq):
- File metadata and analysis results are sent
- The actual binary file content is NOT sent
- Only text outputs from tools are sent for interpretation

For complete privacy, use Ollama (local AI).

### Q: How much does OpenAI cost?

**A:** Approximately:
- Simple challenge: $0.01 - $0.03
- Complex challenge: $0.05 - $0.10
- Most users spend less than $5/month

Use Ollama for free unlimited usage!

### Q: Can the AI "guess" flags?

**A:** No. The AI only interprets actual tool outputs. It never generates random flags. All discovered flags come from actual analysis.

## Advanced

### Q: Can I run this in a CI/CD pipeline?

**A:** Yes! Use Docker or direct CLI:
```bash
ctf-ai --ai=none --solve challenge.png --output-json results.json
```

### Q: Does it support headless mode?

**A:** Yes. All commands work in headless environments. For AI providers, ensure API keys are in config.

### Q: Can I integrate this with CTF platforms?

**A:** Not directly yet, but you can:
1. Download challenges locally
2. Run CTF-AI on them
3. Submit discovered flags manually

API integration with HTB/THM is planned for future versions.

## Contributing

### Q: How can I contribute?

**A:** See `CONTRIBUTING.md`! We welcome:
- New playbooks for challenge types
- Tool integrations
- Bug fixes
- Documentation improvements
- Example challenges

### Q: I found a bug. What should I do?

**A:** Report it via GitHub Issues using the bug report template. Include:
- Your environment (OS, Python version)
- Steps to reproduce
- Error output
- Sample file (if possible)

---

**Can't find your answer?**  
💬 Open a [GitHub Discussion](https://github.com/Prudhvisiva03/ctf-ai-ultimate/discussions)  
🐛 Report a bug via [Issues](https://github.com/Prudhvisiva03/ctf-ai-ultimate/issues)
