# Example Usage & Walkthroughs

This directory contains example CTF challenges and walkthroughs demonstrating how to use CTF-AI Ultimate.

## 📁 Structure

```
examples/
├── basic/          - Simple challenges for beginners
├── intermediate/   - Moderate difficulty challenges
├── advanced/       - Complex multi-stage challenges
└── walkthroughs/   - Detailed solution guides
```

## 🎯 Quick Examples

### Example 1: Basic PNG Steganography

**Challenge**: `basic/hidden_message.png`

```bash
ctf-ai --solve examples/basic/hidden_message.png

# Expected: Tool detects PNG, runs zsteg, finds hidden flag
```

### Example 2: Nested Archive

**Challenge**: `basic/nested.zip`

```bash
ctf-ai --solve examples/basic/nested.zip

# Expected: Recursively extracts archives, finds flag in deepest file
```

### Example 3: PCAP Analysis

**Challenge**: `intermediate/capture.pcap`

```bash
ctf-ai --solve examples/intermediate/capture.pcap

# Expected: Analyzes network traffic, extracts HTTP objects, finds flag
```

### Example 4: Binary Analysis

**Challenge**: `intermediate/crackme`

```bash
ctf-ai --solve examples/intermediate/crackme

# Expected: Runs checksec, strings analysis, suggests reverse engineering steps
```

## 📝 Walkthroughs

Each walkthrough includes:
- Challenge description
- Tools used by CTF-AI
- Step-by-step analysis
- Key learning points
- Alternative approaches

### Available Walkthroughs:

1. **PNG Steganography** - Using zsteg and LSB analysis
2. **ZIP Password Cracking** - Brute-forcing encrypted archives
3. **Network Forensics** - PCAP analysis and HTTP object extraction
4. **Binary Reverse Engineering** - Finding hardcoded flags
5. **PDF Metadata** - Extracting hidden information from PDFs
6. **Web Recon** - HTML comment and hidden path discovery

## 🚀 Running Examples

### Interactive Mode:
```bash
ctf-ai

> solve examples/basic/hidden_message.png
> solve examples/intermediate/capture.pcap
```

### Batch Mode:
```bash
for file in examples/basic/*; do
  ctf-ai --solve "$file"
done
```

## 🎓 Learning Path

1. Start with `basic/` challenges to understand tool capabilities
2. Move to `intermediate/` for complex scenarios
3. Try `advanced/` for multi-stage challenges
4. Read walkthroughs to learn CTF techniques

## ⚡ Pro Tips

- Use `--verbose` flag for detailed output
- Check `output/` directory for full reports
- Enable AI hints with `--ai-hint` for learning
- Compare different AI providers for analysis

## 📖 Creating Your Own Examples

Want to contribute examples? See `CONTRIBUTING.md` for guidelines on:
- Challenge format requirements
- Documentation standards
- Walkthrough templates

---

**Note**: Some examples require you to download actual CTF files from platforms like:
- [PicoCTF](https://picoctf.org/)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

Happy Learning! 🎯
