# CTF-AI Ultimate - Test Examples

## Quick Test Commands

Once installed, test the tool with these commands:

### 1. Test Interactive Mode
```bash
ctf-ai

# Then try:
> help
> playbooks
> settings
> quit
```

### 2. Test with Real Files

#### Create a test PNG with embedded text:
```bash
# Simple test - create a file with flag in strings
echo "flag{test_flag_12345}" > /tmp/test.txt
zip /tmp/test.zip /tmp/test.txt
```

#### Test the tool:
```bash
# Test with AI
ctf-ai --solve /tmp/test.zip

# Test without AI
ctf-ai --ai=none --solve /tmp/test.zip
```

### 3. Test Different AI Providers

#### Test OpenAI (if you have API key):
```bash
# Edit config.json first to add your key
ctf-ai --ai=openai --solve /tmp/test.zip
```

#### Test Ollama (FREE - if installed):
```bash
# Install Ollama first:
curl https://ollama.ai/install.sh | sh
ollama pull llama3
ollama serve

# Then test:
ctf-ai --ai=ollama --solve /tmp/test.zip
```

#### Test without AI:
```bash
ctf-ai --ai=none --solve /tmp/test.zip
```

### 4. Test Legacy CTFHunter
```bash
ctfhunter /tmp/test.zip
```

### 5. Check Generated Reports
```bash
ls -la output/
cat output/report.txt
cat output/results.txt
```

## Expected Results

✅ Tool should:
- Detect file type correctly
- Run appropriate tools
- Find the flag "flag{test_flag_12345}"
- Generate reports in output/
- Not crash or error

⚠️ If you see errors:
- Run `python3 check_dependencies.py` to verify installation
- Check that all tools are installed
- Verify Python dependencies: `pip3 install -r requirements.txt`

## Testing Each Playbook

### PNG Steganography (requires actual stego image)
```bash
# You'll need a real CTF image for this
ctf-ai --solve challenge.png
```

### JPEG Steganography
```bash
ctf-ai --solve image.jpg
```

### PCAP Analysis (need a .pcap file)
```bash
# Download a sample PCAP or create one
ctf-ai --solve capture.pcap
```

### Binary Analysis
```bash
# Any ELF binary
ctf-ai --solve /bin/ls
```

### Web Reconnaissance
```bash
ctf-ai
> solve http://example.com
```

## Verify Installation

```bash
# Check if commands exist
which ctf-ai
which ctfhunter

# Check Python modules
python3 -c "from modules import AIEngine, PlaybookExecutor; print('✅ Modules OK')"

# Check playbooks
ls playbooks/*.json

# Check dependencies
python3 check_dependencies.py
```

## Troubleshooting

### "Command not found: ctf-ai"
```bash
# Re-run installer
cd ctf-ai-ultimate
sudo ./install.sh
```

### "Module not found" errors
```bash
# Reinstall Python dependencies
pip3 install -r requirements.txt --force-reinstall
```

### "Tool not found" errors
```bash
# Install missing tool, example:
sudo apt-get install zsteg steghide binwalk
```

## Success Indicators

✅ Installation successful if:
- `ctf-ai` command works
- `ctfhunter` command works  
- No import errors when running
- Playbooks load correctly
- Tools are found (or show warnings)

## Ready for Real CTFs!

Once tests pass, you're ready to use it on real CTF challenges! 🚀

```bash
ctf-ai
> solve real_challenge.png
```

Good luck! 🔥
