#!/bin/bash
# Simple install script - creates symlink to ctf-ai.py

echo "Installing ctf-ai command..."

# Create symlink in /usr/local/bin
sudo ln -sf "$(pwd)/ctf-ai.py" /usr/local/bin/ctf-ai
sudo chmod +x /usr/local/bin/ctf-ai

echo "✅ ctf-ai command installed!"
echo "Test with: ctf-ai --help"
