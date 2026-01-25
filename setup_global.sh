#!/bin/bash
# Install the 'solve' command globally
# Usage: sudo ./setup_global.sh

echo "Installing 'solve' command..."

# Create the wrapper script
cat > /usr/local/bin/solve << 'EOF'
#!/bin/bash
# Wrapper for CTF-AI Ultimate

# Get the install directory (assuming it's in the user's home who ran sudo or current dir)
INSTALL_DIR="/home/$(logname)/ctf-ai-ultimate"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "❌ Error: Could not find CTF-AI in $INSTALL_DIR"
    echo "Please ensure the repository is cloned to ~/ctf-ai-ultimate"
    exit 1
fi

# Pass all arguments to python script
# We filter out the -d flag if it exists to pass it correctly
sudo python3 "$INSTALL_DIR/ctf-ai.py" --config "$INSTALL_DIR/config.json" --ai=none --solve "$@"
EOF

# Make it executable
chmod +x /usr/local/bin/solve

echo "✅ 'solve' command installed!"
echo "Usage: solve <filename> [-d description]"
