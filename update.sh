#!/bin/bash

# CTF-AI Ultimate Updater

echo "🔄 Checking for updates..."
git pull

echo "📦 Updating dependencies..."
pip3 install -r requirements.txt

echo "🔧 Re-running installer configuration..."
chmod +x install.sh
sudo ./install.sh

echo "✅ Update complete! You are on the newest version."
