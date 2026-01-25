#!/bin/bash
# Shortcut script to solve challenges easily
# Usage: ./solve.sh <file_path>

if [ -z "$1" ]; then
    echo "Usage: ./solve.sh <file_path>"
    exit 1
fi

echo "🚀 Solving: $1"
sudo python3 ctf-ai.py --config config.json --ai=none --solve "$1"
