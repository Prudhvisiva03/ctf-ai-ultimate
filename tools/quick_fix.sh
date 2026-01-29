#!/bin/bash
# Quick fix for Kali Linux externally-managed-environment error
# Just run: ./quick_fix.sh

echo "🔧 Fixing Kali Linux Python package installation..."
echo ""

# Update Python packages with --break-system-packages flag
python3 -m pip install -r requirements.txt --upgrade --break-system-packages

echo ""
echo "✅ Done! Python packages updated successfully!"
echo ""
echo "🚀 Test it:"
echo "   python3 ctf-ai.py --help"
echo "   python3 test_colors.py"
echo ""
