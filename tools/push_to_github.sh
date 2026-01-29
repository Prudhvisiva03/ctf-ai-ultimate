#!/bin/bash
# Quick GitHub Push Script for CTF-AI Ultimate v2.1
# Run this to push all updates to GitHub

echo "🚀 Pushing CTF-AI Ultimate v2.1 to GitHub..."
echo ""

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo "❌ Error: Not a git repository!"
    echo "Run: git init"
    exit 1
fi

# Show what will be committed
echo "📝 Files to be committed:"
git status --short
echo ""

# Ask for confirmation
read -p "❓ Push these changes to GitHub? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Push cancelled"
    exit 1
fi

# Add all files
echo "📦 Adding files..."
git add .

# Commit with message
echo "💾 Committing changes..."
git commit -m "🎉 Release v2.1: Interactive Menu Mode + AI Guidance + Beautiful Colors

New Features:
- ✨ Interactive menu with 9 challenge categories
- 🧠 AI-powered guidance for each challenge type
- 🎨 Beautiful colorful interface with 40+ emojis
- 📄 File type detection and analysis
- 📝 Challenge description support
- 🔧 Fixed Kali Linux update script

Files Added:
- modules/colors.py - Complete color system
- test_colors.py - Color test suite
- demo_menu.py - Menu demonstration
- update.sh - Fixed Kali Linux update script
- quick_fix.sh - Quick fix for Kali
- Multiple documentation files

Files Updated:
- ctf-ai.py - Added menu_mode() and get_ai_guidance()
- ctfhunter.py - Added colorful output
- .gitignore - Enhanced rules

Breaking Changes: None
Compatibility: Python 3.8+, Kali Linux, Windows, Ubuntu"

# Push to GitHub
echo "🚀 Pushing to GitHub..."
git push origin main || git push origin master

# Create and push tag
echo "🏷️  Creating version tag..."
git tag -a v2.1 -m "Version 2.1: Interactive Menu Mode + AI Guidance"
git push origin v2.1

echo ""
echo "✅ Successfully pushed to GitHub!"
echo ""
echo "📢 Tell your friends to update:"
echo "   git pull origin main"
echo "   ./update.sh"
echo ""
echo "🎉 Done!"
