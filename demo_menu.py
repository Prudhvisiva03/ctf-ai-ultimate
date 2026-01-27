#!/usr/bin/env python3
"""
Demo script to showcase the new interactive menu mode
"""

import sys
import os

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.colors import *

def show_menu_demo():
    """Show what the menu looks like"""
    
    print()
    print(colorize("╔═══════════════════════════════════════════════════════════════╗", Colors.BRIGHT_CYAN))
    print(colorize("║           🎯 INTERACTIVE CHALLENGE SOLVER MENU 🎯             ║", Colors.BRIGHT_YELLOW, bold=True))
    print(colorize("╚═══════════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
    print()
    
    # Challenge type menu
    challenge_types = [
        ("1", "🔐 Cryptography", "Encrypted messages, ciphers, encoding", Colors.BRIGHT_RED),
        ("2", "🖼️  Steganography", "Hidden data in images (PNG, JPG, BMP)", Colors.BRIGHT_MAGENTA),
        ("3", "💾 Disk Forensics", "Disk images, MFT, file recovery", Colors.BRIGHT_BLUE),
        ("4", "📦 Archive Analysis", "ZIP, TAR, compressed files", Colors.BRIGHT_YELLOW),
        ("5", "📡 Network/PCAP", "Network captures, packet analysis", Colors.BRIGHT_CYAN),
        ("6", "💻 Binary/Reverse", "ELF, executables, reverse engineering", Colors.BRIGHT_GREEN),
        ("7", "📄 PDF Forensics", "PDF files, metadata, hidden content", Colors.BRIGHT_RED),
        ("8", "🌐 Web Challenges", "Websites, web vulnerabilities", Colors.BRIGHT_BLUE),
        ("9", "🔍 Generic Scan", "Auto-detect challenge type", Colors.BRIGHT_WHITE)
    ]
    
    print(colorize("Select Challenge Type:", Colors.BRIGHT_CYAN, bold=True))
    print(colorize("═" * 65, Colors.BRIGHT_BLACK))
    
    for num, emoji_name, desc, color in challenge_types:
        print(f"  {colorize(num, color, bold=True)}. {emoji_name:20s} - {colorize(desc, Colors.DIM)}")
    
    print(colorize("═" * 65, Colors.BRIGHT_BLACK))
    print(f"  {colorize('0', Colors.BRIGHT_RED, bold=True)}. {Emoji.UNLOCK} Exit to main menu")
    print()
    
    # Show example AI guidance
    print()
    print(colorize("═" * 65, Colors.BRIGHT_CYAN))
    print(colorize("Example: AI Guidance for Steganography", Colors.BRIGHT_YELLOW, bold=True).center(75))
    print(colorize("═" * 65, Colors.BRIGHT_CYAN))
    print()
    
    print(colorize(f"{Emoji.BRAIN} AI Guidance for 🖼️  Steganography:", Colors.BRIGHT_GREEN, bold=True))
    print(colorize("─" * 65, Colors.BRIGHT_BLACK))
    
    guidance = f"""{Emoji.IMAGE} Steganography Challenge Tips:
• Check EXIF metadata with exiftool
• Try LSB (Least Significant Bit) extraction
• Use tools: steghide, zsteg, stegsolve
• Look for hidden files with binwalk
• Check different color channels
• Try strings command for embedded text

{Emoji.INFO} File Info:
• Type: PNG image data, 800 x 600, 8-bit/color RGB
• Size: 245,678 bytes

{Emoji.DOCUMENT} Challenge Description:
Find the hidden message in the image"""
    
    print(colorize(guidance, Colors.BRIGHT_WHITE))
    print(colorize("─" * 65, Colors.BRIGHT_BLACK))
    print()
    
    # Show workflow
    print()
    print(colorize("═" * 65, Colors.BRIGHT_MAGENTA))
    print(colorize("Workflow Example", Colors.BRIGHT_YELLOW, bold=True).center(75))
    print(colorize("═" * 65, Colors.BRIGHT_MAGENTA))
    print()
    
    steps = [
        (f"{Emoji.QUESTION} Select option (0-9):", "2", Colors.BRIGHT_CYAN),
        (f"{Emoji.FILE} Enter file path:", "challenge.png", Colors.BRIGHT_YELLOW),
        (f"{Emoji.DOCUMENT} Challenge description:", "Find the hidden flag", Colors.BRIGHT_CYAN),
        (f"{Emoji.ROCKET} Proceed with AI-powered analysis? (y/n):", "y", Colors.BRIGHT_YELLOW),
    ]
    
    for prompt, answer, color in steps:
        print(colorize(prompt, color, bold=True) + f" {highlight(answer)}")
    
    print()
    print(colorize(f"{Emoji.SPARKLES} Starting AI-powered analysis...", Colors.BRIGHT_MAGENTA, bold=True))
    print()
    
    # Show final message
    print()
    print(colorize("═" * 65, Colors.BRIGHT_GREEN))
    print(colorize(f"{Emoji.SUCCESS} New Interactive Menu Mode Added!", Colors.BRIGHT_GREEN, bold=True).center(75))
    print(colorize("═" * 65, Colors.BRIGHT_GREEN))
    print()
    
    features = [
        "✅ 9 Challenge Types (Crypto, Stego, Disk, Archive, PCAP, Binary, PDF, Web, Generic)",
        "✅ AI-Powered Guidance for Each Type",
        "✅ File Type Detection & Info Display",
        "✅ Challenge Description Support",
        "✅ Interactive Step-by-Step Workflow",
        "✅ Beautiful Colorful Interface"
    ]
    
    for feature in features:
        print(f"  {feature}")
    
    print()
    print(colorize("To use: Run 'python ctf-ai.py' and type 'menu'", Colors.BRIGHT_CYAN, bold=True))
    print()

if __name__ == "__main__":
    show_menu_demo()
