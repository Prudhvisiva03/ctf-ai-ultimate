#!/usr/bin/env python3
"""
Color Test Script for CTF-AI Ultimate
Demonstrates all the colorful features
"""

import sys
import os

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.colors import *

def main():
    """Test all color features"""
    
    # Banner
    print_banner("CTF-AI Ultimate", "Color Test Suite v2.0", width=70)
    print()
    
    # Status Messages
    print_header("Status Messages", Emoji.STAR)
    print_success("This is a success message!")
    print_error("This is an error message!")
    print_warning("This is a warning message!")
    print_info("This is an info message!")
    print()
    
    # Text Formatting
    print_header("Text Formatting", Emoji.SPARKLES)
    print(f"Highlighted text: {highlight('IMPORTANT')}")
    print(f"Code example: {code('python script.py')}")
    print(f"File path: {path('/path/to/file.txt')}")
    print(flag_text("picoCTF{test_flag_123}"))
    print()
    
    # Emojis
    print_header("Emoji Categories", Emoji.FIRE)
    print(f"{Emoji.SEARCH} Search  {Emoji.SCAN} Scan  {Emoji.ANALYZE} Analyze  {Emoji.EXTRACT} Extract")
    print(f"{Emoji.FILE} File  {Emoji.FOLDER} Folder  {Emoji.IMAGE} Image  {Emoji.ARCHIVE} Archive")
    print(f"{Emoji.LOCK} Lock  {Emoji.KEY} Key  {Emoji.SHIELD} Shield  {Emoji.FLAG} Flag  {Emoji.TARGET} Target")
    print(f"{Emoji.ROCKET} Rocket  {Emoji.TROPHY} Trophy  {Emoji.ROBOT} Robot  {Emoji.BRAIN} Brain")
    print()
    
    # Progress Bar
    print_header("Progress Indicators", Emoji.HOURGLASS)
    for i in range(0, 101, 25):
        print(progress_bar(i, 100))
    print()
    
    # Separators
    print_header("Separators", Emoji.TOOL)
    print_separator("=", 60, Colors.BRIGHT_CYAN)
    print_separator("-", 60, Colors.BRIGHT_YELLOW)
    print_separator("━", 60, Colors.BRIGHT_MAGENTA)
    print()
    
    # Box
    print_header("Boxed Messages", Emoji.PACKAGE)
    print(box("This is a boxed message\nWith multiple lines\nLooks professional!", width=50))
    print()
    
    # Table
    print_header("Table Example", Emoji.CHART)
    print_separator("═", 60, Colors.BRIGHT_BLACK)
    columns = ["Name", "Type", "Status"]
    widths = [20, 15, 15]
    colors = [Colors.BRIGHT_CYAN, Colors.BRIGHT_YELLOW, Colors.BRIGHT_GREEN]
    print(table_row(columns, widths, colors))
    print_separator("─", 60, Colors.BRIGHT_BLACK)
    
    data = [
        ["challenge.png", "Image", "✅ Solved"],
        ["data.zip", "Archive", "⏳ Processing"],
        ["capture.pcap", "Network", "❌ Failed"]
    ]
    for row in data:
        print(table_row(row, widths))
    print_separator("═", 60, Colors.BRIGHT_BLACK)
    print()
    
    # Color Palette
    print_header("Color Palette", Emoji.SPARKLES)
    colors_demo = [
        ("Red", Colors.BRIGHT_RED),
        ("Green", Colors.BRIGHT_GREEN),
        ("Yellow", Colors.BRIGHT_YELLOW),
        ("Blue", Colors.BRIGHT_BLUE),
        ("Magenta", Colors.BRIGHT_MAGENTA),
        ("Cyan", Colors.BRIGHT_CYAN),
        ("White", Colors.BRIGHT_WHITE)
    ]
    for name, color in colors_demo:
        print(f"{colorize('█' * 10, color)} {name}")
    print()
    
    # Final Message
    print_separator("═", 60, Colors.BRIGHT_CYAN)
    print(colorize(f"{Emoji.SUCCESS} All color features working perfectly!", Colors.BRIGHT_GREEN, bold=True).center(70))
    print_separator("═", 60, Colors.BRIGHT_CYAN)
    print()

if __name__ == "__main__":
    main()
