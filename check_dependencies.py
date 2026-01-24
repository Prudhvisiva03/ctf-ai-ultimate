#!/usr/bin/env python3
"""
CTFHunter Ultimate - Dependency Checker
Verifies that all required tools and libraries are installed
"""

import subprocess
import sys
import os

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def check_command(cmd, name=None):
    """Check if a command is available"""
    if name is None:
        name = cmd
    
    try:
        result = subprocess.run(
            ['which', cmd] if os.name != 'nt' else ['where', cmd],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✅ {name:20s} - Installed")
            return True
        else:
            print(f"❌ {name:20s} - NOT FOUND")
            return False
    except Exception as e:
        print(f"❌ {name:20s} - Error checking: {str(e)}")
        return False

def check_python_module(module, name=None):
    """Check if a Python module is installed"""
    if name is None:
        name = module
    
    try:
        __import__(module)
        print(f"✅ {name:20s} - Installed")
        return True
    except ImportError:
        print(f"❌ {name:20s} - NOT FOUND")
        return False

def main():
    """Main verification function"""
    
    print_header("CTFHunter Ultimate - Dependency Checker")
    
    # Track results
    total_checks = 0
    passed_checks = 0
    
    # Check Python version
    print("\n[*] Python Version")
    print(f"    Python {sys.version}")
    if sys.version_info >= (3, 8):
        print("    ✅ Version OK (3.8+)")
        passed_checks += 1
    else:
        print("    ❌ Python 3.8+ required")
    total_checks += 1
    
    # Check core system tools
    print_header("Core System Tools")
    tools = [
        ('file', 'file'),
        ('strings', 'strings'),
        ('exiftool', 'exiftool'),
        ('binwalk', 'binwalk'),
    ]
    
    for cmd, name in tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check steganography tools
    print_header("Steganography Tools")
    stego_tools = [
        ('steghide', 'steghide'),
        ('stegseek', 'stegseek'),
        ('zsteg', 'zsteg'),
    ]
    
    for cmd, name in stego_tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check archive tools
    print_header("Archive Tools")
    archive_tools = [
        ('unzip', 'unzip'),
        ('tar', 'tar'),
        ('7z', '7z'),
    ]
    
    for cmd, name in archive_tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check network tools
    print_header("Network Analysis Tools")
    network_tools = [
        ('tshark', 'tshark'),
    ]
    
    for cmd, name in network_tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check binary tools
    print_header("Binary Analysis Tools")
    binary_tools = [
        ('checksec', 'checksec'),
        ('gdb', 'gdb'),
        ('ltrace', 'ltrace'),
        ('strace', 'strace'),
    ]
    
    for cmd, name in binary_tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check PDF tools
    print_header("PDF Analysis Tools")
    pdf_tools = [
        ('pdfinfo', 'pdfinfo'),
        ('pdftotext', 'pdftotext'),
    ]
    
    for cmd, name in pdf_tools:
        if check_command(cmd, name):
            passed_checks += 1
        total_checks += 1
    
    # Check Python modules
    print_header("Python Modules")
    modules = [
        ('magic', 'python-magic'),
        ('requests', 'requests'),
        ('bs4', 'beautifulsoup4'),
    ]
    
    for module, name in modules:
        if check_python_module(module, name):
            passed_checks += 1
        total_checks += 1
    
    # Check optional tools
    print_header("Optional Tools")
    optional_tools = [
        ('dirsearch', 'dirsearch'),
        ('nikto', 'nikto'),
        ('radare2', 'radare2'),
    ]
    
    print("(These are optional but recommended)")
    for cmd, name in optional_tools:
        check_command(cmd, name)
    
    # Check optional Python modules
    print("\n(Optional Python modules)")
    optional_modules = [
        ('openai', 'openai (for AI hints)'),
    ]
    
    for module, name in optional_modules:
        check_python_module(module, name)
    
    # Print summary
    print_header("Summary")
    
    percentage = (passed_checks / total_checks) * 100
    print(f"\n  Passed: {passed_checks}/{total_checks} ({percentage:.1f}%)")
    
    if percentage == 100:
        print("\n  🎉 All required dependencies are installed!")
        print("  You're ready to use CTFHunter Ultimate!")
    elif percentage >= 80:
        print("\n  ⚠️  Most dependencies installed, but some are missing.")
        print("  CTFHunter will work but some features may be unavailable.")
        print("\n  Run: sudo ./install.sh")
    else:
        print("\n  ❌ Many dependencies are missing.")
        print("  Please run the installation script:")
        print("\n  sudo ./install.sh")
    
    print("\n" + "=" * 60 + "\n")
    
    return 0 if percentage == 100 else 1

if __name__ == '__main__':
    sys.exit(main())
