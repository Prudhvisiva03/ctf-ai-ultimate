#!/usr/bin/env python3
"""
Tool Installer - Automatically detect and install missing CTF tools
Author: Prudhvi (CTFHunter)
Version: 2.2.0
"""

import shutil
import subprocess
import os
import sys


class ToolInstaller:
    """Automatically detect and install missing CTF tools"""
    
    # Comprehensive tool mapping
    TOOLS = {
        # Steganography
        'zsteg': {'type': 'gem', 'pkg': 'zsteg', 'desc': 'PNG steganography detector'},
        'steghide': {'type': 'apt', 'pkg': 'steghide', 'desc': 'JPEG steganography tool'},
        'stegseek': {'type': 'apt', 'pkg': 'stegseek', 'desc': 'Steghide password cracker'},
        'outguess': {'type': 'apt', 'pkg': 'outguess', 'desc': 'Steganography tool'},
        'stegoveritas': {'type': 'pip', 'pkg': 'stegoveritas', 'desc': 'Multi stego tool'},
        
        # Forensics
        'binwalk': {'type': 'apt', 'pkg': 'binwalk', 'desc': 'Firmware analysis'},
        'foremost': {'type': 'apt', 'pkg': 'foremost', 'desc': 'File carving'},
        'exiftool': {'type': 'apt', 'pkg': 'libimage-exiftool-perl', 'desc': 'Metadata extractor'},
        'strings': {'type': 'apt', 'pkg': 'binutils', 'desc': 'String extraction'},
        'file': {'type': 'apt', 'pkg': 'file', 'desc': 'File type detection'},
        'xxd': {'type': 'apt', 'pkg': 'xxd', 'desc': 'Hex dump'},
        
        # Network
        'tshark': {'type': 'apt', 'pkg': 'tshark', 'desc': 'Network analyzer'},
        'tcpdump': {'type': 'apt', 'pkg': 'tcpdump', 'desc': 'Packet capture'},
        
        # Binary
        'checksec': {'type': 'apt', 'pkg': 'checksec', 'desc': 'Binary security check'},
        'gdb': {'type': 'apt', 'pkg': 'gdb', 'desc': 'GNU debugger'},
        'radare2': {'type': 'apt', 'pkg': 'radare2', 'desc': 'Reverse engineering'},
        'ltrace': {'type': 'apt', 'pkg': 'ltrace', 'desc': 'Library call tracer'},
        'strace': {'type': 'apt', 'pkg': 'strace', 'desc': 'System call tracer'},
        
        # PDF
        'pdfinfo': {'type': 'apt', 'pkg': 'poppler-utils', 'desc': 'PDF info'},
        'pdftotext': {'type': 'apt', 'pkg': 'poppler-utils', 'desc': 'PDF to text'},
        
        # QR
        'zbarimg': {'type': 'apt', 'pkg': 'zbar-tools', 'desc': 'QR/barcode decoder'},
        
        # Audio
        'sox': {'type': 'apt', 'pkg': 'sox', 'desc': 'Audio processing'},
        'ffmpeg': {'type': 'apt', 'pkg': 'ffmpeg', 'desc': 'Media converter'},
        'ffprobe': {'type': 'apt', 'pkg': 'ffmpeg', 'desc': 'Media analyzer'},
        
        # Hash
        'hashcat': {'type': 'apt', 'pkg': 'hashcat', 'desc': 'Password cracker'},
        'john': {'type': 'apt', 'pkg': 'john', 'desc': 'John the Ripper'},
        
        # Web
        'curl': {'type': 'apt', 'pkg': 'curl', 'desc': 'URL transfer'},
        'wget': {'type': 'apt', 'pkg': 'wget', 'desc': 'File downloader'},
        
        # Image
        'convert': {'type': 'apt', 'pkg': 'imagemagick', 'desc': 'Image converter'},
        'identify': {'type': 'apt', 'pkg': 'imagemagick', 'desc': 'Image info'},
    }
    
    def __init__(self, config=None):
        self.config = config or {}
        
    @staticmethod
    def is_available(tool_name):
        """Check if tool is available"""
        return shutil.which(tool_name) is not None
    
    @staticmethod
    def install(tool_name, silent=False):
        """Install a tool"""
        if tool_name not in ToolInstaller.TOOLS:
            if not silent:
                print(f"⚠️  Unknown tool: {tool_name}")
            return False
        
        tool = ToolInstaller.TOOLS[tool_name]
        install_type = tool['type']
        package = tool['pkg']
        
        if not silent:
            print(f"🔄 Installing {tool_name} ({tool['desc']})...")
        
        try:
            if install_type == 'apt':
                cmd = ['sudo', 'apt-get', 'install', '-y', package]
            elif install_type == 'gem':
                cmd = ['sudo', 'gem', 'install', package]
            elif install_type == 'pip':
                cmd = ['pip3', 'install', package]
            else:
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                if not silent:
                    print(f"✅ {tool_name} installed successfully!")
                return True
            else:
                if not silent:
                    print(f"❌ Failed to install {tool_name}")
                    print(f"   Try: sudo apt-get install {package}")
                return False
                
        except subprocess.TimeoutExpired:
            if not silent:
                print(f"⏱️  Installation timed out")
            return False
        except Exception as e:
            if not silent:
                print(f"❌ Error: {e}")
            return False
    
    def check_and_install(self, tool_name):
        """Check if tool exists, if not install it"""
        if self.is_available(tool_name):
            return True
        return self.install(tool_name)
    
    def check_tools(self, tool_list, auto_install=True):
        """Check multiple tools"""
        available = []
        missing = []
        
        for tool in tool_list:
            if self.is_available(tool):
                available.append(tool)
            else:
                missing.append(tool)
        
        if missing and auto_install:
            print(f"\n⚠️  Missing tools: {', '.join(missing)}")
            response = input("Install automatically? (Y/n): ").strip().lower()
            
            if response != 'n':
                for tool in missing:
                    if self.install(tool):
                        available.append(tool)
        
        return available, missing
    
    @staticmethod
    def list_all():
        """List all supported tools"""
        print("\n📦 Supported Tools:\n")
        for name, info in ToolInstaller.TOOLS.items():
            status = "✅" if ToolInstaller.is_available(name) else "❌"
            print(f"  {status} {name:15} - {info['desc']}")
        print()

