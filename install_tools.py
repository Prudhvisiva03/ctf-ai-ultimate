#!/usr/bin/env python3
"""
CTFHunter Tool Installer
Automatically installs all required tools for CTFHunter
"""

import subprocess
import sys
import os
import platform

# Cross-platform support
IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MAC = sys.platform == 'darwin'


def run_command(cmd, shell=False):
    """Run a command and return success status"""
    try:
        if IS_WINDOWS and not shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        return False


def check_command(cmd):
    """Check if a command exists"""
    try:
        if IS_WINDOWS:
            result = subprocess.run(f'where {cmd}', shell=True, capture_output=True)
        else:
            result = subprocess.run(['which', cmd], capture_output=True)
        return result.returncode == 0
    except:
        return False


def install_python_packages():
    """Install required Python packages"""
    print("\n[*] Installing Python packages...")
    
    packages = [
        'rich>=13.0.0',
        'requests',
        'beautifulsoup4',
        'pycryptodome',
        'python-magic-bin' if IS_WINDOWS else 'python-magic',
        'Pillow',
        'numpy',
        'scipy',
        'openai',
        'anthropic',
        'groq',
        'scapy',
        'pyshark',
        'PyPDF2',
        'pdfminer.six',
        'yara-python',
    ]
    
    for package in packages:
        print(f"    Installing {package}...")
        run_command(f'{sys.executable} -m pip install "{package}" --quiet')
    
    print("[+] Python packages installed!")


def install_linux_tools():
    """Install tools on Linux"""
    print("\n[*] Installing Linux tools...")
    
    # Detect package manager
    if check_command('apt'):
        pkg_manager = 'apt'
        install_cmd = 'sudo apt install -y'
    elif check_command('yum'):
        pkg_manager = 'yum'
        install_cmd = 'sudo yum install -y'
    elif check_command('pacman'):
        pkg_manager = 'pacman'
        install_cmd = 'sudo pacman -S --noconfirm'
    else:
        print("[!] Unknown package manager. Please install tools manually.")
        return
    
    print(f"    Using {pkg_manager} package manager")
    
    # Update package list
    if pkg_manager == 'apt':
        run_command('sudo apt update', shell=True)
    
    # Essential tools
    tools = {
        'apt': [
            'binwalk', 'foremost', 'exiftool', 'steghide', 'zsteg',
            'stegseek', 'strings', 'file', 'xxd', 'hexdump',
            'tshark', 'tcpdump', 'nmap', 'nikto', 'gobuster',
            'john', 'hashcat', 'hydra',
            'radare2', 'gdb', 'ltrace', 'strace',
            'ffmpeg', 'sox', 'audacity',
            'volatility3', 'yara',
            'pdftotext', 'poppler-utils',
            'testdisk', 'photorec', 'sleuthkit',
            'curl', 'wget', 'git'
        ],
        'yum': [
            'binwalk', 'foremost', 'perl-Image-ExifTool',
            'file', 'xxd', 'wireshark', 'nmap',
            'radare2', 'gdb', 'ltrace', 'strace',
            'ffmpeg', 'sox', 'yara',
            'poppler-utils', 'testdisk',
            'curl', 'wget', 'git'
        ],
        'pacman': [
            'binwalk', 'foremost', 'perl-image-exiftool',
            'file', 'xxd', 'wireshark-cli', 'nmap',
            'radare2', 'gdb', 'ltrace', 'strace',
            'ffmpeg', 'sox', 'yara',
            'poppler', 'testdisk',
            'curl', 'wget', 'git'
        ]
    }
    
    for tool in tools.get(pkg_manager, []):
        print(f"    Installing {tool}...")
        run_command(f'{install_cmd} {tool}', shell=True)
    
    # Install Ruby tools
    if check_command('gem'):
        print("    Installing zsteg via gem...")
        run_command('sudo gem install zsteg', shell=True)
    
    print("[+] Linux tools installed!")


def install_macos_tools():
    """Install tools on macOS"""
    print("\n[*] Installing macOS tools...")
    
    if not check_command('brew'):
        print("[!] Homebrew not found. Installing...")
        run_command('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"', shell=True)
    
    tools = [
        'binwalk', 'foremost', 'exiftool', 'steghide',
        'file', 'xxd', 'wireshark', 'nmap',
        'radare2', 'ffmpeg', 'sox',
        'poppler', 'testdisk', 'sleuthkit',
        'curl', 'wget', 'git', 'yara'
    ]
    
    for tool in tools:
        print(f"    Installing {tool}...")
        run_command(f'brew install {tool}', shell=True)
    
    # Install Ruby tools
    print("    Installing zsteg via gem...")
    run_command('gem install zsteg', shell=True)
    
    print("[+] macOS tools installed!")


def install_windows_tools():
    """Install tools on Windows"""
    print("\n[*] Installing Windows tools...")
    print("[!] Note: Some tools need manual installation on Windows")
    
    # Check for chocolatey
    has_choco = check_command('choco')
    has_scoop = check_command('scoop')
    
    if has_choco:
        print("    Using Chocolatey package manager")
        tools = [
            'exiftool', 'ffmpeg', 'wget', 'curl', 'git',
            'wireshark', 'nmap', '7zip',
            'hashcat', 'john',
        ]
        
        for tool in tools:
            print(f"    Installing {tool}...")
            run_command(f'choco install {tool} -y', shell=True)
    
    elif has_scoop:
        print("    Using Scoop package manager")
        tools = [
            'exiftool', 'ffmpeg', 'wget', 'curl', 'git',
            '7zip', 'nmap'
        ]
        
        for tool in tools:
            print(f"    Installing {tool}...")
            run_command(f'scoop install {tool}', shell=True)
    
    else:
        print("[!] No package manager found!")
        print("    Recommended: Install Chocolatey from https://chocolatey.org/")
        print("    Or Scoop from https://scoop.sh/")
        print("")
        print("    Manual installation required for:")
        print("    - ExifTool: https://exiftool.org/")
        print("    - FFmpeg: https://ffmpeg.org/")
        print("    - Wireshark: https://www.wireshark.org/")
        print("    - Nmap: https://nmap.org/")
        print("    - 7-Zip: https://www.7-zip.org/")
        print("    - Volatility: https://www.volatilityfoundation.org/")
        print("    - Ghidra: https://ghidra-sre.org/")
    
    print("[+] Windows tools setup complete!")


def check_installed_tools():
    """Check which tools are installed"""
    print("\n[*] Checking installed tools...")
    
    tools = {
        'File Analysis': ['file', 'strings', 'xxd', 'hexdump', 'binwalk'],
        'Steganography': ['steghide', 'zsteg', 'stegseek', 'exiftool'],
        'Network': ['tshark', 'tcpdump', 'nmap', 'nikto', 'gobuster'],
        'Forensics': ['foremost', 'testdisk', 'volatility', 'volatility3'],
        'Reverse Engineering': ['radare2', 'r2', 'gdb', 'objdump', 'ltrace'],
        'Password Cracking': ['john', 'hashcat', 'hydra'],
        'Media': ['ffmpeg', 'ffprobe', 'sox'],
        'PDF': ['pdftotext', 'pdfinfo'],
        'General': ['curl', 'wget', 'git', 'python3', 'pip']
    }
    
    print("\n" + "=" * 60)
    print(" TOOL STATUS CHECK")
    print("=" * 60)
    
    for category, tool_list in tools.items():
        print(f"\n{category}:")
        for tool in tool_list:
            if check_command(tool):
                print(f"  [OK] {tool}")
            else:
                print(f"  [X]  {tool} - NOT INSTALLED")
    
    print("\n" + "=" * 60)


def main():
    """Main function"""
    print("=" * 60)
    print("  CTFHunter Tool Installer")
    print("=" * 60)
    print(f"  System: {platform.system()} {platform.release()}")
    print(f"  Python: {sys.version.split()[0]}")
    print("=" * 60)
    
    # Install Python packages first
    install_python_packages()
    
    # Install system tools based on OS
    if IS_LINUX:
        install_linux_tools()
    elif IS_MAC:
        install_macos_tools()
    elif IS_WINDOWS:
        install_windows_tools()
    
    # Check what's installed
    check_installed_tools()
    
    print("\n[OK] Installation complete!")
    print("\nTo use CTFHunter:")
    print("  python ctfhunter.py <file>")
    print("  python ctf-ai.py --solve <file>")
    print("  python ctf.py  # Interactive mode")


if __name__ == '__main__':
    main()
