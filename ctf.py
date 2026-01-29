#!/usr/bin/env python3
"""
CTFHunter - The World's First AI-Powered CTF Assistant
Simple & Beautiful Interface
Author: Prudhvi
Version: 3.0.0
"""

import os
import sys
import json
import subprocess
import re
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════════
# COLORS & STYLING
# ═══════════════════════════════════════════════════════════════════════════════

class Style:
    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Box characters
    TL = '╔'  # Top left
    TR = '╗'  # Top right
    BL = '╚'  # Bottom left
    BR = '╝'  # Bottom right
    H = '═'   # Horizontal
    V = '║'   # Vertical


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print beautiful banner"""
    banner = f"""
{Style.CYAN}
    ██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ██║        ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██║        ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET}
   {Style.GREEN}🤖 AI-Powered CTF Assistant{Style.RESET}  {Style.GRAY}│{Style.RESET}  {Style.YELLOW}v3.0.0{Style.RESET}  {Style.GRAY}│{Style.RESET}  {Style.MAGENTA}By Prudhvi{Style.RESET}
   {Style.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET}
"""
    print(banner)


def print_box(title, content, color=Style.CYAN):
    """Print content in a nice box"""
    width = 70
    print(f"\n{color}{Style.TL}{Style.H * (width-2)}{Style.TR}{Style.RESET}")
    print(f"{color}{Style.V}{Style.RESET} {Style.BOLD}{title}{Style.RESET}{' ' * (width - len(title) - 4)}{color}{Style.V}{Style.RESET}")
    print(f"{color}{Style.V}{Style.H * (width-2)}{Style.V}{Style.RESET}")
    
    for line in content.split('\n'):
        padding = width - len(line) - 4
        print(f"{color}{Style.V}{Style.RESET} {line}{' ' * max(0, padding)}{color}{Style.V}{Style.RESET}")
    
    print(f"{color}{Style.BL}{Style.H * (width-2)}{Style.BR}{Style.RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CTFHUNTER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class CTFHunter:
    def __init__(self):
        self.file_path = None
        self.flag_format = "flag{}"
        self.description = ""
        self.results = {'flags': [], 'findings': []}
        
    def prompt(self, text, color=Style.CYAN):
        """Beautiful prompt"""
        return input(f"\n{color}{Style.BOLD}  {text}{Style.RESET} {Style.GRAY}➜{Style.RESET}  ")
    
    def info(self, text):
        """Print info message"""
        print(f"  {Style.BLUE}ℹ{Style.RESET}  {text}")
    
    def success(self, text):
        """Print success message"""
        print(f"  {Style.GREEN}✓{Style.RESET}  {text}")
    
    def warning(self, text):
        """Print warning message"""
        print(f"  {Style.YELLOW}⚠{Style.RESET}  {text}")
    
    def error(self, text):
        """Print error message"""
        print(f"  {Style.RED}✗{Style.RESET}  {text}")
    
    def flag_found(self, flag):
        """Print flag found"""
        print(f"\n  {Style.GREEN}{Style.BOLD}🚩 FLAG FOUND!{Style.RESET}")
        print(f"  {Style.GREEN}╔{'═'*60}╗{Style.RESET}")
        print(f"  {Style.GREEN}║{Style.RESET}  {Style.YELLOW}{Style.BOLD}{flag}{Style.RESET}")
        print(f"  {Style.GREEN}╚{'═'*60}╝{Style.RESET}\n")

    # ───────────────────────────────────────────────────────────────────────────
    # SIMPLE INTERACTIVE MODE
    # ───────────────────────────────────────────────────────────────────────────
    
    def simple_mode(self):
        """Simple interactive mode with clean prompts"""
        clear_screen()
        print_banner()
        
        print(f"\n  {Style.GRAY}Welcome! Let's solve your CTF challenge.{Style.RESET}")
        print(f"  {Style.GRAY}Press Enter to skip optional fields.{Style.RESET}\n")
        
        # File path (required)
        while True:
            self.file_path = self.prompt("File path")
            if not self.file_path:
                self.error("File path is required!")
                continue
            if not os.path.exists(self.file_path):
                self.error(f"File not found: {self.file_path}")
                continue
            self.success(f"File: {os.path.basename(self.file_path)}")
            break
        
        # Flag format (optional)
        flag_input = self.prompt("Flag format (e.g., flag{}, CTF{})", Style.YELLOW)
        if flag_input:
            self.flag_format = flag_input if '{}' in flag_input else f"{flag_input}{{}}"
            self.success(f"Looking for: {self.flag_format}")
        else:
            self.info(f"Using default: {self.flag_format}")
        
        # Description (optional)
        self.description = self.prompt("Challenge description (optional)", Style.MAGENTA)
        if self.description:
            self.info(f"Description noted")
        
        # Start analysis
        print(f"\n  {Style.CYAN}{'─'*60}{Style.RESET}")
        print(f"  {Style.BOLD}Starting analysis...{Style.RESET}")
        print(f"  {Style.CYAN}{'─'*60}{Style.RESET}\n")
        
        self.analyze()
        
        # Show results
        self.show_results()
        
        # Continue prompt
        print(f"\n  {Style.GRAY}{'─'*60}{Style.RESET}")
        again = self.prompt("Analyze another file? (y/n)", Style.GREEN)
        if again.lower() == 'y':
            self.results = {'flags': [], 'findings': []}
            self.simple_mode()

    # ───────────────────────────────────────────────────────────────────────────
    # MENU MODE
    # ───────────────────────────────────────────────────────────────────────────
    
    def menu_mode(self):
        """Beautiful menu-based interface"""
        while True:
            clear_screen()
            print_banner()
            
            menu = """
    ┌─────────────────────────────────────────┐
    │                                         │
    │   [1]  🔍  Quick Scan                   │
    │   [2]  🎯  Full Analysis                │
    │   [3]  🔗  Decode Text/Encoding         │
    │   [4]  🔓  Crack Cipher                 │
    │   [5]  📦  Extract Files                │
    │   [6]  🔮  Check File Type              │
    │   [7]  ⚙️   Settings                     │
    │   [0]  🚪  Exit                         │
    │                                         │
    └─────────────────────────────────────────┘
"""
            print(f"{Style.WHITE}{menu}{Style.RESET}")
            
            choice = self.prompt("Select option", Style.GREEN)
            
            if choice == '1':
                self.quick_scan()
            elif choice == '2':
                self.full_analysis()
            elif choice == '3':
                self.decode_mode()
            elif choice == '4':
                self.cipher_mode()
            elif choice == '5':
                self.extract_mode()
            elif choice == '6':
                self.filetype_mode()
            elif choice == '7':
                self.settings_mode()
            elif choice == '0':
                print(f"\n  {Style.GREEN}Goodbye! Happy hacking! 🎯{Style.RESET}\n")
                sys.exit(0)
            else:
                self.warning("Invalid option!")
                input(f"  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def quick_scan(self):
        """Quick scan mode"""
        clear_screen()
        print_banner()
        print_box("QUICK SCAN", "Fast analysis with common tools", Style.BLUE)
        
        self.file_path = self.prompt("File path")
        if not self.file_path or not os.path.exists(self.file_path):
            self.error("Invalid file!")
            input(f"  {Style.GRAY}Press Enter...{Style.RESET}")
            return
        
        self.flag_format = self.prompt("Flag format (Enter for default)") or "flag{}"
        
        print(f"\n  {Style.CYAN}Scanning...{Style.RESET}\n")
        self.analyze()
        self.show_results()
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def full_analysis(self):
        """Full analysis with all tools"""
        self.simple_mode()
    
    def decode_mode(self):
        """Decode text/encoding mode"""
        clear_screen()
        print_banner()
        print_box("DECODE MODE", "Decode Base64, Hex, Binary, and more", Style.MAGENTA)
        
        print(f"\n  {Style.GRAY}Enter encoded text (or file path):{Style.RESET}")
        data = self.prompt("Input")
        
        if os.path.isfile(data):
            with open(data, 'r') as f:
                data = f.read()
        
        self.flag_format = self.prompt("Flag format (Enter for default)") or "flag{}"
        
        print(f"\n  {Style.CYAN}Decoding...{Style.RESET}\n")
        
        try:
            from modules.chain_decoder import ChainDecoder
            decoder = ChainDecoder()
            results = decoder.analyze_string(data, self.flag_format)
            
            if results.get('flags_found'):
                for flag in results['flags_found']:
                    self.flag_found(flag)
            
            if results.get('decoding_chain'):
                print(f"\n  {Style.BLUE}Decoding Chain:{Style.RESET}")
                for step in results['decoding_chain']:
                    print(f"    {Style.GRAY}→{Style.RESET} {step['encoding']}: {step['decoded'][:60]}")
        except Exception as e:
            self.error(f"Error: {e}")
        
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def cipher_mode(self):
        """Cipher cracking mode"""
        clear_screen()
        print_banner()
        print_box("CIPHER CRACKER", "Auto-crack Caesar, ROT13, Vigenere, XOR", Style.RED)
        
        data = self.prompt("Ciphertext")
        self.flag_format = self.prompt("Flag format (Enter for default)") or "flag{}"
        
        print(f"\n  {Style.CYAN}Cracking...{Style.RESET}\n")
        
        try:
            from modules.cipher_cracker import CipherCracker
            cracker = CipherCracker()
            results = cracker.analyze(data, self.flag_format)
            
            if results.get('cracked_text'):
                print(f"\n  {Style.GREEN}Cracked ({results.get('detected_cipher')}):{Style.RESET}")
                print(f"  {Style.YELLOW}{results['cracked_text'][:200]}{Style.RESET}")
        except Exception as e:
            self.error(f"Error: {e}")
        
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def extract_mode(self):
        """Extract hidden files"""
        clear_screen()
        print_banner()
        print_box("EXTRACT FILES", "Extract embedded files using binwalk", Style.GREEN)
        
        self.file_path = self.prompt("File path")
        if not self.file_path or not os.path.exists(self.file_path):
            self.error("Invalid file!")
            input(f"  {Style.GRAY}Press Enter...{Style.RESET}")
            return
        
        print(f"\n  {Style.CYAN}Extracting...{Style.RESET}\n")
        
        try:
            result = subprocess.run(['binwalk', '-e', self.file_path], 
                                   capture_output=True, text=True, timeout=60)
            print(result.stdout)
            self.success("Check the _extracted folder!")
        except Exception as e:
            self.error(f"binwalk error: {e}")
        
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def filetype_mode(self):
        """Check file type"""
        clear_screen()
        print_banner()
        print_box("FILE TYPE CHECK", "Detect real file type via magic bytes", Style.YELLOW)
        
        self.file_path = self.prompt("File path")
        if not self.file_path or not os.path.exists(self.file_path):
            self.error("Invalid file!")
            input(f"  {Style.GRAY}Press Enter...{Style.RESET}")
            return
        
        try:
            from modules.magic_checker import MagicChecker
            checker = MagicChecker()
            results = checker.analyze(self.file_path)
            
            if results.get('detected_type'):
                dtype = results['detected_type']
                print(f"\n  {Style.GREEN}Detected: {dtype['desc']} (.{dtype['ext']}){Style.RESET}")
            
            if results.get('anomalies'):
                print(f"\n  {Style.YELLOW}Anomalies:{Style.RESET}")
                for a in results['anomalies']:
                    print(f"    {Style.RED}!{Style.RESET} {a}")
        except Exception as e:
            self.error(f"Error: {e}")
        
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")
    
    def settings_mode(self):
        """Settings"""
        clear_screen()
        print_banner()
        print_box("SETTINGS", "Configure CTFHunter", Style.GRAY)
        
        print(f"""
    Current Settings:
    
    • Default flag format: {self.flag_format}
    • Output directory: output/
    
    {Style.GRAY}(Settings are saved automatically){Style.RESET}
""")
        
        new_format = self.prompt("New default flag format (Enter to keep)")
        if new_format:
            self.flag_format = new_format
            self.success(f"Flag format updated to: {new_format}")
        
        input(f"\n  {Style.GRAY}Press Enter to continue...{Style.RESET}")

    # ───────────────────────────────────────────────────────────────────────────
    # ANALYSIS ENGINE
    # ───────────────────────────────────────────────────────────────────────────
    
    def analyze(self):
        """Run analysis on the file"""
        if not self.file_path:
            return
        
        # Detect file type
        ext = os.path.splitext(self.file_path)[1].lower()
        
        # Run tools based on file type
        self.run_strings()
        self.run_exiftool()
        
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            self.run_image_tools()
        elif ext in ['.pcap', '.pcapng']:
            self.run_pcap_tools()
        elif ext in ['.pdf']:
            self.run_pdf_tools()
        elif ext in ['.zip', '.tar', '.gz', '.7z', '.rar']:
            self.run_archive_tools()
        
        # Chain decoder for encoded data
        self.run_chain_decoder()
    
    def run_tool(self, name, cmd):
        """Run a tool and search for flags"""
        print(f"  {Style.BLUE}▸{Style.RESET} {name}...", end=" ", flush=True)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            
            # Search for flags
            flags = self.search_flags(output)
            if flags:
                print(f"{Style.GREEN}🚩 Found!{Style.RESET}")
                self.results['flags'].extend(flags)
            else:
                print(f"{Style.GREEN}✓{Style.RESET}")
            
            return output
        except FileNotFoundError:
            print(f"{Style.YELLOW}not installed{Style.RESET}")
            return ""
        except subprocess.TimeoutExpired:
            print(f"{Style.YELLOW}timeout{Style.RESET}")
            return ""
        except Exception as e:
            print(f"{Style.RED}error{Style.RESET}")
            return ""
    
    def search_flags(self, text):
        """Search for flags in text"""
        flags = []
        
        # Custom flag format
        prefix = self.flag_format.replace('{}', '').replace('{', '').replace('}', '')
        patterns = [
            rf'{re.escape(prefix)}\{{[^}}]+\}}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def run_strings(self):
        output = self.run_tool("strings", ['strings', '-n', '8', self.file_path])
        
    def run_exiftool(self):
        output = self.run_tool("exiftool", ['exiftool', self.file_path])
        if output:
            # Check for GPS
            if 'GPS' in output:
                self.results['findings'].append("📍 GPS coordinates found in metadata!")
    
    def run_image_tools(self):
        ext = os.path.splitext(self.file_path)[1].lower()
        
        self.run_tool("binwalk", ['binwalk', self.file_path])
        
        if ext == '.png':
            self.run_tool("zsteg", ['zsteg', self.file_path])
            self.run_tool("pngcheck", ['pngcheck', self.file_path])
        
        if ext in ['.jpg', '.jpeg']:
            self.run_tool("steghide info", ['steghide', 'info', '-p', '', self.file_path])
        
        self.run_tool("zbarimg (QR)", ['zbarimg', '--raw', '-q', self.file_path])
    
    def run_pcap_tools(self):
        self.run_tool("tshark", ['tshark', '-r', self.file_path, '-Y', 'http'])
    
    def run_pdf_tools(self):
        self.run_tool("pdfinfo", ['pdfinfo', self.file_path])
        output = self.run_tool("pdftotext", ['pdftotext', self.file_path, '-'])
        
    def run_archive_tools(self):
        self.run_tool("unzip -l", ['unzip', '-l', self.file_path])
    
    def run_chain_decoder(self):
        """Run chain decoder for nested encodings"""
        print(f"  {Style.MAGENTA}▸{Style.RESET} chain decoder...", end=" ", flush=True)
        
        try:
            from modules.chain_decoder import ChainDecoder
            decoder = ChainDecoder()
            results = decoder.analyze_file(self.file_path, self.flag_format)
            
            if results.get('flags_found'):
                print(f"{Style.GREEN}🚩 Found!{Style.RESET}")
                self.results['flags'].extend(results['flags_found'])
            else:
                print(f"{Style.GREEN}✓{Style.RESET}")
            
            if results.get('decoding_chain'):
                chains = results['decoding_chain']
                if chains:
                    self.results['findings'].append(f"🔗 Found {len(chains)} encoding chain(s)")
        except Exception as e:
            print(f"{Style.YELLOW}error{Style.RESET}")
    
    def show_results(self):
        """Display final results"""
        print(f"\n  {Style.CYAN}{'═'*60}{Style.RESET}")
        print(f"  {Style.BOLD}RESULTS{Style.RESET}")
        print(f"  {Style.CYAN}{'═'*60}{Style.RESET}")
        
        # Flags
        unique_flags = list(set(self.results['flags']))
        if unique_flags:
            for flag in unique_flags:
                self.flag_found(flag)
        else:
            print(f"\n  {Style.YELLOW}No flags found yet.{Style.RESET}")
            print(f"  {Style.GRAY}Try manual analysis or different tools.{Style.RESET}")
        
        # Findings
        if self.results['findings']:
            print(f"\n  {Style.BLUE}Findings:{Style.RESET}")
            for finding in self.results['findings']:
                print(f"    • {finding}")


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    hunter = CTFHunter()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg in ['-h', '--help']:
            print(f"""
{Style.CYAN}CTFHunter - AI-Powered CTF Assistant{Style.RESET}

{Style.BOLD}Usage:{Style.RESET}
  python ctf.py                    Interactive mode (recommended)
  python ctf.py --menu             Menu-based GUI mode
  python ctf.py <file>             Quick scan a file
  python ctf.py <file> -f <format> Scan with custom flag format

{Style.BOLD}Examples:{Style.RESET}
  python ctf.py
  python ctf.py challenge.png
  python ctf.py image.png -f "digitalcyberhunt{{}}"
  python ctf.py --menu

{Style.BOLD}Options:{Style.RESET}
  -h, --help     Show this help
  -m, --menu     Menu mode
  -f, --flag     Flag format (e.g., flag{{}}, CTF{{}})
  -d, --desc     Challenge description
""")
            return
        
        elif arg in ['-m', '--menu']:
            hunter.menu_mode()
            return
        
        elif os.path.exists(arg):
            # Quick scan mode
            hunter.file_path = arg
            
            # Check for flag format
            if '-f' in sys.argv or '--flag' in sys.argv:
                try:
                    idx = sys.argv.index('-f') if '-f' in sys.argv else sys.argv.index('--flag')
                    hunter.flag_format = sys.argv[idx + 1]
                except:
                    pass
            
            # Check for description
            if '-d' in sys.argv or '--desc' in sys.argv:
                try:
                    idx = sys.argv.index('-d') if '-d' in sys.argv else sys.argv.index('--desc')
                    hunter.description = sys.argv[idx + 1]
                except:
                    pass
            
            clear_screen()
            print_banner()
            print(f"\n  {Style.CYAN}Quick Scan: {Style.YELLOW}{hunter.file_path}{Style.RESET}")
            print(f"  {Style.CYAN}Flag Format: {Style.YELLOW}{hunter.flag_format}{Style.RESET}\n")
            
            hunter.analyze()
            hunter.show_results()
            return
    
    # Default: Simple interactive mode
    hunter.simple_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Style.YELLOW}Interrupted. Goodbye!{Style.RESET}\n")
        sys.exit(0)
