#!/usr/bin/env python3
"""
CTFHunter - The World's First AI-Powered CTF Assistant
Version: 2.2.0
Author: Prudhvi

Features:
- Custom flag format support (ask user for pattern like siva{}, flag{}, etc.)
- Auto-install missing tools
- Challenge description for better AI context
- Natural language commands
- Multi-AI support (OpenAI, Ollama, Claude, Groq)
- 25+ integrated security tools
- Smart playbook system

Usage:
    python ctfhunter_pro.py solve /path/to/file -d "challenge description"
    python ctfhunter_pro.py interactive
"""

import sys
import os
import subprocess
import json
import argparse
import shutil
import re
from pathlib import Path
from datetime import datetime

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# Import modules
try:
    from modules.file_scan import FileScanner
    from modules.stego_scan import StegoScanner
    from modules.zip_scan import ArchiveScanner
    from modules.pcap_scan import PCAPScanner
    from modules.pdf_scan import PDFScanner
    from modules.reporter import Reporter
    from modules.crypto_analyzer import analyze_crypto
    from modules.osint_scanner import OSINTScanner
    from modules.qr_scanner import QRScanner
    from modules.hash_identifier import HashIdentifier
    from modules.audio_stego import AudioStegoScanner
    from modules.html_reporter import HTMLReporter
except ImportError as e:
    print(f"⚠️  Module import error: {e}")
    print("[*] Some features may not be available")


class Colors:
    """ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class ToolManager:
    """Manage and auto-install CTF tools"""
    
    # Comprehensive tool installation mapping
    TOOL_INSTALL_MAP = {
        # Steganography tools
        'zsteg': {'type': 'gem', 'package': 'zsteg'},
        'steghide': {'type': 'apt', 'package': 'steghide'},
        'stegseek': {'type': 'apt', 'package': 'stegseek'},
        'outguess': {'type': 'apt', 'package': 'outguess'},
        'stegoveritas': {'type': 'pip', 'package': 'stegoveritas'},
        
        # Forensics tools
        'binwalk': {'type': 'apt', 'package': 'binwalk'},
        'foremost': {'type': 'apt', 'package': 'foremost'},
        'exiftool': {'type': 'apt', 'package': 'libimage-exiftool-perl'},
        'strings': {'type': 'apt', 'package': 'binutils'},
        'file': {'type': 'apt', 'package': 'file'},
        'xxd': {'type': 'apt', 'package': 'xxd'},
        
        # Network tools
        'tshark': {'type': 'apt', 'package': 'tshark'},
        'wireshark': {'type': 'apt', 'package': 'wireshark'},
        'tcpdump': {'type': 'apt', 'package': 'tcpdump'},
        
        # Binary analysis
        'checksec': {'type': 'apt', 'package': 'checksec'},
        'gdb': {'type': 'apt', 'package': 'gdb'},
        'radare2': {'type': 'apt', 'package': 'radare2'},
        'ltrace': {'type': 'apt', 'package': 'ltrace'},
        'strace': {'type': 'apt', 'package': 'strace'},
        
        # PDF tools
        'pdfinfo': {'type': 'apt', 'package': 'poppler-utils'},
        'pdftotext': {'type': 'apt', 'package': 'poppler-utils'},
        
        # QR tools
        'zbarimg': {'type': 'apt', 'package': 'zbar-tools'},
        
        # Audio tools
        'sox': {'type': 'apt', 'package': 'sox'},
        'ffmpeg': {'type': 'apt', 'package': 'ffmpeg'},
        'ffprobe': {'type': 'apt', 'package': 'ffmpeg'},
        
        # Hash cracking
        'hashcat': {'type': 'apt', 'package': 'hashcat'},
        'john': {'type': 'apt', 'package': 'john'},
        
        # Web tools
        'curl': {'type': 'apt', 'package': 'curl'},
        'wget': {'type': 'apt', 'package': 'wget'},
        
        # Image tools
        'convert': {'type': 'apt', 'package': 'imagemagick'},
        'identify': {'type': 'apt', 'package': 'imagemagick'},
        
        # Python libraries
        'pyzbar': {'type': 'pip', 'package': 'pyzbar'},
        'pillow': {'type': 'pip', 'package': 'Pillow'},
    }
    
    @staticmethod
    def check_tool(tool_name):
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None
    
    @staticmethod
    def install_tool(tool_name, silent=False):
        """Install a missing tool"""
        if tool_name not in ToolManager.TOOL_INSTALL_MAP:
            if not silent:
                print(f"   ⚠️  Unknown tool: {tool_name} - manual install required")
            return False
        
        tool_info = ToolManager.TOOL_INSTALL_MAP[tool_name]
        install_type = tool_info['type']
        package = tool_info['package']
        
        try:
            if not silent:
                print(f"   🔄 Installing {tool_name}...")
            
            if install_type == 'apt':
                result = subprocess.run(
                    ['sudo', 'apt-get', 'install', '-y', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            elif install_type == 'gem':
                result = subprocess.run(
                    ['sudo', 'gem', 'install', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            elif install_type == 'pip':
                result = subprocess.run(
                    ['pip3', 'install', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
            else:
                return False
            
            if result.returncode == 0:
                if not silent:
                    print(f"   ✅ {tool_name} installed successfully!")
                return True
            else:
                if not silent:
                    print(f"   ❌ Failed to install {tool_name}")
                return False
                
        except subprocess.TimeoutExpired:
            if not silent:
                print(f"   ⚠️  Installation timed out for {tool_name}")
            return False
        except Exception as e:
            if not silent:
                print(f"   ❌ Error installing {tool_name}: {e}")
            return False
    
    @staticmethod
    def check_and_install_tools(tool_list, auto_install=True):
        """Check a list of tools and optionally install missing ones"""
        missing = []
        installed = []
        
        for tool in tool_list:
            if ToolManager.check_tool(tool):
                installed.append(tool)
            else:
                missing.append(tool)
        
        if missing and auto_install:
            print(f"\n🔧 {Colors.YELLOW}Missing tools detected:{Colors.RESET}")
            for tool in missing:
                print(f"   ❌ {tool}")
            
            response = input(f"\n{Colors.CYAN}Install missing tools automatically? (Y/n): {Colors.RESET}").strip().lower()
            
            if response != 'n':
                print(f"\n📦 Installing missing tools...")
                for tool in missing:
                    if ToolManager.install_tool(tool):
                        installed.append(tool)
        
        return installed, missing


class CTFHunterPro:
    """Enhanced CTFHunter with custom flag format and auto-install"""
    
    def __init__(self):
        self.config = self.load_config()
        self.custom_flag_patterns = []
        self.challenge_description = ""
        self.output_dir = self.config.get('output_directory', 'output')
        os.makedirs(self.output_dir, exist_ok=True)
        
    def load_config(self):
        """Load configuration"""
        config_files = ['config.json', 'config.example.json']
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        return json.load(f)
                except:
                    pass
        
        return self.get_default_config()
    
    def get_default_config(self):
        """Default configuration"""
        return {
            'output_directory': 'output',
            'auto_install_tools': True,
            'flag_patterns': [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}'
            ]
        }
    
    def print_banner(self):
        """Print awesome banner"""
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  {Colors.MAGENTA}██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ {Colors.CYAN}║
║  {Colors.MAGENTA}██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{Colors.CYAN}║
║  {Colors.MAGENTA}██║        ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{Colors.CYAN}║
║  {Colors.MAGENTA}██║        ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{Colors.CYAN}║
║  {Colors.MAGENTA}╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{Colors.CYAN}║
║  {Colors.MAGENTA} ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.CYAN}║
║                                                                               ║
║  {Colors.GREEN}🤖 World's First AI-Powered CTF Assistant{Colors.CYAN}                                 ║
║  {Colors.YELLOW}📌 Version 2.2.0 | By Prudhvi{Colors.CYAN}                                             ║
║  {Colors.WHITE}🔧 Auto-Install | Custom Flags | 25+ Tools | AI Analysis{Colors.CYAN}                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    def ask_flag_format(self):
        """Ask user for custom flag format"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🚩 FLAG FORMAT SETUP{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        print(f"\n{Colors.WHITE}Common flag formats:{Colors.RESET}")
        print(f"  • flag{{...}}           - Generic CTF")
        print(f"  • digitalcyberhunt{{...}} - Digital Cyberhunt")
        print(f"  • HTB{{...}}            - HackTheBox")
        print(f"  • THM{{...}}            - TryHackMe")
        print(f"  • picoCTF{{...}}        - PicoCTF")
        
        print(f"\n{Colors.YELLOW}Enter your CTF's flag format (e.g., siva{{}}, flag{{}}, DCH{{}}):{Colors.RESET}")
        flag_format = input(f"{Colors.GREEN}>>> {Colors.RESET}").strip()
        
        if flag_format:
            # Convert user input to regex pattern
            # e.g., "siva{}" -> r'siva\{[^}]+\}'
            if '{}' in flag_format:
                prefix = flag_format.replace('{}', '')
                pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
            elif '{' in flag_format:
                prefix = flag_format.split('{')[0]
                pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
            else:
                # Just use as prefix
                pattern = rf'{re.escape(flag_format)}\{{[^}}]+\}}'
            
            self.custom_flag_patterns.append(pattern)
            print(f"\n{Colors.GREEN}✅ Added flag pattern: {Colors.CYAN}{flag_format}{Colors.RESET}")
            print(f"   {Colors.WHITE}Regex: {pattern}{Colors.RESET}")
            
            # Ask for more
            more = input(f"\n{Colors.YELLOW}Add another flag format? (y/N): {Colors.RESET}").strip().lower()
            if more == 'y':
                self.ask_flag_format()
        else:
            print(f"\n{Colors.YELLOW}ℹ️  Using default flag patterns{Colors.RESET}")
    
    def get_all_flag_patterns(self):
        """Get all flag patterns (custom + default)"""
        patterns = self.custom_flag_patterns.copy()
        patterns.extend(self.config.get('flag_patterns', []))
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique
    
    def check_required_tools(self, file_type):
        """Check and install tools based on file type"""
        # Define required tools per file type
        tools_by_type = {
            'image': ['exiftool', 'binwalk', 'strings', 'zsteg', 'steghide', 'file', 'zbarimg'],
            'audio': ['exiftool', 'sox', 'ffmpeg', 'strings', 'binwalk'],
            'archive': ['binwalk', 'file', '7z', 'unzip', 'strings'],
            'pcap': ['tshark', 'strings', 'file'],
            'pdf': ['pdfinfo', 'pdftotext', 'exiftool', 'strings', 'binwalk'],
            'binary': ['checksec', 'strings', 'file', 'gdb', 'ltrace'],
            'text': ['file', 'strings'],
            'default': ['file', 'strings', 'exiftool', 'binwalk']
        }
        
        required_tools = tools_by_type.get(file_type, tools_by_type['default'])
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🔧 CHECKING REQUIRED TOOLS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        missing_tools = []
        for tool in required_tools:
            if ToolManager.check_tool(tool):
                print(f"   {Colors.GREEN}✅ {tool}{Colors.RESET}")
            else:
                print(f"   {Colors.RED}❌ {tool} - NOT FOUND{Colors.RESET}")
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"\n{Colors.YELLOW}⚠️  {len(missing_tools)} tool(s) missing!{Colors.RESET}")
            
            auto_install = input(f"\n{Colors.CYAN}Install missing tools automatically? (Y/n): {Colors.RESET}").strip().lower()
            
            if auto_install != 'n':
                print(f"\n{Colors.BLUE}📦 Installing missing tools...{Colors.RESET}")
                for tool in missing_tools:
                    ToolManager.install_tool(tool)
        else:
            print(f"\n{Colors.GREEN}✅ All required tools are available!{Colors.RESET}")
    
    def detect_file_type(self, filepath):
        """Detect file type"""
        ext = Path(filepath).suffix.lower()
        
        type_map = {
            '.png': 'image', '.jpg': 'image', '.jpeg': 'image', 
            '.gif': 'image', '.bmp': 'image', '.webp': 'image',
            '.wav': 'audio', '.mp3': 'audio', '.flac': 'audio', '.ogg': 'audio',
            '.zip': 'archive', '.tar': 'archive', '.gz': 'archive', 
            '.rar': 'archive', '.7z': 'archive',
            '.pcap': 'pcap', '.pcapng': 'pcap',
            '.pdf': 'pdf',
            '.elf': 'binary', '.bin': 'binary', '.exe': 'binary',
            '.txt': 'text', '.enc': 'text', '.cipher': 'text'
        }
        
        return type_map.get(ext, 'default')
    
    def search_flags(self, text):
        """Search for flags in text using all patterns"""
        flags = []
        patterns = self.get_all_flag_patterns()
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                flags.extend(matches)
            except:
                pass
        
        return list(set(flags))  # Remove duplicates
    
    def analyze_file(self, filepath):
        """Main analysis function"""
        if not os.path.exists(filepath):
            print(f"{Colors.RED}❌ File not found: {filepath}{Colors.RESET}")
            return None
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🔍 ANALYZING: {Colors.YELLOW}{filepath}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        if self.challenge_description:
            print(f"\n{Colors.WHITE}📝 Description: {self.challenge_description}{Colors.RESET}")
        
        file_type = self.detect_file_type(filepath)
        print(f"{Colors.WHITE}📁 Detected type: {Colors.GREEN}{file_type}{Colors.RESET}")
        
        # Check and install required tools
        self.check_required_tools(file_type)
        
        results = {
            'target': filepath,
            'file_type': file_type,
            'description': self.challenge_description,
            'flags': [],
            'findings': [],
            'methods_executed': [],
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🚀 RUNNING ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        # Run appropriate scanners based on file type
        try:
            if file_type == 'image':
                results = self._analyze_image(filepath, results)
            elif file_type == 'audio':
                results = self._analyze_audio(filepath, results)
            elif file_type == 'archive':
                results = self._analyze_archive(filepath, results)
            elif file_type == 'pcap':
                results = self._analyze_pcap(filepath, results)
            elif file_type == 'pdf':
                results = self._analyze_pdf(filepath, results)
            elif file_type == 'text':
                results = self._analyze_text(filepath, results)
            else:
                results = self._analyze_generic(filepath, results)
        except Exception as e:
            print(f"{Colors.RED}❌ Analysis error: {e}{Colors.RESET}")
        
        # Display results
        self._display_results(results)
        
        # Generate reports
        self._generate_reports(results)
        
        return results
    
    def _run_tool(self, tool, args, results, description=""):
        """Run a tool and capture output"""
        if not ToolManager.check_tool(tool):
            print(f"   {Colors.YELLOW}⚠️  {tool} not available, skipping...{Colors.RESET}")
            return ""
        
        print(f"   {Colors.BLUE}▶ Running {tool}...{Colors.RESET}", end=" ")
        
        try:
            result = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=120
            )
            output = result.stdout + result.stderr
            
            # Search for flags
            flags = self.search_flags(output)
            if flags:
                print(f"{Colors.GREEN}🚩 FLAG FOUND!{Colors.RESET}")
                results['flags'].extend(flags)
            else:
                print(f"{Colors.GREEN}✓{Colors.RESET}")
            
            results['methods_executed'].append({
                'name': f"{tool} {' '.join(args[:2])}",
                'success': True
            })
            
            return output
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}⏱️  Timeout{Colors.RESET}")
            return ""
        except Exception as e:
            print(f"{Colors.RED}❌ Error{Colors.RESET}")
            return ""
    
    def _analyze_image(self, filepath, results):
        """Analyze image files"""
        # EXIF
        output = self._run_tool('exiftool', [filepath], results)
        if output:
            results['findings'].append(f"EXIF metadata extracted")
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        # Binwalk
        self._run_tool('binwalk', [filepath], results)
        
        # zsteg (for PNG)
        if filepath.lower().endswith('.png'):
            output = self._run_tool('zsteg', [filepath], results)
            if output:
                flags = self.search_flags(output)
                results['flags'].extend(flags)
        
        # QR Code check
        output = self._run_tool('zbarimg', ['--raw', '-q', filepath], results)
        if output.strip():
            results['findings'].append(f"QR Code content: {output.strip()}")
            flags = self.search_flags(output)
            results['flags'].extend(flags)
        
        # OSINT scan
        try:
            osint = OSINTScanner()
            osint_results = osint.scan(filepath)
            if osint_results.get('coordinates'):
                results['findings'].append(f"GPS: {osint_results['coordinates']}")
            if osint_results.get('findings'):
                results['findings'].extend(osint_results['findings'])
        except:
            pass
        
        return results
    
    def _analyze_audio(self, filepath, results):
        """Analyze audio files"""
        # EXIF
        self._run_tool('exiftool', [filepath], results)
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        # Spectrogram
        spec_output = os.path.join(self.output_dir, 'spectrogram.png')
        self._run_tool('sox', [filepath, '-n', 'spectrogram', '-o', spec_output], results)
        if os.path.exists(spec_output):
            results['findings'].append(f"Spectrogram saved: {spec_output}")
        
        # Binwalk
        self._run_tool('binwalk', [filepath], results)
        
        return results
    
    def _analyze_archive(self, filepath, results):
        """Analyze archive files"""
        # Binwalk extract
        self._run_tool('binwalk', ['-e', filepath], results)
        
        # File info
        self._run_tool('file', [filepath], results)
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        return results
    
    def _analyze_pcap(self, filepath, results):
        """Analyze PCAP files"""
        # Tshark HTTP
        output = self._run_tool('tshark', ['-r', filepath, '-Y', 'http', '-T', 'fields', '-e', 'http.request.uri'], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        return results
    
    def _analyze_pdf(self, filepath, results):
        """Analyze PDF files"""
        # PDF info
        self._run_tool('pdfinfo', [filepath], results)
        
        # PDF text
        output = self._run_tool('pdftotext', [filepath, '-'], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        # EXIF
        self._run_tool('exiftool', [filepath], results)
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        return results
    
    def _analyze_text(self, filepath, results):
        """Analyze text/crypto files"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Direct flag search
            flags = self.search_flags(content)
            results['flags'].extend(flags)
            
            # Try crypto analysis
            crypto_results = analyze_crypto(content)
            if crypto_results.get('decoded_results'):
                for decoded in crypto_results['decoded_results']:
                    results['findings'].append(f"{decoded['method']}: {decoded['result'][:100]}")
                    flags = self.search_flags(decoded['result'])
                    results['flags'].extend(flags)
        except:
            pass
        
        return results
    
    def _analyze_generic(self, filepath, results):
        """Generic file analysis"""
        # File type
        self._run_tool('file', [filepath], results)
        
        # Strings
        output = self._run_tool('strings', ['-n', '8', filepath], results)
        flags = self.search_flags(output)
        results['flags'].extend(flags)
        
        # EXIF
        self._run_tool('exiftool', [filepath], results)
        
        # Binwalk
        self._run_tool('binwalk', [filepath], results)
        
        return results
    
    def _display_results(self, results):
        """Display analysis results"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 ANALYSIS RESULTS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        # Remove duplicate flags
        results['flags'] = list(set(results['flags']))
        
        if results['flags']:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🚩 FLAGS FOUND ({len(results['flags'])}):{Colors.RESET}")
            for flag in results['flags']:
                print(f"\n   {Colors.GREEN}╔{'═'*50}╗{Colors.RESET}")
                print(f"   {Colors.GREEN}║{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{flag}{Colors.RESET}")
                print(f"   {Colors.GREEN}╚{'═'*50}╝{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}❌ No flags found yet.{Colors.RESET}")
            print(f"{Colors.WHITE}   Try different tools or check the output directory.{Colors.RESET}")
        
        if results['findings']:
            print(f"\n{Colors.BLUE}🔍 FINDINGS:{Colors.RESET}")
            for finding in results['findings'][:10]:
                print(f"   • {finding}")
        
        print(f"\n{Colors.WHITE}📁 Methods executed: {len(results['methods_executed'])}{Colors.RESET}")
    
    def _generate_reports(self, results):
        """Generate TXT, JSON, and HTML reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(results['target']).stem
        
        # JSON report
        json_path = os.path.join(self.output_dir, f'{base_name}_{timestamp}_report.json')
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # HTML report
        try:
            html_reporter = HTMLReporter({'output_directory': self.output_dir})
            html_path = html_reporter.generate(results, results['target'])
            print(f"\n{Colors.GREEN}📄 Reports saved:{Colors.RESET}")
            print(f"   • {json_path}")
            print(f"   • {html_path}")
        except:
            print(f"\n{Colors.GREEN}📄 Report saved: {json_path}{Colors.RESET}")
    
    def interactive_mode(self):
        """Interactive mode"""
        self.print_banner()
        self.ask_flag_format()
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🎮 INTERACTIVE MODE{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"\n{Colors.WHITE}Commands:{Colors.RESET}")
        print(f"  • {Colors.GREEN}solve <filepath>{Colors.RESET} - Analyze a file")
        print(f"  • {Colors.GREEN}flag <format>{Colors.RESET}   - Add custom flag format")
        print(f"  • {Colors.GREEN}help{Colors.RESET}            - Show help")
        print(f"  • {Colors.GREEN}exit{Colors.RESET}            - Exit")
        
        while True:
            try:
                cmd = input(f"\n{Colors.CYAN}🤖 CTFHunter> {Colors.RESET}").strip()
                
                if not cmd:
                    continue
                elif cmd.lower() == 'exit':
                    print(f"\n{Colors.GREEN}👋 Goodbye! Good luck with your CTF!{Colors.RESET}")
                    break
                elif cmd.lower() == 'help':
                    self._show_help()
                elif cmd.lower().startswith('flag '):
                    flag_format = cmd[5:].strip()
                    if flag_format:
                        prefix = flag_format.replace('{}', '').replace('{', '')
                        pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
                        self.custom_flag_patterns.append(pattern)
                        print(f"{Colors.GREEN}✅ Added flag pattern: {flag_format}{Colors.RESET}")
                elif cmd.lower().startswith('solve '):
                    filepath = cmd[6:].strip()
                    self.analyze_file(filepath)
                else:
                    # Try to treat as filepath
                    if os.path.exists(cmd):
                        self.analyze_file(cmd)
                    else:
                        print(f"{Colors.YELLOW}Unknown command. Type 'help' for usage.{Colors.RESET}")
                        
            except KeyboardInterrupt:
                print(f"\n{Colors.GREEN}👋 Goodbye!{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.RESET}")
    
    def _show_help(self):
        """Show help"""
        print(f"""
{Colors.CYAN}CTFHunter Pro - Help{Colors.RESET}
{'='*40}

{Colors.GREEN}Commands:{Colors.RESET}
  solve <file>      Analyze a challenge file
  flag <format>     Add custom flag format (e.g., flag siva{{}})
  help              Show this help
  exit              Exit interactive mode

{Colors.GREEN}Examples:{Colors.RESET}
  solve /home/user/challenge.png
  solve challenge.zip
  flag siva{{}}
  flag digitalcyberhunt{{}}

{Colors.GREEN}CLI Usage:{Colors.RESET}
  python ctfhunter_pro.py solve <file> -d "description" -f "flag{{}}"
  python ctfhunter_pro.py interactive
""")


def main():
    parser = argparse.ArgumentParser(
        description='CTFHunter Pro - World\'s First AI-Powered CTF Assistant',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Solve command
    solve_parser = subparsers.add_parser('solve', help='Analyze a challenge file')
    solve_parser.add_argument('filepath', help='Path to the challenge file')
    solve_parser.add_argument('-d', '--description', help='Challenge description', default='')
    solve_parser.add_argument('-f', '--flag-format', help='Flag format (e.g., siva{}, flag{})', action='append', default=[])
    
    # Interactive command
    subparsers.add_parser('interactive', help='Start interactive mode')
    
    args = parser.parse_args()
    
    hunter = CTFHunterPro()
    
    if args.command == 'solve':
        hunter.print_banner()
        
        # Add custom flag formats from CLI
        for fmt in args.flag_format:
            prefix = fmt.replace('{}', '').replace('{', '')
            pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
            hunter.custom_flag_patterns.append(pattern)
            print(f"{Colors.GREEN}✅ Flag format: {fmt}{Colors.RESET}")
        
        # If no flag format provided, ask for it
        if not args.flag_format:
            hunter.ask_flag_format()
        
        hunter.challenge_description = args.description
        hunter.analyze_file(args.filepath)
        
    elif args.command == 'interactive':
        hunter.interactive_mode()
    else:
        hunter.print_banner()
        hunter.interactive_mode()


if __name__ == '__main__':
    main()
