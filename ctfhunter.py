#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTFHunter Ultimate - Professional CTF Automation Tool
Author: Prudhvi (CTF Community)
Version: 2.1.0

A comprehensive tool for automated CTF challenge analysis including:
- File scanning and type detection
- Steganography analysis
- Archive extraction
- Network packet analysis
- Binary reverse engineering basics
- PDF forensics
- Web reconnaissance
- AI-powered hints (optional)
"""

import sys
import os

# Fix Windows UTF-8 encoding - comprehensive approach
if sys.platform.startswith('win'):
    # Set environment variable for Python encoding
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable VT mode for ANSI colors
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        # Set console output codepage to UTF-8
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except:
        pass
    
    # Reconfigure stdout/stderr with UTF-8
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import argparse
import json
from pathlib import Path

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.file_scan import FileScanner
from modules.stego_scan import StegoScanner
from modules.zip_scan import ArchiveScanner
from modules.pcap_scan import PCAPScanner
from modules.elf_scan import ELFScanner
from modules.pdf_scan import PDFScanner
from modules.web_scan import WebScanner
from modules.ai_helper import AIHelper
from modules.reporter import Reporter

# New Enhanced Modules
try:
    from modules.memory_forensics import MemoryForensics
    MEMORY_FORENSICS_AVAILABLE = True
except ImportError:
    MEMORY_FORENSICS_AVAILABLE = False

try:
    from modules.video_stego import VideoSteganography
    VIDEO_STEGO_AVAILABLE = True
except ImportError:
    VIDEO_STEGO_AVAILABLE = False

try:
    from modules.log_analyzer import LogAnalyzer
    LOG_ANALYZER_AVAILABLE = True
except ImportError:
    LOG_ANALYZER_AVAILABLE = False

try:
    from modules.malware_analyzer import MalwareAnalyzer
    MALWARE_ANALYZER_AVAILABLE = True
except ImportError:
    MALWARE_ANALYZER_AVAILABLE = False

try:
    from modules.advanced_ciphers import AdvancedCiphers
    ADVANCED_CIPHERS_AVAILABLE = True
except ImportError:
    ADVANCED_CIPHERS_AVAILABLE = False

# Deep Analysis Modules (In-Depth Analysis)
try:
    from modules.deep_analyzer import DeepAnalyzer
    DEEP_ANALYZER_AVAILABLE = True
except ImportError:
    DEEP_ANALYZER_AVAILABLE = False

try:
    from modules.deep_stego import DeepStegoAnalyzer
    DEEP_STEGO_AVAILABLE = True
except ImportError:
    DEEP_STEGO_AVAILABLE = False

try:
    from modules.deep_crypto import DeepCryptoAnalyzer
    DEEP_CRYPTO_AVAILABLE = True
except ImportError:
    DEEP_CRYPTO_AVAILABLE = False

try:
    from modules.deep_forensics import DeepForensicsAnalyzer
    DEEP_FORENSICS_AVAILABLE = True
except ImportError:
    DEEP_FORENSICS_AVAILABLE = False

try:
    from modules.deep_network import DeepNetworkAnalyzer
    DEEP_NETWORK_AVAILABLE = True
except ImportError:
    DEEP_NETWORK_AVAILABLE = False

from modules.colors import (
    Colors, Emoji, colorize, success, error, warning, info,
    header, highlight, code, path as color_path, flag_text,
    separator, print_success, print_error, print_warning,
    print_info, print_header, print_separator
)


class CTFHunter:
    def __init__(self, config_file='config.json'):
        """Initialize CTFHunter with configuration"""
        
        # Load configuration
        self.config = self.load_config(config_file)
        
        # Initialize modules
        self.file_scanner = FileScanner(self.config)
        self.stego_scanner = StegoScanner(self.config)
        self.archive_scanner = ArchiveScanner(self.config)
        self.pcap_scanner = PCAPScanner(self.config)
        self.elf_scanner = ELFScanner(self.config)
        self.pdf_scanner = PDFScanner(self.config)
        self.web_scanner = WebScanner(self.config)
        self.ai_helper = AIHelper(self.config)
        self.reporter = Reporter(self.config)
        
        # Initialize new enhanced modules
        if MEMORY_FORENSICS_AVAILABLE:
            self.memory_forensics = MemoryForensics(self.config)
        if VIDEO_STEGO_AVAILABLE:
            self.video_stego = VideoSteganography(self.config)
        if LOG_ANALYZER_AVAILABLE:
            self.log_analyzer = LogAnalyzer(self.config)
        if MALWARE_ANALYZER_AVAILABLE:
            self.malware_analyzer = MalwareAnalyzer(self.config)
        if ADVANCED_CIPHERS_AVAILABLE:
            self.advanced_ciphers = AdvancedCiphers(self.config)
        
        # Initialize Deep Analysis Modules (In-Depth Analysis)
        if DEEP_ANALYZER_AVAILABLE:
            self.deep_analyzer = DeepAnalyzer(self.config)
        if DEEP_STEGO_AVAILABLE:
            self.deep_stego = DeepStegoAnalyzer(self.config)
        if DEEP_CRYPTO_AVAILABLE:
            self.deep_crypto = DeepCryptoAnalyzer(self.config)
        if DEEP_FORENSICS_AVAILABLE:
            self.deep_forensics = DeepForensicsAnalyzer(self.config)
        if DEEP_NETWORK_AVAILABLE:
            self.deep_network = DeepNetworkAnalyzer(self.config)
        
        # Create output directory
        output_dir = self.config.get('output_directory', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            # Try to load from script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(script_dir, config_file)
            
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                print(f"⚠️  Config file not found: {config_path}")
                print("[*] Using default configuration")
                return self.get_default_config()
                
        except Exception as e:
            print_warning(f"Error loading config: {str(e)}", emoji=True)
            print_info("Using default configuration", emoji=False)
            return self.get_default_config()
    
    def get_default_config(self):
        """Get default configuration"""
        return {
            'output_directory': 'output',
            'verbose': True,
            'auto_extract': True,
            'recursive_scan': True,
            'max_recursion_depth': 5,
            'flag_patterns': [
                r'digitalcyberhunt\{[^}]+\}',
                r'DCH\{[^}]+\}',
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'picoCTF\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'THM\{[^}]+\}',
                r'OSCTF\{[^}]+\}',
                r'cyberhunt\{[^}]+\}'
            ]
        }
    
    def detect_input_type(self, target):
        """Detect if target is URL or file"""
        if target.startswith('http://') or target.startswith('https://'):
            return 'url'
        else:
            return 'file'
    
    def detect_challenge_type(self, filepath):
        """Detect challenge type based on file"""
        
        if not os.path.exists(filepath):
            return 'unknown'
        
        # Get file extension
        ext = Path(filepath).suffix.lower()
        
        # Archive types
        if ext in ['.zip', '.tar', '.gz', '.tgz', '.bz2', '.rar', '.7z', '.xz']:
            return 'archive'
        
        # Image types (steganography)
        if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
            return 'image'
        
        # Video types (steganography)
        if ext in ['.mp4', '.avi', '.mkv', '.mov', '.webm', '.flv']:
            return 'video'
        
        # Memory dump types
        if ext in ['.raw', '.mem', '.vmem', '.dmp', '.lime']:
            return 'memory'
        
        # Log files
        if ext in ['.log'] or 'log' in Path(filepath).stem.lower():
            return 'log'
        
        # PCAP types
        if ext in ['.pcap', '.pcapng', '.cap']:
            return 'pcap'
        
        # PDF types
        if ext == '.pdf':
            return 'pdf'
        
        # Try to detect binary/ELF
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                
                # ELF magic bytes
                if magic[:4] == b'\x7fELF':
                    return 'elf'
                
                # PE magic bytes
                if magic[:2] == b'MZ':
                    return 'exe'
                    
        except:
            pass
        
        return 'generic'
    
    def scan_file(self, filepath):
        """Scan a file based on its type"""
        
        print()
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        print(colorize(f"{Emoji.SEARCH} CTFHunter Ultimate - Starting Analysis", Colors.BRIGHT_YELLOW, bold=True).center(90))
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        
        # Detect challenge type
        challenge_type = self.detect_challenge_type(filepath)
        
        print()
        print(colorize(f"{Emoji.TARGET} Challenge Type Detected: ", Colors.BRIGHT_CYAN, bold=True) + 
              highlight(challenge_type.upper()))
        
        # Perform generic file scan first
        print()
        print_info("Performing generic file scan...", emoji=False)
        scan_results = self.file_scanner.scan(filepath)
        
        # DEEP ANALYSIS - Run comprehensive in-depth analysis
        print()
        print(colorize(f"{Emoji.SEARCH} Running IN-DEPTH analysis (byte-level, multi-layer)...", Colors.BRIGHT_MAGENTA, bold=True))
        
        if DEEP_ANALYZER_AVAILABLE:
            try:
                deep_results = self.deep_analyzer.analyze(filepath)
                scan_results['deep_analysis'] = deep_results
                
                # If flags found in deep analysis, add them
                if deep_results.get('flags_found'):
                    if 'flags' not in scan_results:
                        scan_results['flags'] = []
                    scan_results['flags'].extend(deep_results['flags_found'])
            except Exception as e:
                print_warning(f"Deep analysis error: {str(e)}", emoji=True)
        
        if DEEP_FORENSICS_AVAILABLE:
            try:
                forensics_results = self.deep_forensics.analyze(filepath)
                scan_results['deep_forensics'] = forensics_results
                
                if forensics_results.get('flags_found'):
                    if 'flags' not in scan_results:
                        scan_results['flags'] = []
                    scan_results['flags'].extend(forensics_results['flags_found'])
            except Exception as e:
                print_warning(f"Deep forensics error: {str(e)}", emoji=True)
        
        # Perform specialized scans based on type
        if challenge_type == 'image':
            print()
            print(colorize(f"{Emoji.IMAGE} Detected image file - running steganography analysis...", Colors.BRIGHT_MAGENTA, bold=True))
            stego_results = self.stego_scanner.scan(filepath)
            scan_results.update(stego_results)
            
            # DEEP STEGO ANALYSIS
            if DEEP_STEGO_AVAILABLE:
                print()
                print(colorize(f"{Emoji.SEARCH} Running IN-DEPTH steganography analysis...", Colors.BRIGHT_CYAN, bold=True))
                try:
                    deep_stego_results = self.deep_stego.analyze(filepath)
                    scan_results['deep_stego'] = deep_stego_results
                    
                    if deep_stego_results.get('flags_found'):
                        if 'flags' not in scan_results:
                            scan_results['flags'] = []
                        scan_results['flags'].extend(deep_stego_results['flags_found'])
                except Exception as e:
                    print_warning(f"Deep stego error: {str(e)}", emoji=True)
            
        elif challenge_type == 'archive':
            print()
            print(colorize(f"{Emoji.ARCHIVE} Detected archive - running extraction and recursive scan...", Colors.BRIGHT_YELLOW, bold=True))
            archive_results = self.archive_scanner.scan(filepath)
            scan_results.update(archive_results)
            
        elif challenge_type == 'pcap':
            print()
            print(colorize(f"{Emoji.WIFI} Detected PCAP file - running network analysis...", Colors.BRIGHT_BLUE, bold=True))
            pcap_results = self.pcap_scanner.scan(filepath)
            scan_results.update(pcap_results)
            
            # DEEP NETWORK ANALYSIS
            if DEEP_NETWORK_AVAILABLE:
                print()
                print(colorize(f"{Emoji.SEARCH} Running IN-DEPTH network analysis...", Colors.BRIGHT_CYAN, bold=True))
                try:
                    output_dir = self.config.get('output_directory', 'output')
                    deep_network_results = self.deep_network.analyze(filepath, output_dir)
                    scan_results['deep_network'] = deep_network_results
                    
                    if deep_network_results.get('flags_found'):
                        if 'flags' not in scan_results:
                            scan_results['flags'] = []
                        scan_results['flags'].extend(deep_network_results['flags_found'])
                except Exception as e:
                    print_warning(f"Deep network error: {str(e)}", emoji=True)
            
        elif challenge_type == 'elf':
            print()
            print(colorize(f"{Emoji.CODE} Detected ELF binary - running reverse engineering reconnaissance...", Colors.BRIGHT_GREEN, bold=True))
            elf_results = self.elf_scanner.scan(filepath)
            scan_results.update(elf_results)
            
        elif challenge_type == 'pdf':
            print()
            print(colorize(f"{Emoji.DOCUMENT} Detected PDF - running forensics analysis...", Colors.BRIGHT_RED, bold=True))
            pdf_results = self.pdf_scanner.scan(filepath)
            scan_results.update(pdf_results)
        
        elif challenge_type == 'video':
            print()
            print(colorize(f"{Emoji.VIDEO} Detected video file - running video steganography analysis...", Colors.BRIGHT_MAGENTA, bold=True))
            if VIDEO_STEGO_AVAILABLE:
                video_results = self.video_stego.analyze(filepath)
                scan_results['video_analysis'] = video_results
            else:
                print_warning("Video steganography module not available", emoji=True)
        
        elif challenge_type == 'memory':
            print()
            print(colorize(f"{Emoji.MEMORY} Detected memory dump - running memory forensics...", Colors.BRIGHT_CYAN, bold=True))
            if MEMORY_FORENSICS_AVAILABLE:
                memory_results = self.memory_forensics.analyze(filepath)
                scan_results['memory_analysis'] = memory_results
            else:
                print_warning("Memory forensics module not available", emoji=True)
        
        elif challenge_type == 'log':
            print()
            print(colorize(f"{Emoji.LOG} Detected log file - running log analysis...", Colors.BRIGHT_YELLOW, bold=True))
            if LOG_ANALYZER_AVAILABLE:
                log_results = self.log_analyzer.analyze(filepath)
                scan_results['log_analysis'] = log_results
            else:
                print_warning("Log analyzer module not available", emoji=True)
        
        elif challenge_type == 'exe':
            print()
            print(colorize(f"{Emoji.MALWARE} Detected executable - running malware analysis...", Colors.BRIGHT_RED, bold=True))
            if MALWARE_ANALYZER_AVAILABLE:
                malware_results = self.malware_analyzer.analyze(filepath)
                scan_results['malware_analysis'] = malware_results
            else:
                print_warning("Malware analyzer module not available", emoji=True)
        
        # Try crypto analysis on any extracted text/strings
        if DEEP_CRYPTO_AVAILABLE:
            print()
            print(colorize(f"{Emoji.KEY} Running IN-DEPTH cryptographic analysis on extracted strings...", Colors.BRIGHT_YELLOW, bold=True))
            try:
                # Check if any base64 or encoded strings were found
                strings_to_analyze = []
                
                # Get base64 candidates from deep analysis
                if scan_results.get('deep_analysis', {}).get('encoded_strings'):
                    strings_to_analyze.extend(scan_results['deep_analysis']['encoded_strings'])
                
                # Get strings from file scan
                if scan_results.get('strings'):
                    for s in scan_results.get('strings', [])[:50]:  # Limit to 50
                        if len(s) > 10:
                            strings_to_analyze.append(s)
                
                # Analyze suspicious strings
                crypto_results = []
                for text in strings_to_analyze[:20]:  # Analyze top 20
                    if isinstance(text, str) and len(text) > 5:
                        result = self.deep_crypto.analyze(text)
                        if result.get('flags_found') or result.get('successful_decryptions'):
                            crypto_results.append(result)
                            
                            if result.get('flags_found'):
                                if 'flags' not in scan_results:
                                    scan_results['flags'] = []
                                scan_results['flags'].extend(result['flags_found'])
                
                scan_results['deep_crypto'] = crypto_results
            except Exception as e:
                print_warning(f"Deep crypto error: {str(e)}", emoji=True)
        
        # Deduplicate flags
        if 'flags' in scan_results:
            scan_results['flags'] = list(set(scan_results['flags']))
        
        return scan_results
    
    def scan_url(self, url):
        """Scan a URL"""
        
        print()
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        print(colorize(f"{Emoji.GLOBE} CTFHunter Ultimate - Web Challenge Analysis", Colors.BRIGHT_YELLOW, bold=True).center(90))
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        
        # Perform web scan
        scan_results = self.web_scanner.scan(url)
        
        return scan_results
    
    def display_summary(self, scan_results):
        """Display scan summary"""
        
        print()
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        print(colorize(f"{Emoji.CHART} SCAN SUMMARY", Colors.BRIGHT_YELLOW, bold=True).center(90))
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
        
        # Collect all flags
        flags = self.reporter._collect_all_flags(scan_results)
        
        if flags:
            print()
            print(colorize(f"{Emoji.TROPHY} SUCCESS! Found {len(flags)} flag(s):", Colors.BRIGHT_GREEN, bold=True))
            for i, flag in enumerate(flags, 1):
                print(f"\n  {i}. {flag_text(flag)}")
        else:
            print()
            print_warning("No flags automatically discovered", emoji=True)
            print_info("Manual analysis may be required", emoji=False)
        
        print()
        print(colorize("═" * 80, Colors.BRIGHT_CYAN))
    
    def run(self, target, use_ai=False):
        """Main execution function"""
        
        # Detect input type
        input_type = self.detect_input_type(target)
        
        # Perform scan
        if input_type == 'url':
            scan_results = self.scan_url(target)
        else:
            # Validate file exists
            if not os.path.exists(target):
                print_error(f"File not found: {target}", emoji=True)
                return
            
            scan_results = self.scan_file(target)
        
        # Display summary
        self.display_summary(scan_results)
        
        # Generate report
        print()
        print_info("Generating comprehensive report...", emoji=False)
        self.reporter.generate_report(scan_results, target)
        
        # AI hint if requested
        if use_ai:
            if self.ai_helper.is_available():
                self.ai_helper.get_hint(scan_results)
            else:
                print()
                print_warning("AI helper not configured", emoji=True)
                print_info("Set 'openai_api_key' in config.json to enable AI hints", emoji=False)
        
        print()
        print_success("Analysis complete!", emoji=True)
        print_info(f"Check the '{self.config.get('output_directory', 'output')}' directory for detailed results", emoji=False)


def print_banner():
    """Print CTFHunter banner"""
    print()
    print(colorize("╔═══════════════════════════════════════════════════════════╗", Colors.BRIGHT_CYAN))
    print(colorize("║                                                           ║", Colors.BRIGHT_CYAN))
    print(colorize("║        ██████╗████████╗███████╗██╗  ██╗██╗   ██╗         ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║       ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║         ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║       ██║        ██║   █████╗  ███████║██║   ██║         ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║       ██║        ██║   ██╔══╝  ██╔══██║██║   ██║         ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║       ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝         ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║        ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝          ║", Colors.BRIGHT_MAGENTA, bold=True))
    print(colorize("║                                                           ║", Colors.BRIGHT_CYAN))
    print(colorize("║              ULTIMATE CTF AUTOMATION TOOL                ║", Colors.BRIGHT_YELLOW, bold=True))
    print(colorize("║            Version 2.5 - IN-DEPTH ANALYSIS               ║", Colors.BRIGHT_GREEN, bold=True))
    print(colorize("║                                                           ║", Colors.BRIGHT_CYAN))
    print(colorize("╚═══════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
    print()
    print(colorize("Professional CTF Challenge Analysis & Flag Discovery Tool", Colors.BRIGHT_WHITE).center(70))
    print(colorize("DEEP ANALYSIS: Byte-level | Multi-layer | Comprehensive", Colors.BRIGHT_GREEN).center(70))
    print()


def main():
    """Main entry point"""
    
    # Print banner
    print_banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='CTFHunter Ultimate - Professional CTF Automation Tool',
        epilog='Examples:\n'
               '  ctfhunter file.png\n'
               '  ctfhunter challenge.zip\n'
               '  ctfhunter capture.pcap\n'
               '  ctfhunter binary.elf\n'
               '  ctfhunter document.pdf\n'
               '  ctfhunter https://target-site.com\n'
               '  ctfhunter --ai-hint file.png\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'target',
        help='Target file or URL to analyze'
    )
    
    parser.add_argument(
        '--ai-hint',
        action='store_true',
        help='Enable AI-powered hints (requires OpenAI API key in config)'
    )
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='CTFHunter Ultimate 2.5 - IN-DEPTH ANALYSIS'
    )
    
    args = parser.parse_args()
    
    # Initialize CTFHunter
    try:
        hunter = CTFHunter(config_file=args.config)
        
        # Run analysis
        hunter.run(args.target, use_ai=args.ai_hint)
        
    except KeyboardInterrupt:
        print()
        print_warning("Scan interrupted by user", emoji=True)
        sys.exit(1)
    except Exception as e:
        print()
        print_error(f"Fatal error: {str(e)}", emoji=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
