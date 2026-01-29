#!/usr/bin/env python3
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
                r'picoCTF\{[^}]+\}'
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
        
        # Perform specialized scans based on type
        if challenge_type == 'image':
            print()
            print(colorize(f"{Emoji.IMAGE} Detected image file - running steganography analysis...", Colors.BRIGHT_MAGENTA, bold=True))
            stego_results = self.stego_scanner.scan(filepath)
            scan_results.update(stego_results)
            
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
    print(colorize("║                     Version 1.0                          ║", Colors.BRIGHT_CYAN))
    print(colorize("║                                                           ║", Colors.BRIGHT_CYAN))
    print(colorize("╚═══════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
    print()
    print(colorize("Professional CTF Challenge Analysis & Flag Discovery Tool", Colors.BRIGHT_WHITE).center(70))
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
        version='CTFHunter Ultimate 1.0'
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
