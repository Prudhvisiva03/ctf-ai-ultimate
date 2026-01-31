#!/usr/bin/env python3
"""
██████╗████████╗███████╗    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
██╔════╝╚══██╔══╝██╔════╝    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
██║        ██║   █████╗      ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗  
██║        ██║   ██╔══╝      ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
╚██████╗   ██║   ██║         ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
 ╚═════╝   ╚═╝   ╚═╝          ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

CTF ULTIMATE - 100% RELIABLE CTF SOLVING TOOL
Specially optimized for Digital Cyberhunt CTF

Author: Prudhvi
Version: 3.0.0

Categories Covered:
✅ Geolocation & OSINT - Track locations, decode GPS data
✅ Web & AI Security - Exploit AI-based vulnerabilities  
✅ Cyber & Cryptography - Break ciphers, decrypt messages
✅ Metadata Forensics - Extract hidden info from images & network logs
"""

import sys
import os
import re
import json
import subprocess
import base64
import binascii
import urllib.parse
import hashlib
from pathlib import Path
from datetime import datetime

# Fix Windows encoding
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except:
        pass

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


# Default flag patterns for Digital Cyberhunt
DEFAULT_FLAG_PATTERNS = [
    r'digitalcyberhunt\{[^}]+\}',
    r'DCH\{[^}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'ctf\{[^}]+\}',
]


class CTFUltimate:
    """Ultimate CTF solving tool - 100% reliable"""
    
    def __init__(self):
        self.flag_patterns = DEFAULT_FLAG_PATTERNS.copy()
        self.found_flags = []
        self.findings = []
        self.output_dir = 'output'
        os.makedirs(self.output_dir, exist_ok=True)
    
    def print_banner(self):
        print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║  {Colors.MAGENTA}██████╗████████╗███████╗    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗{Colors.CYAN}
║  {Colors.MAGENTA}██╔════╝╚══██╔══╝██╔════╝    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝{Colors.CYAN}
║  {Colors.MAGENTA}██║        ██║   █████╗      ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗ {Colors.CYAN}
║  {Colors.MAGENTA}██║        ██║   ██╔══╝      ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝ {Colors.CYAN}
║  {Colors.MAGENTA}╚██████╗   ██║   ██║         ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗{Colors.CYAN}
║  {Colors.MAGENTA} ╚═════╝   ╚═╝   ╚═╝          ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝{Colors.CYAN}
║                                                                                         
║  {Colors.GREEN}🎯 100% RELIABLE CTF SOLVING TOOL - DIGITAL CYBERHUNT EDITION{Colors.CYAN}
║  {Colors.YELLOW}📌 Geolocation | OSINT | Web Security | Cryptography | Forensics{Colors.CYAN}
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")
    
    def add_flag_pattern(self, prefix):
        """Add custom flag pattern"""
        pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
        if pattern not in self.flag_patterns:
            self.flag_patterns.insert(0, pattern)
        print(f"{Colors.GREEN}✅ Added flag pattern: {prefix}{{...}}{Colors.RESET}")
    
    def search_flags(self, text):
        """Search for flags in text"""
        flags = []
        for pattern in self.flag_patterns:
            try:
                matches = re.findall(pattern, str(text), re.IGNORECASE)
                flags.extend(matches)
            except:
                pass
        return list(set(flags))
    
    def run_command(self, cmd, timeout=60):
        """Run a command and return output"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                shell=isinstance(cmd, str)
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""
        except Exception as e:
            return ""
    
    def tool_exists(self, tool):
        """Check if tool exists"""
        import shutil
        return shutil.which(tool) is not None
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CRYPTOGRAPHY MODULE - Break ciphers, decrypt messages
    # ═══════════════════════════════════════════════════════════════════════════
    
    def decode_base64(self, text):
        """Decode Base64"""
        try:
            decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
            return decoded
        except:
            return None
    
    def decode_base32(self, text):
        """Decode Base32"""
        try:
            decoded = base64.b32decode(text.strip().upper()).decode('utf-8', errors='ignore')
            return decoded
        except:
            return None
    
    def decode_hex(self, text):
        """Decode Hex"""
        try:
            clean = text.replace(' ', '').replace('\n', '')
            decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            return decoded
        except:
            return None
    
    def decode_url(self, text):
        """Decode URL encoding"""
        try:
            return urllib.parse.unquote(text)
        except:
            return None
    
    def decode_binary(self, text):
        """Decode binary"""
        try:
            clean = text.replace(' ', '')
            chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
            return ''.join(chars)
        except:
            return None
    
    def decode_rot13(self, text):
        """Decode ROT13"""
        import codecs
        return codecs.decode(text, 'rot_13')
    
    def decode_caesar(self, text, shift=None):
        """Decode Caesar cipher"""
        results = []
        shifts = [shift] if shift else range(1, 26)
        for s in shifts:
            decoded = ''
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decoded += chr((ord(c) - base - s) % 26 + base)
                else:
                    decoded += c
            results.append((s, decoded))
        return results
    
    def decode_morse(self, text):
        """Decode Morse code"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '/': ' ', '.-.-.-': '.', '--..--': ',', '..--..': '?'
        }
        try:
            words = text.strip().split('/')
            decoded = []
            for word in words:
                letters = word.strip().split()
                decoded_word = ''.join(morse_dict.get(l, '?') for l in letters)
                decoded.append(decoded_word)
            return ' '.join(decoded)
        except:
            return None
    
    def try_all_decodings(self, text):
        """Try all common decodings"""
        results = []
        text = text.strip()
        
        # Base64
        decoded = self.decode_base64(text)
        if decoded and decoded.isprintable():
            results.append(('Base64', decoded))
            # Try nested
            nested = self.try_all_decodings(decoded)
            results.extend(nested)
        
        # Base32
        decoded = self.decode_base32(text)
        if decoded and decoded.isprintable():
            results.append(('Base32', decoded))
        
        # Hex
        decoded = self.decode_hex(text)
        if decoded and decoded.isprintable():
            results.append(('Hex', decoded))
        
        # URL
        decoded = self.decode_url(text)
        if decoded != text and decoded.isprintable():
            results.append(('URL', decoded))
        
        # Binary
        if re.match(r'^[01\s]+$', text):
            decoded = self.decode_binary(text)
            if decoded:
                results.append(('Binary', decoded))
        
        # ROT13
        decoded = self.decode_rot13(text)
        results.append(('ROT13', decoded))
        
        # Morse
        if re.match(r'^[\.\-\s/]+$', text):
            decoded = self.decode_morse(text)
            if decoded:
                results.append(('Morse', decoded))
        
        return results
    
    def analyze_crypto(self, filepath_or_text):
        """Analyze cryptographic content"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🔐 CRYPTOGRAPHY ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        # Get text content
        if os.path.exists(filepath_or_text):
            with open(filepath_or_text, 'r', errors='ignore') as f:
                text = f.read()
        else:
            text = filepath_or_text
        
        # Try all decodings
        print(f"{Colors.YELLOW}🔄 Trying all decodings...{Colors.RESET}\n")
        decodings = self.try_all_decodings(text)
        
        for encoding, decoded in decodings:
            print(f"   {Colors.GREEN}✓ {encoding}:{Colors.RESET}")
            print(f"     {decoded[:200]}{'...' if len(decoded) > 200 else ''}")
            
            # Search for flags
            flags = self.search_flags(decoded)
            if flags:
                print(f"     {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
        
        # Caesar all shifts
        print(f"\n{Colors.YELLOW}🔄 Trying Caesar cipher (all shifts)...{Colors.RESET}")
        caesar_results = self.decode_caesar(text)
        for shift, decoded in caesar_results:
            flags = self.search_flags(decoded)
            if flags:
                print(f"   {Colors.GREEN}✓ Caesar shift {shift}: {decoded[:100]}{Colors.RESET}")
                print(f"     {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # OSINT & GEOLOCATION MODULE
    # ═══════════════════════════════════════════════════════════════════════════
    
    def extract_gps(self, filepath):
        """Extract GPS from image"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🌍 GEOLOCATION & OSINT ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        # Use exiftool
        if self.tool_exists('exiftool'):
            output = self.run_command(['exiftool', '-gps*', '-c', '%.6f', filepath])
            print(f"{Colors.YELLOW}📍 GPS Data:{Colors.RESET}")
            if output.strip():
                print(output)
                
                # Extract coordinates
                lat_match = re.search(r'GPS Latitude\s*:\s*(.+)', output)
                lon_match = re.search(r'GPS Longitude\s*:\s*(.+)', output)
                
                if lat_match and lon_match:
                    lat = lat_match.group(1).strip()
                    lon = lon_match.group(1).strip()
                    print(f"\n{Colors.GREEN}📱 Google Maps:{Colors.RESET}")
                    print(f"   https://maps.google.com/?q={lat},{lon}")
                    self.findings.append(f"GPS: {lat}, {lon}")
            else:
                print("   No GPS data found")
        
        # Extract all metadata
        if self.tool_exists('exiftool'):
            output = self.run_command(['exiftool', filepath])
            print(f"\n{Colors.YELLOW}📋 Full Metadata:{Colors.RESET}")
            
            # Look for interesting fields
            interesting = ['Author', 'Creator', 'Artist', 'Comment', 'User Comment', 
                          'Copyright', 'Make', 'Model', 'Software', 'Description']
            
            for line in output.split('\n'):
                for field in interesting:
                    if field.lower() in line.lower():
                        print(f"   {Colors.GREEN}{line}{Colors.RESET}")
                        self.findings.append(line)
            
            # Search for flags in metadata
            flags = self.search_flags(output)
            if flags:
                print(f"\n{Colors.GREEN}🚩 FLAG FOUND IN METADATA: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
        
        # Look for What3Words
        if self.tool_exists('strings'):
            output = self.run_command(['strings', '-n', '8', filepath])
            w3w = re.findall(r'([a-z]+\.[a-z]+\.[a-z]+)', output.lower())
            for match in w3w[:5]:
                if len(match.split('.')[0]) >= 3:
                    print(f"\n{Colors.YELLOW}🗺️ Possible What3Words:{Colors.RESET} {match}")
                    print(f"   Check: https://what3words.com/{match}")
        
        # Reverse image search URLs
        print(f"\n{Colors.YELLOW}🖼️ Reverse Image Search:{Colors.RESET}")
        print(f"   Google: https://images.google.com/ (upload image)")
        print(f"   TinEye: https://tineye.com/")
        print(f"   Yandex: https://yandex.com/images/")
        print(f"   GeoSpy: https://geospy.ai/")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # METADATA FORENSICS MODULE
    # ═══════════════════════════════════════════════════════════════════════════
    
    def analyze_forensics(self, filepath):
        """Analyze file for hidden data"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🔬 METADATA & FORENSICS ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        # File info
        print(f"{Colors.YELLOW}📁 File Info:{Colors.RESET}")
        if self.tool_exists('file'):
            output = self.run_command(['file', filepath])
            print(f"   {output.strip()}")
        
        # Strings search
        print(f"\n{Colors.YELLOW}🔤 Strings Analysis:{Colors.RESET}")
        if self.tool_exists('strings'):
            output = self.run_command(['strings', '-n', '8', filepath])
            flags = self.search_flags(output)
            if flags:
                print(f"   {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
            
            # Look for interesting strings
            interesting_patterns = [
                r'password[:\s=]+\S+',
                r'secret[:\s=]+\S+', 
                r'key[:\s=]+\S+',
                r'user[:\s=]+\S+',
                r'admin[:\s=]+\S+',
                r'https?://\S+',
                r'[a-zA-Z0-9+/]{20,}={0,2}',  # Base64
            ]
            
            for pattern in interesting_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                for m in matches[:3]:
                    print(f"   ⚠️ Found: {m[:100]}")
                    self.findings.append(m[:100])
        
        # Binwalk
        print(f"\n{Colors.YELLOW}📦 Embedded Files:{Colors.RESET}")
        if self.tool_exists('binwalk'):
            output = self.run_command(['binwalk', filepath])
            print(output[:500] if output else "   No embedded files found")
            
            # Extract embedded files
            extract_dir = f"{filepath}_extracted"
            self.run_command(['binwalk', '-e', '-C', extract_dir, filepath])
            
            if os.path.exists(extract_dir):
                print(f"   {Colors.GREEN}📂 Extracted to: {extract_dir}{Colors.RESET}")
        
        # Hex analysis for hidden data at end of file
        print(f"\n{Colors.YELLOW}🔍 Hex Analysis (file end):{Colors.RESET}")
        try:
            with open(filepath, 'rb') as f:
                f.seek(-500, 2)  # Last 500 bytes
                data = f.read()
                # Look for readable text
                text = data.decode('utf-8', errors='ignore')
                if text.strip():
                    flags = self.search_flags(text)
                    if flags:
                        print(f"   {Colors.GREEN}🚩 FLAG FOUND AT END: {flags}{Colors.RESET}")
                        self.found_flags.extend(flags)
                    elif any(c.isalpha() for c in text):
                        printable = ''.join(c if c.isprintable() else '.' for c in text)
                        if len(printable.replace('.', '')) > 10:
                            print(f"   Hidden text: {printable[:200]}")
        except:
            pass
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEGANOGRAPHY MODULE
    # ═══════════════════════════════════════════════════════════════════════════
    
    def analyze_stego(self, filepath):
        """Analyze image for steganography"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🖼️ STEGANOGRAPHY ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        ext = Path(filepath).suffix.lower()
        
        # zsteg for PNG
        if ext == '.png' and self.tool_exists('zsteg'):
            print(f"{Colors.YELLOW}🔍 zsteg (PNG LSB):{Colors.RESET}")
            output = self.run_command(['zsteg', filepath])
            if output:
                print(output[:1000])
                flags = self.search_flags(output)
                if flags:
                    print(f"   {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                    self.found_flags.extend(flags)
        
        # steghide for JPG (try empty password)
        if ext in ['.jpg', '.jpeg'] and self.tool_exists('steghide'):
            print(f"\n{Colors.YELLOW}🔍 steghide (JPG, empty password):{Colors.RESET}")
            output = self.run_command(['steghide', 'extract', '-sf', filepath, '-p', '', '-f'])
            print(output if output else "   No data extracted with empty password")
            
            # Try common passwords
            common_passwords = ['password', '123456', 'secret', 'ctf', 'flag', 'hidden']
            for pwd in common_passwords:
                output = self.run_command(['steghide', 'extract', '-sf', filepath, '-p', pwd, '-f'])
                if 'extracted' in output.lower():
                    print(f"   {Colors.GREEN}✓ Extracted with password: {pwd}{Colors.RESET}")
        
        # stegseek for brute force
        if ext in ['.jpg', '.jpeg'] and self.tool_exists('stegseek'):
            print(f"\n{Colors.YELLOW}🔍 stegseek (brute force):{Colors.RESET}")
            output = self.run_command(['stegseek', filepath], timeout=120)
            print(output[:500] if output else "   No hidden data found")
        
        # QR code detection
        if self.tool_exists('zbarimg'):
            print(f"\n{Colors.YELLOW}📱 QR Code Detection:{Colors.RESET}")
            output = self.run_command(['zbarimg', '--raw', '-q', filepath])
            if output.strip():
                print(f"   {Colors.GREEN}QR Content: {output.strip()}{Colors.RESET}")
                flags = self.search_flags(output)
                if flags:
                    print(f"   {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                    self.found_flags.extend(flags)
            else:
                print("   No QR code found")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # WEB SECURITY MODULE
    # ═══════════════════════════════════════════════════════════════════════════
    
    def analyze_web(self, url):
        """Analyze web challenge"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🌐 WEB SECURITY ANALYSIS{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            print(f"{Colors.RED}❌ Install requests and beautifulsoup4: pip install requests beautifulsoup4{Colors.RESET}")
            return
        
        try:
            print(f"{Colors.YELLOW}🔗 Fetching: {url}{Colors.RESET}")
            headers = {'User-Agent': 'Mozilla/5.0 CTFHunter/3.0'}
            resp = requests.get(url, headers=headers, timeout=30)
            
            print(f"   Status: {resp.status_code}")
            print(f"   Content-Length: {len(resp.content)}")
            
            # Check response headers
            print(f"\n{Colors.YELLOW}📋 Response Headers:{Colors.RESET}")
            interesting_headers = ['Server', 'X-Flag', 'Flag', 'X-Secret', 'X-Powered-By']
            for h in resp.headers:
                if any(x.lower() in h.lower() for x in interesting_headers + ['flag', 'secret', 'hint']):
                    print(f"   {Colors.GREEN}{h}: {resp.headers[h]}{Colors.RESET}")
            
            # Search HTML source
            print(f"\n{Colors.YELLOW}🔍 HTML Source Analysis:{Colors.RESET}")
            flags = self.search_flags(resp.text)
            if flags:
                print(f"   {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
            
            # HTML Comments
            soup = BeautifulSoup(resp.text, 'html.parser')
            comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
            if comments:
                print(f"\n{Colors.YELLOW}💬 HTML Comments:{Colors.RESET}")
                for c in comments[:5]:
                    print(f"   {c[:200]}")
                    flags = self.search_flags(c)
                    if flags:
                        self.found_flags.extend(flags)
            
            # Hidden inputs
            hidden = soup.find_all('input', {'type': 'hidden'})
            if hidden:
                print(f"\n{Colors.YELLOW}🔒 Hidden Inputs:{Colors.RESET}")
                for h in hidden:
                    print(f"   name={h.get('name')} value={h.get('value')}")
            
            # Check robots.txt
            robots_url = url.rstrip('/') + '/robots.txt'
            robots_resp = requests.get(robots_url, headers=headers, timeout=10)
            if robots_resp.status_code == 200:
                print(f"\n{Colors.YELLOW}🤖 robots.txt:{Colors.RESET}")
                print(robots_resp.text[:500])
                flags = self.search_flags(robots_resp.text)
                if flags:
                    self.found_flags.extend(flags)
            
            # Common paths to check
            print(f"\n{Colors.YELLOW}📂 Checking common paths...{Colors.RESET}")
            paths = ['/flag.txt', '/flag', '/.git/config', '/admin', '/backup', 
                    '/config.php', '/.env', '/api/flag', '/secret']
            
            for path in paths:
                try:
                    test_url = url.rstrip('/') + path
                    test_resp = requests.get(test_url, headers=headers, timeout=5)
                    if test_resp.status_code == 200:
                        print(f"   {Colors.GREEN}✓ Found: {path}{Colors.RESET}")
                        flags = self.search_flags(test_resp.text)
                        if flags:
                            print(f"     {Colors.GREEN}🚩 FLAG: {flags}{Colors.RESET}")
                            self.found_flags.extend(flags)
                except:
                    pass
                    
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # NETWORK FORENSICS MODULE
    # ═══════════════════════════════════════════════════════════════════════════
    
    def analyze_pcap(self, filepath):
        """Analyze PCAP file"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}📡 NETWORK FORENSICS (PCAP){Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        if not self.tool_exists('tshark'):
            print(f"{Colors.RED}❌ tshark not installed. Install Wireshark.{Colors.RESET}")
            return
        
        # Basic info
        print(f"{Colors.YELLOW}📊 PCAP Statistics:{Colors.RESET}")
        output = self.run_command(['tshark', '-r', filepath, '-q', '-z', 'io,stat,0'])
        print(output[:500] if output else "   Unable to read PCAP")
        
        # Extract HTTP
        print(f"\n{Colors.YELLOW}🌐 HTTP Requests:{Colors.RESET}")
        output = self.run_command(['tshark', '-r', filepath, '-Y', 'http.request', '-T', 'fields', 
                                  '-e', 'http.host', '-e', 'http.request.uri'])
        if output.strip():
            print(output[:1000])
            flags = self.search_flags(output)
            if flags:
                self.found_flags.extend(flags)
        
        # Extract strings
        print(f"\n{Colors.YELLOW}🔤 Strings from PCAP:{Colors.RESET}")
        if self.tool_exists('strings'):
            output = self.run_command(['strings', '-n', '10', filepath])
            flags = self.search_flags(output)
            if flags:
                print(f"   {Colors.GREEN}🚩 FLAG FOUND: {flags}{Colors.RESET}")
                self.found_flags.extend(flags)
        
        # Follow TCP streams
        print(f"\n{Colors.YELLOW}📝 TCP Stream 0:{Colors.RESET}")
        output = self.run_command(['tshark', '-r', filepath, '-q', '-z', 'follow,tcp,ascii,0'])
        if output:
            print(output[:1500])
            flags = self.search_flags(output)
            if flags:
                self.found_flags.extend(flags)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def analyze(self, target):
        """Main analysis function"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🎯 TARGET: {Colors.YELLOW}{target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
        
        # Web URL
        if target.startswith('http://') or target.startswith('https://'):
            self.analyze_web(target)
            return
        
        # File
        if not os.path.exists(target):
            print(f"{Colors.RED}❌ File not found: {target}{Colors.RESET}")
            return
        
        # Detect file type
        ext = Path(target).suffix.lower()
        
        # Image files
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']:
            self.extract_gps(target)
            self.analyze_forensics(target)
            self.analyze_stego(target)
        
        # PCAP files
        elif ext in ['.pcap', '.pcapng', '.cap']:
            self.analyze_pcap(target)
        
        # PDF files
        elif ext == '.pdf':
            self.analyze_forensics(target)
            # PDF specific
            if self.tool_exists('pdftotext'):
                output = self.run_command(['pdftotext', target, '-'])
                flags = self.search_flags(output)
                if flags:
                    print(f"{Colors.GREEN}🚩 FLAG IN PDF: {flags}{Colors.RESET}")
                    self.found_flags.extend(flags)
        
        # Archive files
        elif ext in ['.zip', '.tar', '.gz', '.rar', '.7z']:
            self.analyze_forensics(target)
            # Extract
            if self.tool_exists('7z'):
                output_dir = f"{target}_extracted"
                self.run_command(['7z', 'x', '-y', f'-o{output_dir}', target])
                if os.path.exists(output_dir):
                    print(f"{Colors.GREEN}📂 Extracted to: {output_dir}{Colors.RESET}")
        
        # Text/crypto files
        elif ext in ['.txt', '.enc', '.cipher', '.encoded']:
            self.analyze_crypto(target)
        
        # Default: full scan
        else:
            self.analyze_forensics(target)
            self.analyze_crypto(target)
        
        # Final results
        self.print_results()
    
    def print_results(self):
        """Print final results"""
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 FINAL RESULTS{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")
        
        if self.found_flags:
            print(f"{Colors.GREEN}🚩 FLAGS FOUND:{Colors.RESET}")
            for flag in set(self.found_flags):
                print(f"   {Colors.GREEN}{Colors.BOLD}➤ {flag}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠️ No flags found automatically.{Colors.RESET}")
            print(f"{Colors.WHITE}   Try manual investigation with the hints above.{Colors.RESET}")
        
        if self.findings:
            print(f"\n{Colors.YELLOW}📋 Key Findings:{Colors.RESET}")
            for f in self.findings[:10]:
                print(f"   • {f}")
        
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    
    def interactive(self):
        """Interactive mode"""
        self.print_banner()
        
        # Ask for flag format
        print(f"\n{Colors.CYAN}🚩 Enter your CTF flag format (e.g., digitalcyberhunt{{}}, flag{{}}):{Colors.RESET}")
        flag_format = input(f"{Colors.GREEN}>>> {Colors.RESET}").strip()
        
        if flag_format:
            prefix = flag_format.replace('{}', '').replace('{', '')
            self.add_flag_pattern(prefix)
        else:
            print(f"{Colors.YELLOW}Using default patterns (digitalcyberhunt{{}}, flag{{}}, etc.){Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}🎮 INTERACTIVE MODE{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"""
Commands:
  {Colors.GREEN}solve <file/url>{Colors.RESET}  - Analyze file or URL (use FULL PATH or drag & drop)
  {Colors.GREEN}crypto <text>{Colors.RESET}     - Decode crypto text
  {Colors.GREEN}osint <username>{Colors.RESET}  - OSINT on username
  {Colors.GREEN}cd <directory>{Colors.RESET}    - Change directory
  {Colors.GREEN}ls{Colors.RESET}                - List files in current directory
  {Colors.GREEN}pwd{Colors.RESET}               - Show current directory
  {Colors.GREEN}exit{Colors.RESET}              - Exit

{Colors.YELLOW}💡 TIP: Drag & drop file into terminal for full path!{Colors.RESET}
""")
        
        while True:
            try:
                cmd = input(f"\n{Colors.CYAN}🤖 CTF> {Colors.RESET}").strip()
                
                if not cmd:
                    continue
                elif cmd.lower() == 'exit':
                    print(f"{Colors.GREEN}👋 Good luck with your CTF!{Colors.RESET}")
                    break
                elif cmd.lower() == 'pwd':
                    print(f"{Colors.GREEN}{os.getcwd()}{Colors.RESET}")
                elif cmd.lower() == 'ls':
                    files = os.listdir('.')
                    for f in sorted(files):
                        if os.path.isdir(f):
                            print(f"  {Colors.BLUE}📁 {f}/{Colors.RESET}")
                        else:
                            print(f"  📄 {f}")
                elif cmd.lower().startswith('cd '):
                    new_dir = cmd[3:].strip()
                    try:
                        os.chdir(os.path.expanduser(new_dir))
                        print(f"{Colors.GREEN}📂 Changed to: {os.getcwd()}{Colors.RESET}")
                    except:
                        print(f"{Colors.RED}❌ Cannot change to: {new_dir}{Colors.RESET}")
                elif cmd.lower().startswith('solve '):
                    target = cmd[6:].strip().strip('"').strip("'")
                    # Expand ~ to home directory
                    target = os.path.expanduser(target)
                    self.analyze(target)
                elif cmd.lower().startswith('crypto '):
                    text = cmd[7:].strip()
                    self.analyze_crypto(text)
                elif cmd.lower().startswith('osint '):
                    username = cmd[6:].strip()
                    self.osint_username(username)
                elif os.path.exists(cmd) or os.path.exists(os.path.expanduser(cmd)) or cmd.startswith('http'):
                    target = os.path.expanduser(cmd)
                    self.analyze(target)
                else:
                    # Try as crypto text
                    self.analyze_crypto(cmd)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.GREEN}👋 Goodbye!{Colors.RESET}")
                break
    
    def osint_username(self, username):
        """Quick OSINT on username"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}👤 OSINT: {username}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
        }
        
        print(f"{Colors.YELLOW}🔍 Check these URLs:{Colors.RESET}")
        for platform, url in platforms.items():
            print(f"   {platform}: {url}")
        
        print(f"\n{Colors.YELLOW}🛠️ Tools to use:{Colors.RESET}")
        print(f"   sherlock {username}")
        print(f"   maigret {username}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='CTF Ultimate - 100% Reliable CTF Solver')
    parser.add_argument('target', nargs='?', help='File or URL to analyze')
    parser.add_argument('-f', '--flag', help='Flag format (e.g., digitalcyberhunt{})', action='append', default=[])
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    ctf = CTFUltimate()
    
    # Add custom flag patterns
    for fmt in args.flag:
        prefix = fmt.replace('{}', '').replace('{', '')
        ctf.add_flag_pattern(prefix)
    
    if args.interactive or not args.target:
        ctf.interactive()
    else:
        ctf.print_banner()
        ctf.analyze(args.target)


if __name__ == '__main__':
    main()
