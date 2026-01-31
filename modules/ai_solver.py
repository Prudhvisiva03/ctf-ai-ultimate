#!/usr/bin/env python3
"""
AI Solver Module - Intelligent CTF Challenge Solver
Automatically solves challenges using multiple techniques
Author: Prudhvi (CTFHunter)
Version: 3.0.0
"""

import os
import sys
import json
import subprocess
import shutil
import re
import base64
import binascii
import time
from pathlib import Path


class AISolver:
    """Intelligent CTF Solver that tries multiple techniques automatically"""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get('output_directory', 'output')
        self.flags_found = []
        self.steps_taken = []
        self.manual_steps = []
        self.verbose = config.get('verbose', True)
        
        # Flag patterns
        self.flag_patterns = config.get('flag_patterns', [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}',
            r'digitalcyberhunt\{[^}]+\}',
            r'DCH\{[^}]+\}'
        ])
        
        # Tool requirements for each technique
        self.tool_requirements = {
            'strings': {'windows': 'strings', 'linux': 'strings'},
            'binwalk': {'pip': 'binwalk'},
            'exiftool': {'windows': 'exiftool', 'linux': 'exiftool'},
            'steghide': {'linux': 'steghide'},
            'zsteg': {'gem': 'zsteg'},
            'foremost': {'linux': 'foremost'},
            'tshark': {'windows': 'tshark', 'linux': 'tshark'},
            'pdftotext': {'linux': 'poppler-utils'},
            'unzip': {'windows': 'builtin', 'linux': 'unzip'},
        }
        
    def log(self, message, level='info'):
        """Log a message with formatting"""
        icons = {
            'info': '[*]',
            'success': '[+]',
            'error': '[-]',
            'warning': '[!]',
            'step': '[>]',
            'flag': '[FLAG]'
        }
        colors = {
            'info': '\033[94m',
            'success': '\033[92m',
            'error': '\033[91m',
            'warning': '\033[93m',
            'step': '\033[96m',
            'flag': '\033[95m'
        }
        reset = '\033[0m'
        
        icon = icons.get(level, '[*]')
        color = colors.get(level, '')
        
        if self.verbose:
            print(f"{color}{icon} {message}{reset}")
        
        self.steps_taken.append({'level': level, 'message': message})
        
    def check_flags(self, text):
        """Check text for flags and add to found list"""
        if not text:
            return []
        
        found = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, str(text), re.IGNORECASE)
            for match in matches:
                if match not in self.flags_found:
                    self.flags_found.append(match)
                    found.append(match)
                    self.log(f"FLAG FOUND: {match}", 'flag')
        return found
    
    def is_tool_available(self, tool_name):
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None
    
    def install_tool(self, tool_name):
        """Try to install a missing tool"""
        self.log(f"Attempting to install: {tool_name}", 'step')
        
        is_windows = sys.platform == 'win32'
        
        # Python packages
        pip_tools = {
            'binwalk': 'binwalk',
            'pycryptodome': 'pycryptodome',
            'pillow': 'Pillow',
            'opencv-python': 'opencv-python',
        }
        
        if tool_name in pip_tools:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', pip_tools[tool_name]], 
                             capture_output=True, timeout=120)
                self.log(f"Installed {tool_name} via pip", 'success')
                return True
            except:
                pass
        
        if is_windows:
            # Windows-specific installations
            choco_tools = {
                'exiftool': 'exiftool',
                'ffmpeg': 'ffmpeg',
                'strings': 'strings',
            }
            
            if tool_name in choco_tools:
                self.manual_steps.append({
                    'tool': tool_name,
                    'command': f'choco install {choco_tools[tool_name]}',
                    'alt': f'Download from official website and add to PATH'
                })
                return False
        else:
            # Linux installations
            apt_tools = {
                'steghide': 'steghide',
                'foremost': 'foremost',
                'exiftool': 'libimage-exiftool-perl',
                'binwalk': 'binwalk',
                'tshark': 'tshark',
                'strings': 'binutils',
                'pdftotext': 'poppler-utils',
            }
            
            if tool_name in apt_tools:
                try:
                    result = subprocess.run(
                        ['sudo', 'apt-get', 'install', '-y', apt_tools[tool_name]],
                        capture_output=True, timeout=300
                    )
                    if result.returncode == 0:
                        self.log(f"Installed {tool_name} via apt", 'success')
                        return True
                except:
                    pass
        
        return False
    
    def run_command(self, cmd, timeout=60):
        """Run a command and return output"""
        try:
            result = subprocess.run(
                cmd if isinstance(cmd, list) else cmd.split(),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout + result.stderr
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return str(e)
    
    def solve(self, filepath):
        """Main solver - automatically try multiple techniques"""
        
        if not os.path.exists(filepath):
            self.log(f"File not found: {filepath}", 'error')
            return self.get_results()
        
        self.log(f"Starting automated CTF solve for: {filepath}", 'info')
        print("\n" + "="*70)
        print("🤖 CTFHunter AI SOLVER - Automatic Challenge Analysis")
        print("="*70 + "\n")
        
        # Detect file type
        file_type = self.detect_file_type(filepath)
        self.log(f"Detected file type: {file_type}", 'info')
        
        # Run universal techniques first
        self.try_universal_techniques(filepath)
        
        # Run type-specific techniques
        if file_type in ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'image']:
            self.solve_image(filepath)
        elif file_type in ['zip', 'tar', 'gz', '7z', 'rar', 'archive']:
            self.solve_archive(filepath)
        elif file_type in ['pcap', 'pcapng', 'network']:
            self.solve_pcap(filepath)
        elif file_type in ['pdf', 'document']:
            self.solve_pdf(filepath)
        elif file_type in ['elf', 'exe', 'binary']:
            self.solve_binary(filepath)
        elif file_type in ['wav', 'mp3', 'audio']:
            self.solve_audio(filepath)
        else:
            self.solve_generic(filepath)
        
        return self.get_results()
    
    def detect_file_type(self, filepath):
        """Detect file type from extension and magic bytes"""
        ext = Path(filepath).suffix.lower().lstrip('.')
        
        # Check extension first
        type_map = {
            'png': 'image', 'jpg': 'image', 'jpeg': 'image', 'bmp': 'image', 'gif': 'image',
            'zip': 'archive', 'tar': 'archive', 'gz': 'archive', '7z': 'archive', 'rar': 'archive',
            'pcap': 'network', 'pcapng': 'network',
            'pdf': 'document',
            'wav': 'audio', 'mp3': 'audio', 'flac': 'audio',
            'elf': 'binary', 'exe': 'binary',
        }
        
        if ext in type_map:
            return ext
        
        # Check magic bytes
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            
            if header.startswith(b'\x89PNG'):
                return 'png'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'jpg'
            elif header.startswith(b'PK\x03\x04'):
                return 'zip'
            elif header.startswith(b'%PDF'):
                return 'pdf'
            elif header.startswith(b'\x7fELF'):
                return 'elf'
            elif header.startswith(b'MZ'):
                return 'exe'
            elif header.startswith(b'\xd4\xc3\xb2\xa1') or header.startswith(b'\xa1\xb2\xc3\xd4'):
                return 'pcap'
            elif header.startswith(b'RIFF'):
                return 'wav'
        except:
            pass
        
        return 'unknown'
    
    def try_universal_techniques(self, filepath):
        """Try techniques that work on any file"""
        
        print("\n" + "-"*50)
        print("📋 STEP 1: Universal Analysis Techniques")
        print("-"*50 + "\n")
        
        # 1. Strings extraction
        self.log("Extracting strings from file...", 'step')
        self.try_strings(filepath)
        
        # 2. Hex dump check
        self.log("Checking hex dump for hidden data...", 'step')
        self.try_hex_analysis(filepath)
        
        # 3. File carving with binwalk
        self.log("Running binwalk for embedded files...", 'step')
        self.try_binwalk(filepath)
        
        # 4. Check for common encodings
        self.log("Checking for encoded data...", 'step')
        self.try_decode_file(filepath)
        
    def try_strings(self, filepath):
        """Extract and analyze strings"""
        
        # Python implementation (cross-platform)
        strings_found = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Extract printable strings (min length 4)
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 4:
                        strings_found.append(''.join(current))
                    current = []
            
            if len(current) >= 4:
                strings_found.append(''.join(current))
            
            self.log(f"Found {len(strings_found)} strings", 'success')
            
            # Check each string for flags
            for s in strings_found:
                self.check_flags(s)
            
            # Look for interesting strings
            interesting = []
            keywords = ['flag', 'ctf', 'password', 'secret', 'key', 'hidden', 'base64', 'http', 'ftp']
            for s in strings_found:
                for kw in keywords:
                    if kw.lower() in s.lower():
                        interesting.append(s)
                        break
            
            if interesting:
                self.log(f"Found {len(interesting)} interesting strings:", 'success')
                for s in interesting[:10]:
                    print(f"    → {s[:100]}")
                    
        except Exception as e:
            self.log(f"Strings extraction error: {e}", 'error')
    
    def try_hex_analysis(self, filepath):
        """Analyze hex dump for hidden data"""
        try:
            with open(filepath, 'rb') as f:
                # Check header
                header = f.read(32)
                
                # Check footer
                f.seek(-32, 2)
                footer = f.read(32)
            
            # Look for flags in hex
            self.check_flags(header.decode('utf-8', errors='ignore'))
            self.check_flags(footer.decode('utf-8', errors='ignore'))
            
            # Check for appended data after file end markers
            # PNG IEND, JPEG EOI, etc.
            
        except Exception as e:
            self.log(f"Hex analysis error: {e}", 'error')
    
    def try_binwalk(self, filepath):
        """Run binwalk for embedded files"""
        try:
            import binwalk
            self.log("Scanning for embedded files...", 'step')
            
            for module in binwalk.scan(filepath, signature=True, quiet=True):
                for result in module.results:
                    self.log(f"Found: {result.description} at offset {result.offset}", 'success')
            
            # Extract
            extract_dir = os.path.join(self.output_dir, '_binwalk_extracted')
            os.makedirs(extract_dir, exist_ok=True)
            
            for module in binwalk.scan(filepath, extract=True, directory=extract_dir, quiet=True):
                if module.results:
                    self.log(f"Extracted files to: {extract_dir}", 'success')
                    # Scan extracted files
                    for root, dirs, files in os.walk(extract_dir):
                        for f in files:
                            extracted_path = os.path.join(root, f)
                            self.log(f"Checking extracted: {f}", 'step')
                            with open(extracted_path, 'rb') as ef:
                                content = ef.read()
                                self.check_flags(content.decode('utf-8', errors='ignore'))
                    
        except ImportError:
            self.log("binwalk not installed, trying command line...", 'warning')
            output = self.run_command(['binwalk', '-e', filepath])
            if output:
                self.check_flags(output)
        except Exception as e:
            self.log(f"Binwalk error: {e}", 'warning')
    
    def try_decode_file(self, filepath):
        """Try common decoding methods"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            text = data.decode('utf-8', errors='ignore')
            
            # Try Base64
            self.log("Trying Base64 decode...", 'step')
            try:
                # Find base64-like strings
                b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
                b64_matches = re.findall(b64_pattern, text)
                
                for match in b64_matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        self.check_flags(decoded)
                        if 'flag' in decoded.lower() or '{' in decoded:
                            self.log(f"Base64 decoded: {decoded[:100]}", 'success')
                    except:
                        pass
            except:
                pass
            
            # Try hex decode
            self.log("Trying hex decode...", 'step')
            try:
                hex_pattern = r'[0-9a-fA-F]{20,}'
                hex_matches = re.findall(hex_pattern, text)
                
                for match in hex_matches:
                    try:
                        decoded = binascii.unhexlify(match).decode('utf-8', errors='ignore')
                        self.check_flags(decoded)
                        if 'flag' in decoded.lower():
                            self.log(f"Hex decoded: {decoded[:100]}", 'success')
                    except:
                        pass
            except:
                pass
            
            # Try ROT13
            self.log("Trying ROT13...", 'step')
            import codecs
            rot13 = codecs.decode(text, 'rot_13')
            self.check_flags(rot13)
            
        except Exception as e:
            self.log(f"Decode error: {e}", 'warning')
    
    def solve_image(self, filepath):
        """Solve image steganography challenges"""
        
        print("\n" + "-"*50)
        print("🖼️  STEP 2: Image Steganography Analysis")
        print("-"*50 + "\n")
        
        ext = Path(filepath).suffix.lower()
        
        # 1. EXIF metadata
        self.log("Checking EXIF metadata...", 'step')
        self.try_exif(filepath)
        
        # 2. PNG-specific
        if ext == '.png':
            self.log("Running PNG-specific analysis...", 'step')
            self.try_zsteg(filepath)
            self.try_pngcheck(filepath)
        
        # 3. JPG-specific
        if ext in ['.jpg', '.jpeg']:
            self.log("Running JPEG-specific analysis...", 'step')
            self.try_steghide(filepath)
            self.try_stegseek(filepath)
        
        # 4. LSB analysis
        self.log("Checking LSB steganography...", 'step')
        self.try_lsb_extraction(filepath)
        
        # 5. Visual analysis hints
        self.manual_steps.append({
            'tool': 'StegSolve',
            'description': 'Use StegSolve to analyze color planes and apply filters',
            'command': 'java -jar StegSolve.jar'
        })
        
    def try_exif(self, filepath):
        """Extract EXIF metadata"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(filepath)
            exif_data = img._getexif()
            
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    self.log(f"EXIF {tag}: {value}", 'info')
                    self.check_flags(str(value))
            
            # Check image info/comments
            if hasattr(img, 'info'):
                for key, value in img.info.items():
                    self.log(f"Image info {key}: {value}", 'info')
                    self.check_flags(str(value))
                    
        except Exception as e:
            self.log(f"EXIF extraction: {e}", 'warning')
            
            # Try exiftool
            output = self.run_command(['exiftool', filepath])
            if output:
                print(output[:500])
                self.check_flags(output)
    
    def try_zsteg(self, filepath):
        """Run zsteg for PNG steganography"""
        if not self.is_tool_available('zsteg'):
            self.log("zsteg not available", 'warning')
            self.manual_steps.append({
                'tool': 'zsteg',
                'description': 'Install zsteg to analyze PNG steganography',
                'command': 'gem install zsteg',
                'then': f'zsteg -a {filepath}'
            })
            return
        
        output = self.run_command(['zsteg', '-a', filepath])
        if output:
            self.log("Zsteg output:", 'success')
            for line in output.split('\n')[:20]:
                if line.strip():
                    print(f"    {line}")
                    self.check_flags(line)
    
    def try_pngcheck(self, filepath):
        """Check PNG structure"""
        if self.is_tool_available('pngcheck'):
            output = self.run_command(['pngcheck', '-v', filepath])
            if output:
                self.check_flags(output)
    
    def try_steghide(self, filepath):
        """Try steghide extraction"""
        if not self.is_tool_available('steghide'):
            self.log("steghide not available", 'warning')
            self.manual_steps.append({
                'tool': 'steghide',
                'description': 'Install steghide to extract hidden data from JPEG',
                'command': 'sudo apt install steghide',
                'then': f'steghide extract -sf {filepath}'
            })
            return
        
        # Try empty password
        output_file = os.path.join(self.output_dir, 'steghide_extracted.txt')
        output = self.run_command(['steghide', 'extract', '-sf', filepath, '-p', '', '-xf', output_file])
        
        if output and 'wrote extracted data' in output.lower():
            self.log(f"Steghide extracted data!", 'success')
            with open(output_file, 'r', errors='ignore') as f:
                content = f.read()
                self.check_flags(content)
                print(f"    Content: {content[:200]}")
        
        # Try common passwords
        common_passwords = ['password', '123456', 'secret', 'admin', 'ctf', 'flag']
        for pwd in common_passwords:
            output = self.run_command(['steghide', 'extract', '-sf', filepath, '-p', pwd, '-xf', output_file])
            if output and 'wrote extracted data' in output.lower():
                self.log(f"Steghide extracted with password: {pwd}", 'success')
                with open(output_file, 'r', errors='ignore') as f:
                    content = f.read()
                    self.check_flags(content)
    
    def try_stegseek(self, filepath):
        """Try stegseek for fast steghide cracking"""
        if not self.is_tool_available('stegseek'):
            self.manual_steps.append({
                'tool': 'stegseek',
                'description': 'Fast steghide password cracker',
                'command': 'sudo apt install stegseek',
                'then': f'stegseek {filepath} /usr/share/wordlists/rockyou.txt'
            })
            return
        
        output_file = os.path.join(self.output_dir, 'stegseek_output')
        output = self.run_command(['stegseek', filepath, '-xf', output_file], timeout=120)
        if output and os.path.exists(output_file):
            with open(output_file, 'r', errors='ignore') as f:
                content = f.read()
                self.check_flags(content)
    
    def try_lsb_extraction(self, filepath):
        """Try LSB steganography extraction"""
        try:
            from PIL import Image
            
            img = Image.open(filepath)
            pixels = list(img.getdata())
            
            # Extract LSB
            bits = []
            for pixel in pixels[:1000]:  # First 1000 pixels
                if isinstance(pixel, tuple):
                    for channel in pixel[:3]:  # RGB
                        bits.append(str(channel & 1))
            
            # Convert bits to bytes
            binary = ''.join(bits)
            chars = []
            for i in range(0, len(binary) - 8, 8):
                byte = binary[i:i+8]
                char = chr(int(byte, 2))
                if 32 <= ord(char) < 127:
                    chars.append(char)
            
            text = ''.join(chars)
            self.check_flags(text)
            
            if text and len(text) > 10:
                self.log(f"LSB data found: {text[:100]}", 'success')
                
        except Exception as e:
            self.log(f"LSB extraction: {e}", 'warning')
    
    def solve_archive(self, filepath):
        """Solve archive challenges"""
        
        print("\n" + "-"*50)
        print("📦 STEP 2: Archive Analysis")
        print("-"*50 + "\n")
        
        extract_dir = os.path.join(self.output_dir, '_archive_extracted')
        os.makedirs(extract_dir, exist_ok=True)
        
        ext = Path(filepath).suffix.lower()
        
        # Try to extract
        if ext == '.zip':
            self.try_zip_extract(filepath, extract_dir)
        elif ext in ['.tar', '.gz', '.tgz']:
            self.try_tar_extract(filepath, extract_dir)
        elif ext == '.rar':
            self.try_rar_extract(filepath, extract_dir)
        elif ext == '.7z':
            self.try_7z_extract(filepath, extract_dir)
        
        # Scan extracted files
        self.scan_directory(extract_dir)
    
    def try_zip_extract(self, filepath, extract_dir):
        """Extract ZIP files"""
        import zipfile
        
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                # Check for password
                for name in zf.namelist():
                    try:
                        zf.extract(name, extract_dir)
                        self.log(f"Extracted: {name}", 'success')
                    except RuntimeError as e:
                        if 'password' in str(e).lower():
                            self.log(f"Password protected: {name}", 'warning')
                            self.try_crack_zip(filepath, extract_dir)
                            return
                        
        except zipfile.BadZipFile:
            self.log("Invalid or corrupted ZIP file", 'error')
            self.manual_steps.append({
                'description': 'Try fixing the ZIP file',
                'command': f'zip -FF {filepath} --out fixed.zip'
            })
    
    def try_crack_zip(self, filepath, extract_dir):
        """Try to crack ZIP password"""
        import zipfile
        
        self.log("Attempting to crack ZIP password...", 'step')
        
        # Common passwords
        passwords = [
            '', 'password', '123456', 'admin', 'secret', 'ctf', 'flag',
            'letmein', 'welcome', 'monkey', 'dragon', 'master', '12345678'
        ]
        
        with zipfile.ZipFile(filepath, 'r') as zf:
            for pwd in passwords:
                try:
                    zf.extractall(extract_dir, pwd=pwd.encode())
                    self.log(f"ZIP cracked! Password: '{pwd}'", 'success')
                    return
                except:
                    pass
        
        # Suggest tools
        self.manual_steps.append({
            'tool': 'john',
            'description': 'Use John the Ripper to crack ZIP',
            'commands': [
                f'zip2john {filepath} > hash.txt',
                'john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt'
            ]
        })
        
        self.manual_steps.append({
            'tool': 'fcrackzip',
            'description': 'Use fcrackzip for ZIP password',
            'command': f'fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt {filepath}'
        })
    
    def try_tar_extract(self, filepath, extract_dir):
        """Extract TAR files"""
        import tarfile
        
        try:
            with tarfile.open(filepath, 'r:*') as tf:
                tf.extractall(extract_dir)
                self.log(f"Extracted TAR to: {extract_dir}", 'success')
        except Exception as e:
            self.log(f"TAR extraction error: {e}", 'error')
    
    def try_rar_extract(self, filepath, extract_dir):
        """Extract RAR files"""
        output = self.run_command(['unrar', 'x', filepath, extract_dir])
        if output:
            self.log("RAR extracted", 'success')
        else:
            self.manual_steps.append({
                'tool': 'unrar',
                'command': f'unrar x {filepath}'
            })
    
    def try_7z_extract(self, filepath, extract_dir):
        """Extract 7z files"""
        output = self.run_command(['7z', 'x', filepath, f'-o{extract_dir}'])
        if output:
            self.log("7z extracted", 'success')
    
    def scan_directory(self, directory):
        """Recursively scan a directory for flags"""
        for root, dirs, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                self.log(f"Scanning: {f}", 'step')
                
                try:
                    with open(fpath, 'rb') as file:
                        content = file.read()
                        self.check_flags(content.decode('utf-8', errors='ignore'))
                except:
                    pass
    
    def solve_pcap(self, filepath):
        """Solve network capture challenges"""
        
        print("\n" + "-"*50)
        print("📡 STEP 2: Network Capture Analysis")
        print("-"*50 + "\n")
        
        # Try tshark
        if self.is_tool_available('tshark'):
            self.log("Running tshark analysis...", 'step')
            
            # Extract HTTP
            output = self.run_command(['tshark', '-r', filepath, '-Y', 'http', '-T', 'fields', '-e', 'http.request.uri', '-e', 'http.file_data'])
            if output:
                self.check_flags(output)
            
            # Follow TCP streams
            output = self.run_command(['tshark', '-r', filepath, '-z', 'follow,tcp,ascii,0'])
            if output:
                self.check_flags(output)
                
        else:
            self.manual_steps.append({
                'tool': 'Wireshark',
                'description': 'Open PCAP in Wireshark',
                'steps': [
                    'File > Open > Select PCAP',
                    'Right-click packet > Follow > TCP Stream',
                    'Check File > Export Objects > HTTP'
                ]
            })
        
        # Try scapy
        try:
            from scapy.all import rdpcap
            
            packets = rdpcap(filepath)
            self.log(f"Loaded {len(packets)} packets", 'success')
            
            for pkt in packets:
                if pkt.haslayer('Raw'):
                    data = pkt['Raw'].load.decode('utf-8', errors='ignore')
                    self.check_flags(data)
                    
        except ImportError:
            self.log("scapy not available", 'warning')
        except Exception as e:
            self.log(f"PCAP error: {e}", 'warning')
    
    def solve_pdf(self, filepath):
        """Solve PDF challenges"""
        
        print("\n" + "-"*50)
        print("📄 STEP 2: PDF Forensics")
        print("-"*50 + "\n")
        
        # Extract text
        self.log("Extracting PDF text...", 'step')
        
        try:
            import PyPDF2
            
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                
                # Check metadata
                if reader.metadata:
                    self.log("PDF Metadata:", 'info')
                    for key, value in reader.metadata.items():
                        print(f"    {key}: {value}")
                        self.check_flags(str(value))
                
                # Extract text from each page
                for i, page in enumerate(reader.pages):
                    text = page.extract_text()
                    if text:
                        self.check_flags(text)
                        
        except ImportError:
            self.log("PyPDF2 not installed", 'warning')
            self.manual_steps.append({
                'command': 'pip install PyPDF2'
            })
        except Exception as e:
            self.log(f"PDF error: {e}", 'warning')
        
        # Try pdftotext
        if self.is_tool_available('pdftotext'):
            output = self.run_command(['pdftotext', filepath, '-'])
            if output:
                self.check_flags(output)
        
        # Check for JavaScript/embedded files
        self.manual_steps.append({
            'tool': 'pdf-parser',
            'description': 'Analyze PDF structure for hidden objects',
            'command': f'pdf-parser.py {filepath}'
        })
    
    def solve_binary(self, filepath):
        """Solve binary/reverse engineering challenges"""
        
        print("\n" + "-"*50)
        print("💻 STEP 2: Binary Analysis")
        print("-"*50 + "\n")
        
        # Strings already done in universal
        
        # Check file info
        if self.is_tool_available('file'):
            output = self.run_command(['file', filepath])
            if output:
                self.log(f"File type: {output}", 'info')
        
        # Suggest tools
        self.manual_steps.append({
            'tool': 'Ghidra',
            'description': 'Open in Ghidra for full reverse engineering',
            'steps': [
                'File > Import File',
                'Analyze the binary',
                'Search for strings (Search > For Strings)',
                'Look for main function'
            ]
        })
        
        self.manual_steps.append({
            'tool': 'gdb',
            'description': 'Debug with GDB',
            'commands': [
                f'gdb {filepath}',
                'info functions',
                'break main',
                'run'
            ]
        })
    
    def solve_audio(self, filepath):
        """Solve audio steganography challenges"""
        
        print("\n" + "-"*50)
        print("🔊 STEP 2: Audio Analysis")
        print("-"*50 + "\n")
        
        # Check spectrogram
        self.manual_steps.append({
            'tool': 'Sonic Visualiser / Audacity',
            'description': 'Check the spectrogram for hidden images',
            'steps': [
                'Open in Audacity',
                'View > Spectrogram',
                'Look for patterns or text'
            ]
        })
        
        # SSTV
        self.manual_steps.append({
            'tool': 'SSTV Decoder',
            'description': 'May contain SSTV (Slow Scan TV) encoded image',
            'command': 'sstv -d {filepath} -o output.png'
        })
        
        # Morse code
        self.manual_steps.append({
            'description': 'Listen for morse code patterns (short/long beeps)'
        })
    
    def solve_generic(self, filepath):
        """Solve unknown file types"""
        
        print("\n" + "-"*50)
        print("❓ STEP 2: Generic File Analysis")
        print("-"*50 + "\n")
        
        # Already ran universal techniques
        self.log("Universal techniques completed. Try manual analysis.", 'info')
        
        self.manual_steps.append({
            'description': 'Check if file extension is misleading',
            'steps': [
                'Use `file` command to check real type',
                'Try renaming to common extensions (.zip, .png, etc.)',
                'Open in hex editor to check magic bytes'
            ]
        })
    
    def get_results(self):
        """Get final results and summary"""
        
        print("\n" + "="*70)
        print("[#] SOLVER RESULTS SUMMARY")
        print("="*70 + "\n")
        
        # Flags found
        if self.flags_found:
            print("[FLAG] FLAGS FOUND:")
            print("-"*40)
            for i, flag in enumerate(self.flags_found, 1):
                print(f"  {i}. \033[92m{flag}\033[0m")
            print()
        else:
            print("[!] No flags automatically found\n")
        
        # Manual steps needed
        if self.manual_steps:
            print("[>] MANUAL STEPS TO TRY:")
            print("-"*40)
            for i, step in enumerate(self.manual_steps, 1):
                print(f"\n  {i}. {step.get('tool', step.get('description', 'Step'))}")
                if 'description' in step and 'tool' in step:
                    print(f"     {step['description']}")
                if 'command' in step:
                    print(f"     -> {step['command']}")
                if 'commands' in step:
                    for cmd in step['commands']:
                        print(f"     → {cmd}")
                if 'steps' in step:
                    for s in step['steps']:
                        print(f"     • {s}")
                if 'then' in step:
                    print(f"     Then: {step['then']}")
            print()
        
        print("="*70)
        
        return {
            'flags': self.flags_found,
            'steps_taken': self.steps_taken,
            'manual_steps': self.manual_steps
        }


# For standalone testing
if __name__ == '__main__':
    if len(sys.argv) > 1:
        solver = AISolver({'output_directory': 'output', 'verbose': True})
        solver.solve(sys.argv[1])
    else:
        print("Usage: python ai_solver.py <file>")
