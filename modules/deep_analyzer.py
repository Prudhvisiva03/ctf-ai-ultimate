#!/usr/bin/env python3
"""
Deep Analysis Module - In-Depth CTF Analysis Engine
Performs comprehensive analysis at every level
"""

import subprocess
import os
import re
import base64
import binascii
import struct
import hashlib
import zlib
import gzip
import bz2
import lzma
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from collections import Counter
import itertools


class DeepAnalyzer:
    """
    In-depth analysis engine that leaves no stone unturned.
    Analyzes files at byte level, entropy, patterns, and beyond.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = config.get('output_directory', 'output') if config else 'output'
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.findings = []
        self.flags_found = []
        self.suspicious_items = []
        self.decoded_data = []
        
        # Flag patterns - comprehensive
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}',
            r'OSCTF\{[^}]+\}',
            r'cyberhunt\{[^}]+\}',
            r'DCH\{[^}]+\}',
            r'digitalcyberhunt\{[^}]+\}',
            r'DUCTF\{[^}]+\}',
            r'CSAW\{[^}]+\}',
            r'SECCON\{[^}]+\}',
            r'hxp\{[^}]+\}',
        ]
        
        # Encoding patterns to detect
        self.encoding_patterns = {
            'base64': r'^[A-Za-z0-9+/]{4,}={0,2}$',
            'base32': r'^[A-Z2-7]{8,}={0,6}$',
            'base16': r'^[0-9A-Fa-f]{2,}$',
            'binary': r'^[01]{8,}$',
            'octal': r'^[0-7]{3,}(?:\s[0-7]{3,})*$',
            'decimal': r'^\d{1,3}(?:\s\d{1,3})+$',
            'url_encoded': r'%[0-9A-Fa-f]{2}',
            'unicode_escape': r'\\u[0-9A-Fa-f]{4}',
            'hex_escape': r'\\x[0-9A-Fa-f]{2}',
        }
        
        # File signatures (magic bytes)
        self.file_signatures = {
            b'\x89PNG\r\n\x1a\n': ('PNG', 'png'),
            b'\xff\xd8\xff': ('JPEG', 'jpg'),
            b'GIF87a': ('GIF87', 'gif'),
            b'GIF89a': ('GIF89', 'gif'),
            b'%PDF': ('PDF', 'pdf'),
            b'PK\x03\x04': ('ZIP', 'zip'),
            b'PK\x05\x06': ('ZIP_empty', 'zip'),
            b'\x1f\x8b': ('GZIP', 'gz'),
            b'BZh': ('BZIP2', 'bz2'),
            b'\xfd7zXZ': ('XZ', 'xz'),
            b'Rar!\x1a\x07': ('RAR', 'rar'),
            b'7z\xbc\xaf\x27\x1c': ('7Z', '7z'),
            b'\x7fELF': ('ELF', 'elf'),
            b'MZ': ('PE/DOS', 'exe'),
            b'\xca\xfe\xba\xbe': ('Mach-O', 'macho'),
            b'\xce\xfa\xed\xfe': ('Mach-O_32', 'macho'),
            b'\xcf\xfa\xed\xfe': ('Mach-O_64', 'macho'),
            b'RIFF': ('RIFF', 'riff'),
            b'OggS': ('OGG', 'ogg'),
            b'fLaC': ('FLAC', 'flac'),
            b'ID3': ('MP3', 'mp3'),
            b'\x00\x00\x00\x18ftypmp4': ('MP4', 'mp4'),
            b'\x00\x00\x00\x1cftypM4V': ('M4V', 'm4v'),
            b'SQLite format 3': ('SQLite', 'db'),
        }
    
    # ==================== CORE ANALYSIS ====================
    
    def analyze(self, filepath: str, depth: int = 0, max_depth: int = 10) -> Dict:
        """
        Deep recursive analysis of a file
        """
        if depth > max_depth:
            return {'error': 'Max recursion depth reached'}
        
        indent = "  " * depth
        print(f"\n{indent}[DEEP] Analyzing: {os.path.basename(filepath)} (depth={depth})")
        print(f"{indent}{'='*60}")
        
        results = {
            'filepath': filepath,
            'depth': depth,
            'basic_info': {},
            'hex_analysis': {},
            'string_analysis': {},
            'encoding_analysis': {},
            'entropy_analysis': {},
            'pattern_analysis': {},
            'embedded_files': [],
            'flags_found': [],
            'decoded_outputs': [],
            'recursive_findings': []
        }
        
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}
        
        # 1. Basic file info
        results['basic_info'] = self._analyze_basic_info(filepath, indent)
        
        # 2. Read raw data
        with open(filepath, 'rb') as f:
            raw_data = f.read()
        
        # 3. Hex and byte-level analysis
        results['hex_analysis'] = self._analyze_hex(raw_data, indent)
        
        # 4. String extraction and analysis
        results['string_analysis'] = self._analyze_strings(raw_data, filepath, indent)
        
        # 5. Entropy analysis
        results['entropy_analysis'] = self._analyze_entropy(raw_data, indent)
        
        # 6. Detect and decode encodings
        results['encoding_analysis'] = self._analyze_encodings(raw_data, filepath, indent)
        
        # 7. Search for embedded files
        results['embedded_files'] = self._find_embedded_files(raw_data, filepath, indent)
        
        # 8. Pattern analysis
        results['pattern_analysis'] = self._analyze_patterns(raw_data, indent)
        
        # 9. Collect all flags found
        results['flags_found'] = self.flags_found.copy()
        
        # 10. Recursively analyze extracted/decoded files
        for item in results['encoding_analysis'].get('decoded_files', []):
            if os.path.exists(item):
                print(f"\n{indent}[RECURSIVE] Analyzing decoded file: {item}")
                sub_results = self.analyze(item, depth + 1, max_depth)
                results['recursive_findings'].append(sub_results)
        
        for item in results['embedded_files']:
            if isinstance(item, dict) and item.get('extracted_path'):
                print(f"\n{indent}[RECURSIVE] Analyzing extracted file: {item['extracted_path']}")
                sub_results = self.analyze(item['extracted_path'], depth + 1, max_depth)
                results['recursive_findings'].append(sub_results)
        
        return results
    
    # ==================== BASIC INFO ====================
    
    def _analyze_basic_info(self, filepath: str, indent: str) -> Dict:
        """Get comprehensive basic file information"""
        print(f"{indent}[1/8] Basic Info Analysis...")
        
        info = {
            'filename': os.path.basename(filepath),
            'size': os.path.getsize(filepath),
            'extension': Path(filepath).suffix,
        }
        
        # File magic
        with open(filepath, 'rb') as f:
            header = f.read(32)
        
        info['magic_bytes'] = header[:16].hex()
        
        for sig, (name, ext) in self.file_signatures.items():
            if header.startswith(sig):
                info['detected_type'] = name
                info['real_extension'] = ext
                
                # Check extension mismatch
                if info['extension'].lower().strip('.') != ext:
                    msg = f"EXTENSION MISMATCH: File is {name} but has extension {info['extension']}"
                    print(f"{indent}    [!] {msg}")
                    self.suspicious_items.append(msg)
                    info['extension_mismatch'] = True
                break
        
        # File hash
        with open(filepath, 'rb') as f:
            data = f.read()
        info['md5'] = hashlib.md5(data).hexdigest()
        info['sha256'] = hashlib.sha256(data).hexdigest()
        
        print(f"{indent}    Size: {info['size']} bytes")
        print(f"{indent}    Type: {info.get('detected_type', 'Unknown')}")
        print(f"{indent}    MD5: {info['md5']}")
        
        return info
    
    # ==================== HEX ANALYSIS ====================
    
    def _analyze_hex(self, data: bytes, indent: str) -> Dict:
        """Deep hex/byte level analysis"""
        print(f"{indent}[2/8] Hex/Byte Analysis...")
        
        analysis = {
            'header_hex': data[:64].hex(),
            'footer_hex': data[-64:].hex() if len(data) > 64 else data.hex(),
            'null_bytes': data.count(b'\x00'),
            'printable_ratio': sum(1 for b in data if 32 <= b < 127) / len(data) if data else 0,
            'anomalies': []
        }
        
        # Check for hidden data after file end markers
        end_markers = {
            'PNG': b'IEND\xaeB`\x82',
            'JPEG': b'\xff\xd9',
            'GIF': b'\x00;',
            'ZIP': b'PK\x05\x06',
        }
        
        for fmt, marker in end_markers.items():
            pos = data.find(marker)
            if pos != -1:
                remaining = len(data) - pos - len(marker)
                if remaining > 10:  # More than 10 bytes after end marker
                    msg = f"Found {remaining} bytes AFTER {fmt} end marker!"
                    print(f"{indent}    [!] {msg}")
                    analysis['anomalies'].append(msg)
                    
                    # Extract hidden data
                    hidden = data[pos + len(marker):]
                    hidden_path = os.path.join(self.output_dir, 'hidden_after_eof.bin')
                    with open(hidden_path, 'wb') as f:
                        f.write(hidden)
                    print(f"{indent}    [+] Extracted hidden data to: {hidden_path}")
                    analysis['hidden_data_path'] = hidden_path
                    
                    # Search for flags in hidden data
                    self._search_flags_in_data(hidden, f"hidden data after {fmt}")
        
        # Check for steganography indicators in LSB
        if len(data) > 1000:
            lsb_bits = ''.join(str(b & 1) for b in data[:1000])
            # Check if LSB looks like ASCII
            try:
                lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits)-7, 8))
                if sum(32 <= b < 127 for b in lsb_bytes) > len(lsb_bytes) * 0.7:
                    msg = "LSB data appears to contain text - possible steganography!"
                    print(f"{indent}    [!] {msg}")
                    analysis['lsb_text'] = lsb_bytes.decode('ascii', errors='ignore')
                    self._search_flags_in_data(lsb_bytes, "LSB extraction")
            except:
                pass
        
        return analysis
    
    # ==================== STRING ANALYSIS ====================
    
    def _analyze_strings(self, data: bytes, filepath: str, indent: str) -> Dict:
        """Deep string extraction and analysis"""
        print(f"{indent}[3/8] String Analysis...")
        
        analysis = {
            'ascii_strings': [],
            'unicode_strings': [],
            'interesting_strings': [],
            'urls': [],
            'emails': [],
            'ips': [],
            'paths': [],
            'base64_candidates': [],
            'hex_strings': [],
        }
        
        # Extract ASCII strings (min length 4)
        ascii_pattern = rb'[\x20-\x7e]{4,}'
        analysis['ascii_strings'] = [m.decode('ascii') for m in re.findall(ascii_pattern, data)]
        
        # Extract Unicode strings
        try:
            text = data.decode('utf-16-le', errors='ignore')
            unicode_pattern = r'[\x20-\x7e]{4,}'
            analysis['unicode_strings'] = re.findall(unicode_pattern, text)
        except:
            pass
        
        all_strings = analysis['ascii_strings'] + analysis['unicode_strings']
        
        print(f"{indent}    Found {len(analysis['ascii_strings'])} ASCII strings")
        print(f"{indent}    Found {len(analysis['unicode_strings'])} Unicode strings")
        
        # Analyze each string
        for s in all_strings:
            # Search for flags
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, s, re.IGNORECASE)
                for m in matches:
                    if m not in self.flags_found:
                        self.flags_found.append(m)
                        print(f"{indent}    [FLAG] {m}")
            
            # URLs
            if re.match(r'https?://', s):
                analysis['urls'].append(s)
            
            # Emails
            if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s):
                analysis['emails'].append(s)
            
            # IPs
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                analysis['ips'].append(s)
            
            # File paths
            if re.match(r'[/\\][\w/\\.-]+', s) or re.match(r'[A-Z]:\\', s):
                analysis['paths'].append(s)
            
            # Base64 candidates
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
                analysis['base64_candidates'].append(s)
            
            # Hex strings
            if re.match(r'^[0-9a-fA-F]{16,}$', s):
                analysis['hex_strings'].append(s)
            
            # Interesting keywords
            keywords = ['flag', 'password', 'secret', 'key', 'hidden', 'admin', 
                       'root', 'token', 'credential', 'private', 'encrypt', 'decrypt']
            for kw in keywords:
                if kw in s.lower():
                    analysis['interesting_strings'].append(s)
                    break
        
        if analysis['interesting_strings']:
            print(f"{indent}    [!] Found {len(analysis['interesting_strings'])} interesting strings")
        
        return analysis
    
    # ==================== ENTROPY ANALYSIS ====================
    
    def _analyze_entropy(self, data: bytes, indent: str) -> Dict:
        """Analyze entropy to detect encryption/compression/hidden data"""
        print(f"{indent}[4/8] Entropy Analysis...")
        
        import math
        
        def calc_entropy(d: bytes) -> float:
            if not d:
                return 0
            freq = Counter(d)
            probs = [count / len(d) for count in freq.values()]
            return -sum(p * math.log2(p) for p in probs if p > 0)
        
        analysis = {
            'overall_entropy': calc_entropy(data),
            'block_entropies': [],
            'high_entropy_regions': [],
            'low_entropy_regions': []
        }
        
        print(f"{indent}    Overall entropy: {analysis['overall_entropy']:.4f} bits/byte")
        
        # Interpret entropy
        if analysis['overall_entropy'] > 7.5:
            print(f"{indent}    [!] Very high entropy - likely encrypted or compressed")
        elif analysis['overall_entropy'] > 6.5:
            print(f"{indent}    [!] High entropy - possibly compressed")
        elif analysis['overall_entropy'] < 4.0:
            print(f"{indent}    [!] Low entropy - possibly text or sparse data")
        
        # Block-wise entropy analysis
        block_size = 256
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) >= 64:  # Minimum block size
                ent = calc_entropy(block)
                analysis['block_entropies'].append((i, ent))
                
                if ent > 7.8:
                    analysis['high_entropy_regions'].append((i, i+block_size, ent))
                elif ent < 2.0:
                    analysis['low_entropy_regions'].append((i, i+block_size, ent))
        
        if analysis['high_entropy_regions']:
            print(f"{indent}    Found {len(analysis['high_entropy_regions'])} high-entropy regions")
        if analysis['low_entropy_regions']:
            print(f"{indent}    Found {len(analysis['low_entropy_regions'])} low-entropy regions")
        
        return analysis
    
    # ==================== ENCODING ANALYSIS ====================
    
    def _analyze_encodings(self, data: bytes, filepath: str, indent: str) -> Dict:
        """Detect and decode various encodings"""
        print(f"{indent}[5/8] Encoding Detection & Decoding...")
        
        analysis = {
            'detected_encodings': [],
            'decoded_data': [],
            'decoded_files': []
        }
        
        # Try to interpret as text
        try:
            text = data.decode('utf-8', errors='ignore').strip()
        except:
            text = data.decode('latin-1', errors='ignore').strip()
        
        # Multi-layer decoding - keep decoding until nothing changes
        max_iterations = 10
        current_data = text
        iteration = 0
        
        while iteration < max_iterations:
            decoded, encoding_used = self._try_decode(current_data)
            
            if decoded == current_data or not encoding_used:
                break
            
            print(f"{indent}    [+] Decoded {encoding_used}")
            analysis['detected_encodings'].append(encoding_used)
            analysis['decoded_data'].append({
                'encoding': encoding_used,
                'result': decoded[:200] + '...' if len(decoded) > 200 else decoded
            })
            
            # Search for flags in decoded data
            self._search_flags_in_data(decoded.encode() if isinstance(decoded, str) else decoded, encoding_used)
            
            current_data = decoded
            iteration += 1
        
        # Save final decoded result if different from original
        if iteration > 0:
            final_path = os.path.join(self.output_dir, f'{os.path.basename(filepath)}_decoded.txt')
            with open(final_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(current_data if isinstance(current_data, str) else current_data.decode('utf-8', errors='ignore'))
            print(f"{indent}    [+] Saved decoded data to: {final_path}")
            analysis['decoded_files'].append(final_path)
        
        # Check for hex dump format
        if re.match(r'^[0-9a-fA-F\s]+$', text):
            try:
                binary = bytes.fromhex(text.replace(' ', '').replace('\n', ''))
                hex_path = os.path.join(self.output_dir, f'{os.path.basename(filepath)}_fromhex.bin')
                with open(hex_path, 'wb') as f:
                    f.write(binary)
                print(f"{indent}    [+] Converted hex to binary: {hex_path}")
                analysis['decoded_files'].append(hex_path)
                self._search_flags_in_data(binary, "hex decode")
            except:
                pass
        
        return analysis
    
    def _try_decode(self, data: str) -> Tuple[str, Optional[str]]:
        """Try various decodings on data"""
        
        # Base64
        try:
            if re.match(r'^[A-Za-z0-9+/\s]+=*$', data.strip()):
                decoded = base64.b64decode(data.strip()).decode('utf-8', errors='ignore')
                if decoded and sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded, 'base64'
        except:
            pass
        
        # Base32
        try:
            if re.match(r'^[A-Z2-7\s]+=*$', data.strip().upper()):
                decoded = base64.b32decode(data.strip().upper()).decode('utf-8', errors='ignore')
                if decoded and sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded, 'base32'
        except:
            pass
        
        # Hex
        try:
            if re.match(r'^[0-9a-fA-F\s]+$', data.strip()):
                clean = data.strip().replace(' ', '').replace('\n', '')
                if len(clean) % 2 == 0:
                    decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                    if decoded and sum(c.isprintable() for c in decoded) > len(decoded) * 0.7:
                        return decoded, 'hex'
        except:
            pass
        
        # Binary
        try:
            if re.match(r'^[01\s]+$', data.strip()):
                clean = data.strip().replace(' ', '').replace('\n', '')
                if len(clean) % 8 == 0:
                    decoded = ''.join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
                    if decoded and sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                        return decoded, 'binary'
        except:
            pass
        
        # ROT13
        try:
            import codecs
            decoded = codecs.decode(data, 'rot_13')
            # Check if it looks more like English
            if self._looks_like_english(decoded) > self._looks_like_english(data):
                return decoded, 'rot13'
        except:
            pass
        
        # URL decode
        try:
            if '%' in data:
                from urllib.parse import unquote
                decoded = unquote(data)
                if decoded != data:
                    return decoded, 'url_decode'
        except:
            pass
        
        # Unicode escape
        try:
            if '\\u' in data or '\\x' in data:
                decoded = data.encode().decode('unicode_escape')
                if decoded != data:
                    return decoded, 'unicode_escape'
        except:
            pass
        
        return data, None
    
    def _looks_like_english(self, text: str) -> float:
        """Score how much text looks like English"""
        common_words = ['the', 'and', 'is', 'to', 'of', 'in', 'for', 'flag', 'ctf']
        score = sum(1 for w in common_words if w in text.lower())
        return score
    
    # ==================== EMBEDDED FILE DETECTION ====================
    
    def _find_embedded_files(self, data: bytes, filepath: str, indent: str) -> List[Dict]:
        """Find and extract embedded files"""
        print(f"{indent}[6/8] Embedded File Detection...")
        
        embedded = []
        
        # Search for file signatures at any offset
        for sig, (name, ext) in self.file_signatures.items():
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                
                if pos > 0:  # Embedded (not at start)
                    print(f"{indent}    [!] Found embedded {name} at offset {pos}")
                    
                    # Extract from this position
                    extracted_data = data[pos:]
                    extract_path = os.path.join(self.output_dir, f'embedded_{pos}.{ext}')
                    
                    with open(extract_path, 'wb') as f:
                        f.write(extracted_data)
                    
                    print(f"{indent}    [+] Extracted to: {extract_path}")
                    embedded.append({
                        'type': name,
                        'offset': pos,
                        'extracted_path': extract_path
                    })
                    
                    self._search_flags_in_data(extracted_data, f"embedded {name}")
                
                offset = pos + 1
        
        # Try decompression
        decompress_methods = [
            ('zlib', lambda d: zlib.decompress(d)),
            ('gzip', lambda d: gzip.decompress(d)),
            ('bz2', lambda d: bz2.decompress(d)),
            ('lzma', lambda d: lzma.decompress(d)),
        ]
        
        for name, decompress_fn in decompress_methods:
            # Try at different offsets
            for offset in [0, 2, 4, 8, 10]:
                if offset >= len(data):
                    break
                try:
                    decompressed = decompress_fn(data[offset:])
                    if len(decompressed) > 10:
                        decomp_path = os.path.join(self.output_dir, f'decompressed_{name}_{offset}.bin')
                        with open(decomp_path, 'wb') as f:
                            f.write(decompressed)
                        print(f"{indent}    [+] Decompressed with {name} (offset {offset}): {decomp_path}")
                        embedded.append({
                            'type': f'{name}_compressed',
                            'offset': offset,
                            'extracted_path': decomp_path
                        })
                        self._search_flags_in_data(decompressed, f"{name} decompression")
                        break
                except:
                    pass
        
        return embedded
    
    # ==================== PATTERN ANALYSIS ====================
    
    def _analyze_patterns(self, data: bytes, indent: str) -> Dict:
        """Analyze byte patterns for anomalies and hidden data"""
        print(f"{indent}[7/8] Pattern Analysis...")
        
        analysis = {
            'repeating_patterns': [],
            'xor_key_candidates': [],
            'caesar_candidates': [],
            'null_regions': [],
        }
        
        # Find repeating patterns
        for length in [4, 8, 16]:
            patterns = Counter()
            for i in range(len(data) - length):
                pattern = data[i:i+length]
                patterns[pattern] += 1
            
            for pattern, count in patterns.most_common(5):
                if count > 10 and pattern != b'\x00' * length:
                    analysis['repeating_patterns'].append({
                        'length': length,
                        'pattern': pattern.hex(),
                        'count': count
                    })
        
        # XOR key detection - frequency analysis
        if len(data) > 100:
            byte_freq = Counter(data)
            # Most common byte might be XOR of space (0x20) or null (0x00)
            most_common = byte_freq.most_common(3)
            
            for byte_val, count in most_common:
                if count > len(data) * 0.1:  # At least 10% of file
                    # Try XOR with this byte
                    xor_key = byte_val ^ ord(' ')  # Assume XOR of space
                    if 0x20 <= xor_key <= 0x7e:  # Printable key
                        analysis['xor_key_candidates'].append({
                            'key': hex(xor_key),
                            'char': chr(xor_key),
                            'reasoning': 'frequency analysis'
                        })
                    
                    # Try XOR with common characters
                    for target in [0x00, 0x20, ord('e'), ord('E')]:
                        key = byte_val ^ target
                        if key != 0:
                            # Test XOR
                            decrypted = bytes([b ^ key for b in data[:100]])
                            printable = sum(1 for b in decrypted if 32 <= b < 127)
                            if printable > 70:
                                analysis['xor_key_candidates'].append({
                                    'key': hex(key),
                                    'preview': decrypted.decode('ascii', errors='ignore')[:50]
                                })
        
        # Find null byte regions (potential hidden data boundaries)
        null_start = None
        for i, b in enumerate(data):
            if b == 0:
                if null_start is None:
                    null_start = i
            else:
                if null_start is not None and i - null_start > 16:
                    analysis['null_regions'].append((null_start, i))
                null_start = None
        
        if analysis['xor_key_candidates']:
            print(f"{indent}    Found {len(analysis['xor_key_candidates'])} potential XOR keys")
        
        return analysis
    
    # ==================== FLAG SEARCH ====================
    
    def _search_flags_in_data(self, data: bytes, source: str):
        """Search for flags in binary data"""
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = data.decode('latin-1', errors='ignore')
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if m not in self.flags_found:
                    self.flags_found.append(m)
                    print(f"    [FLAG FOUND in {source}] {m}")
    
    # ==================== SUMMARY ====================
    
    def get_summary(self) -> str:
        """Get analysis summary"""
        lines = [
            "=" * 60,
            "DEEP ANALYSIS SUMMARY",
            "=" * 60,
            f"Flags Found: {len(self.flags_found)}",
            f"Suspicious Items: {len(self.suspicious_items)}",
            f"Decoded Data Items: {len(self.decoded_data)}",
        ]
        
        if self.flags_found:
            lines.append("\nFLAGS:")
            for flag in self.flags_found:
                lines.append(f"  [FLAG] {flag}")
        
        if self.suspicious_items:
            lines.append("\nSUSPICIOUS ITEMS:")
            for item in self.suspicious_items:
                lines.append(f"  [!] {item}")
        
        return '\n'.join(lines)
