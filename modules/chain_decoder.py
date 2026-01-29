#!/usr/bin/env python3
"""
Chain Decoder - Automatically decode nested/chained encodings from files
Author: Prudhvi (CTFHunter)
Version: 2.2.0

Handles: Image with Base64 → Base32 → Hex → Flag (any chain!)
"""

import re
import os
import base64
import binascii
import subprocess
import codecs
from typing import Dict, List, Optional, Tuple


class ChainDecoder:
    """Automatically decode nested/chained encodings from files"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.max_depth = 10  # Maximum decoding depth
        self.results = {
            'original_data': None,
            'decoding_chain': [],
            'final_result': None,
            'flags_found': [],
            'all_decoded': []
        }
    
    def analyze_file(self, filepath: str, flag_format: str = "flag{}") -> Dict:
        """Extract and decode data from any file"""
        print(f"\n🔗 Chain Decoder: {os.path.basename(filepath)}")
        print(f"   Looking for nested encodings...\n")
        
        if not os.path.exists(filepath):
            print(f"  ❌ File not found")
            return self.results
        
        # Extract potential encoded data from file
        encoded_strings = self._extract_encoded_data(filepath)
        
        print(f"  📝 Found {len(encoded_strings)} potential encoded string(s)\n")
        
        # Try to decode each string
        for i, data in enumerate(encoded_strings[:20]):  # Limit to 20
            if len(data) < 8:  # Skip very short strings
                continue
                
            print(f"  🔄 Analyzing string {i+1} ({len(data)} chars)...")
            chain = self._decode_chain(data, flag_format)
            
            if chain and len(chain) > 1:
                self.results['decoding_chain'].append({
                    'original': data[:100],
                    'chain': chain,
                    'final': chain[-1]['decoded']
                })
                
                # Check for flags
                self._check_for_flags(chain[-1]['decoded'], flag_format)
        
        self._print_results()
        return self.results
    
    def analyze_string(self, data: str, flag_format: str = "flag{}") -> Dict:
        """Decode a string through multiple encoding layers"""
        print(f"\n🔗 Chain Decoder")
        print(f"   Input: {data[:80]}{'...' if len(data) > 80 else ''}\n")
        
        self.results['original_data'] = data
        
        chain = self._decode_chain(data, flag_format)
        
        if chain:
            self.results['decoding_chain'] = chain
            self.results['final_result'] = chain[-1]['decoded'] if chain else data
            self._check_for_flags(self.results['final_result'], flag_format)
        
        self._print_results()
        return self.results
    
    def _extract_encoded_data(self, filepath: str) -> List[str]:
        """Extract potential encoded strings from file"""
        encoded_strings = []
        
        # 1. Run strings command
        try:
            result = subprocess.run(
                ['strings', '-n', '10', filepath],
                capture_output=True, text=True, timeout=30
            )
            strings_output = result.stdout.split('\n')
            
            for s in strings_output:
                s = s.strip()
                if self._looks_encoded(s):
                    encoded_strings.append(s)
        except:
            pass
        
        # 2. Read file directly for text files
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Try as text
            text_content = content.decode('utf-8', errors='ignore')
            
            # Look for Base64 patterns
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            b64_matches = re.findall(b64_pattern, text_content)
            encoded_strings.extend(b64_matches)
            
            # Look for Hex patterns
            hex_pattern = r'(?:0x)?[A-Fa-f0-9]{20,}'
            hex_matches = re.findall(hex_pattern, text_content)
            encoded_strings.extend(hex_matches)
            
            # Look for Base32 patterns
            b32_pattern = r'[A-Z2-7]{20,}={0,6}'
            b32_matches = re.findall(b32_pattern, text_content)
            encoded_strings.extend(b32_matches)
            
            # Look in comments (<!-- -->)
            comment_pattern = r'<!--\s*([^>]+)\s*-->'
            comments = re.findall(comment_pattern, text_content)
            for comment in comments:
                if self._looks_encoded(comment):
                    encoded_strings.append(comment.strip())
            
            # Check EXIF data
            self._extract_from_exif(filepath, encoded_strings)
            
        except:
            pass
        
        # 3. Check for data after file end markers
        self._extract_appended_data(filepath, encoded_strings)
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in encoded_strings:
            if s not in seen and len(s) >= 8:
                seen.add(s)
                unique.append(s)
        
        return unique
    
    def _extract_from_exif(self, filepath: str, results: List[str]):
        """Extract encoded data from EXIF metadata"""
        try:
            result = subprocess.run(
                ['exiftool', '-s', '-s', '-s', '-Comment', '-UserComment', 
                 '-ImageDescription', '-Artist', '-Copyright', filepath],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and self._looks_encoded(line):
                    results.append(line)
        except:
            pass
    
    def _extract_appended_data(self, filepath: str, results: List[str]):
        """Extract data appended after file end markers"""
        markers = {
            b'\xff\xd9': 'JPEG',  # JPEG end
            b'\x49\x45\x4e\x44\xae\x42\x60\x82': 'PNG',  # PNG IEND
            b'%%EOF': 'PDF',
        }
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            for marker, ftype in markers.items():
                pos = content.rfind(marker)
                if pos != -1 and pos < len(content) - len(marker) - 5:
                    appended = content[pos + len(marker):]
                    text = appended.decode('utf-8', errors='ignore').strip()
                    if text and len(text) > 5:
                        results.append(text)
        except:
            pass
    
    def _looks_encoded(self, data: str) -> bool:
        """Check if string looks like it's encoded"""
        if not data or len(data) < 8:
            return False
        
        # Base64 pattern
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
            return True
        
        # Base32 pattern
        if re.match(r'^[A-Z2-7]+=*$', data):
            return True
        
        # Hex pattern
        if re.match(r'^(0x)?[A-Fa-f0-9]+$', data):
            return True
        
        # Binary pattern
        if re.match(r'^[01\s]+$', data) and len(data) >= 8:
            return True
        
        return False
    
    def _decode_chain(self, data: str, flag_format: str, depth: int = 0) -> List[Dict]:
        """Recursively decode through encoding chain"""
        if depth >= self.max_depth:
            return []
        
        chain = []
        current_data = data.strip()
        
        while depth < self.max_depth:
            # Try all decoders
            decoded, encoding_type = self._try_all_decodings(current_data)
            
            if decoded and decoded != current_data:
                chain.append({
                    'depth': len(chain) + 1,
                    'encoding': encoding_type,
                    'input': current_data[:100],
                    'decoded': decoded
                })
                
                # Check if we found a flag
                if self._has_flag(decoded, flag_format):
                    break
                
                # Check if result looks like it's still encoded
                if self._looks_encoded(decoded):
                    current_data = decoded
                    depth += 1
                else:
                    # Result is plaintext, we're done
                    break
            else:
                # No more decoding possible
                break
        
        return chain
    
    def _try_all_decodings(self, data: str) -> Tuple[Optional[str], str]:
        """Try all decoding methods and return best result"""
        decoders = [
            ('Base64', self._decode_base64),
            ('Base64-URLSafe', self._decode_base64_url),
            ('Base32', self._decode_base32),
            ('Hexadecimal', self._decode_hex),
            ('Binary', self._decode_binary),
            ('ROT13', self._decode_rot13),
            ('URL Encoding', self._decode_url),
            ('Base85', self._decode_base85),
            ('Octal', self._decode_octal),
            ('Decimal ASCII', self._decode_decimal),
            ('Reversed', self._decode_reversed),
        ]
        
        for name, decoder in decoders:
            try:
                result = decoder(data)
                if result and self._is_valid_result(result):
                    return result, name
            except:
                pass
        
        return None, ''
    
    def _decode_base64(self, data: str) -> Optional[str]:
        """Decode Base64"""
        clean = re.sub(r'\s', '', data)
        
        # Check pattern
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', clean):
            return None
        
        # Fix padding
        padding = len(clean) % 4
        if padding:
            clean += '=' * (4 - padding)
        
        try:
            decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            return None
    
    def _decode_base64_url(self, data: str) -> Optional[str]:
        """Decode URL-safe Base64"""
        clean = re.sub(r'\s', '', data)
        
        if not re.match(r'^[A-Za-z0-9_-]+={0,2}$', clean):
            return None
        
        try:
            decoded = base64.urlsafe_b64decode(clean + '==').decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            return None
    
    def _decode_base32(self, data: str) -> Optional[str]:
        """Decode Base32"""
        clean = re.sub(r'\s', '', data.upper())
        
        if not re.match(r'^[A-Z2-7]+=*$', clean):
            return None
        
        # Fix padding
        padding = len(clean) % 8
        if padding:
            clean += '=' * (8 - padding)
        
        try:
            decoded = base64.b32decode(clean).decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            return None
    
    def _decode_hex(self, data: str) -> Optional[str]:
        """Decode Hexadecimal"""
        clean = re.sub(r'\s', '', data)
        clean = re.sub(r'^(0x|\\x)', '', clean, flags=re.IGNORECASE)
        clean = re.sub(r'\\x', '', clean)
        
        if not re.match(r'^[0-9A-Fa-f]+$', clean):
            return None
        
        if len(clean) % 2 != 0:
            return None
        
        try:
            decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            return None
    
    def _decode_binary(self, data: str) -> Optional[str]:
        """Decode Binary"""
        clean = re.sub(r'\s', '', data)
        
        if not re.match(r'^[01]+$', clean):
            return None
        
        if len(clean) % 8 != 0:
            clean = clean.zfill((len(clean) // 8 + 1) * 8)
        
        try:
            decoded = ''.join(
                chr(int(clean[i:i+8], 2))
                for i in range(0, len(clean), 8)
            )
            return decoded if decoded else None
        except:
            return None
    
    def _decode_rot13(self, data: str) -> Optional[str]:
        """Decode ROT13"""
        try:
            decoded = codecs.decode(data, 'rot_13')
            return decoded
        except:
            return None
    
    def _decode_url(self, data: str) -> Optional[str]:
        """Decode URL encoding"""
        if '%' not in data:
            return None
        
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(data)
            return decoded if decoded != data else None
        except:
            return None
    
    def _decode_base85(self, data: str) -> Optional[str]:
        """Decode Base85"""
        try:
            decoded = base64.a85decode(data).decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            pass
        
        try:
            decoded = base64.b85decode(data).decode('utf-8', errors='ignore')
            return decoded if decoded else None
        except:
            return None
    
    def _decode_octal(self, data: str) -> Optional[str]:
        """Decode Octal"""
        if not re.match(r'^[\s\\]*[0-7]{2,3}([\s\\]+[0-7]{2,3})+$', data):
            return None
        
        try:
            octal_values = re.findall(r'[0-7]{2,3}', data)
            decoded = ''.join(chr(int(o, 8)) for o in octal_values)
            return decoded if decoded else None
        except:
            return None
    
    def _decode_decimal(self, data: str) -> Optional[str]:
        """Decode Decimal ASCII"""
        if not re.match(r'^[\s,]*\d{1,3}([\s,]+\d{1,3})+$', data.strip()):
            return None
        
        try:
            values = [int(d) for d in re.findall(r'\d+', data)]
            if all(0 <= v <= 127 for v in values):
                decoded = ''.join(chr(v) for v in values)
                return decoded if decoded else None
        except:
            pass
        return None
    
    def _decode_reversed(self, data: str) -> Optional[str]:
        """Try reversing the string"""
        reversed_data = data[::-1]
        
        # Check if reversed looks like flag or encoded
        if self._has_flag(reversed_data, "flag{}") or self._looks_encoded(reversed_data):
            return reversed_data
        return None
    
    def _is_valid_result(self, text: str) -> bool:
        """Check if decoded result is valid"""
        if not text:
            return False
        
        # Check printable ratio
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if printable / len(text) < 0.7:
            return False
        
        return True
    
    def _has_flag(self, text: str, flag_format: str) -> bool:
        """Check if text contains a flag"""
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        patterns = [
            rf'{re.escape(prefix)}\{{[^}}]+\}}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _check_for_flags(self, text: str, flag_format: str):
        """Extract flags from text"""
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        patterns = [
            rf'{re.escape(prefix)}\{{[^}}]+\}}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Za-z0-9_]+\{[^}]+\}',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags_found']:
                    self.results['flags_found'].append(match)
    
    def _print_results(self):
        """Print decoding results"""
        if not self.results['decoding_chain'] and not self.results['flags_found']:
            print("  ℹ️  No encoded data chains found")
            return
        
        # Print chains
        chains = self.results['decoding_chain']
        if isinstance(chains, list) and chains:
            # Check if it's a list of chains (from file) or single chain (from string)
            if isinstance(chains[0], dict) and 'chain' in chains[0]:
                # Multiple chains from file
                for i, chain_data in enumerate(chains):
                    print(f"\n  📦 Chain {i+1}:")
                    for step in chain_data['chain']:
                        print(f"     {step['depth']}. {step['encoding']}: {step['decoded'][:80]}")
            else:
                # Single chain from string
                print(f"\n  📦 Decoding Chain:")
                for step in chains:
                    print(f"     {step['depth']}. {step['encoding']}")
                    print(f"        → {step['decoded'][:100]}")
        
        # Print flags
        if self.results['flags_found']:
            print(f"\n  🚩 FLAGS FOUND:")
            for flag in self.results['flags_found']:
                print(f"     ⭐ {flag}")
        
        # Print final result
        if self.results.get('final_result'):
            print(f"\n  ✅ Final Result: {self.results['final_result'][:200]}")
        
        print()


def decode_chain(data: str, flag_format: str = "flag{}") -> Dict:
    """Convenience function for chain decoding"""
    decoder = ChainDecoder()
    return decoder.analyze_string(data, flag_format)


def decode_file(filepath: str, flag_format: str = "flag{}") -> Dict:
    """Convenience function for file chain decoding"""
    decoder = ChainDecoder()
    return decoder.analyze_file(filepath, flag_format)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isfile(arg):
            decode_file(arg)
        else:
            decode_chain(arg)
    else:
        # Test: Base64 → Base32 → Hex → Flag
        # flag{nested_encoding}
        # → Hex: 666c61677b6e65737465645f656e636f64696e677d
        # → Base32: MZWGCZ33NZXW4Z3OMFXGIYLTORZGC3DJNZTSA43FMNXWY===
        # → Base64: TVpXR0NaMzNOWlhXNFozT01GWEdJWUxUT1JaR0MzREpOWlRTQTQzRk1OWFdZPT09
        
        test = "TVpXR0NaMzNOWlhXNFozT01GWEdJWUxUT1JaR0MzREpOWlRTQTQzRk1OWFdZPT09"
        print("Testing nested encoding: Base64 → Base32 → Hex → Flag")
        decode_chain(test)
