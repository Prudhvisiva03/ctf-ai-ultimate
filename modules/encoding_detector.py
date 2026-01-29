#!/usr/bin/env python3
"""
Encoding Detector - Auto-detect and decode multiple encoding types
Author: Prudhvi (CTFHunter)
Version: 2.2.0
"""

import re
import base64
import binascii
import codecs
import urllib.parse
from typing import Dict, List, Tuple, Optional


class EncodingDetector:
    """Detect and decode various encoding types used in CTF challenges"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.results = {
            'detected_encodings': [],
            'decoded_values': [],
            'encoding_chain': [],
            'possible_flags': []
        }
    
    def analyze(self, data: str, flag_format: str = "flag{}") -> Dict:
        """Analyze data for various encodings"""
        print(f"\n🔤 Analyzing for encodings...")
        
        # Clean input
        data = data.strip()
        
        # Try all encoding detections
        self._detect_base64(data)
        self._detect_base32(data)
        self._detect_base16_hex(data)
        self._detect_binary(data)
        self._detect_octal(data)
        self._detect_decimal_ascii(data)
        self._detect_url_encoding(data)
        self._detect_rot13(data)
        self._detect_rot_all(data)
        self._detect_morse(data)
        self._detect_unicode_escape(data)
        self._detect_html_entities(data)
        self._detect_base58(data)
        self._detect_base85(data)
        self._detect_reversed(data)
        
        # Try recursive decoding
        self._recursive_decode(data, max_depth=5)
        
        # Search for flags in all decoded values
        self._search_flags(flag_format)
        
        self._print_results()
        return self.results
    
    def _add_result(self, encoding: str, original: str, decoded: str):
        """Add a detection result"""
        if decoded and decoded != original and len(decoded) > 2:
            self.results['detected_encodings'].append(encoding)
            self.results['decoded_values'].append({
                'encoding': encoding,
                'original': original[:100] + '...' if len(original) > 100 else original,
                'decoded': decoded[:500] if len(decoded) > 500 else decoded
            })
    
    def _detect_base64(self, data: str):
        """Detect and decode Base64"""
        # Standard Base64 pattern
        b64_pattern = r'^[A-Za-z0-9+/]+=*$'
        
        # Clean whitespace
        clean_data = re.sub(r'\s', '', data)
        
        if re.match(b64_pattern, clean_data) and len(clean_data) >= 4:
            try:
                # Check padding
                padding_needed = len(clean_data) % 4
                if padding_needed:
                    clean_data += '=' * (4 - padding_needed)
                
                decoded = base64.b64decode(clean_data).decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    self._add_result('Base64', data, decoded)
            except:
                pass
        
        # URL-safe Base64
        b64url_pattern = r'^[A-Za-z0-9_-]+=*$'
        if re.match(b64url_pattern, clean_data) and len(clean_data) >= 4:
            try:
                decoded = base64.urlsafe_b64decode(clean_data + '==').decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    self._add_result('Base64-URLSafe', data, decoded)
            except:
                pass
    
    def _detect_base32(self, data: str):
        """Detect and decode Base32"""
        b32_pattern = r'^[A-Z2-7]+=*$'
        clean_data = re.sub(r'\s', '', data.upper())
        
        if re.match(b32_pattern, clean_data) and len(clean_data) >= 8:
            try:
                # Fix padding
                padding_needed = len(clean_data) % 8
                if padding_needed:
                    clean_data += '=' * (8 - padding_needed)
                
                decoded = base64.b32decode(clean_data).decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    self._add_result('Base32', data, decoded)
            except:
                pass
    
    def _detect_base16_hex(self, data: str):
        """Detect and decode Hexadecimal"""
        # Remove common hex prefixes
        clean_data = re.sub(r'\s', '', data)
        clean_data = re.sub(r'^(0x|\\x)', '', clean_data, flags=re.IGNORECASE)
        clean_data = re.sub(r'\\x', '', clean_data)
        
        hex_pattern = r'^[0-9A-Fa-f]+$'
        
        if re.match(hex_pattern, clean_data) and len(clean_data) >= 4 and len(clean_data) % 2 == 0:
            try:
                decoded = bytes.fromhex(clean_data).decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    self._add_result('Hexadecimal', data, decoded)
            except:
                pass
    
    def _detect_binary(self, data: str):
        """Detect and decode Binary"""
        clean_data = re.sub(r'\s', '', data)
        binary_pattern = r'^[01]+$'
        
        if re.match(binary_pattern, clean_data) and len(clean_data) >= 8:
            try:
                # Ensure length is multiple of 8
                if len(clean_data) % 8 != 0:
                    clean_data = clean_data.zfill((len(clean_data) // 8 + 1) * 8)
                
                decoded = ''.join(
                    chr(int(clean_data[i:i+8], 2)) 
                    for i in range(0, len(clean_data), 8)
                )
                if decoded and self._is_printable(decoded):
                    self._add_result('Binary', data, decoded)
            except:
                pass
    
    def _detect_octal(self, data: str):
        """Detect and decode Octal"""
        # Pattern: space or backslash separated octal values
        octal_pattern = r'^[\s\\]*[0-7]{2,3}([\s\\]+[0-7]{2,3})+$'
        
        if re.match(octal_pattern, data):
            try:
                octal_values = re.findall(r'[0-7]{2,3}', data)
                decoded = ''.join(chr(int(o, 8)) for o in octal_values)
                if decoded and self._is_printable(decoded):
                    self._add_result('Octal', data, decoded)
            except:
                pass
    
    def _detect_decimal_ascii(self, data: str):
        """Detect and decode Decimal ASCII"""
        # Pattern: space/comma separated decimal values
        decimal_pattern = r'^[\s,]*\d{1,3}([\s,]+\d{1,3})+$'
        
        if re.match(decimal_pattern, data.strip()):
            try:
                decimal_values = re.findall(r'\d+', data)
                int_values = [int(d) for d in decimal_values]
                
                # Check if values are valid ASCII
                if all(0 <= v <= 127 for v in int_values):
                    decoded = ''.join(chr(v) for v in int_values)
                    if decoded and self._is_printable(decoded):
                        self._add_result('Decimal ASCII', data, decoded)
            except:
                pass
    
    def _detect_url_encoding(self, data: str):
        """Detect and decode URL encoding"""
        if '%' in data:
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    self._add_result('URL Encoding', data, decoded)
            except:
                pass
    
    def _detect_rot13(self, data: str):
        """Detect and decode ROT13"""
        try:
            decoded = codecs.decode(data, 'rot_13')
            # Check if it looks more readable than original
            if decoded != data and self._has_common_words(decoded):
                self._add_result('ROT13', data, decoded)
        except:
            pass
    
    def _detect_rot_all(self, data: str):
        """Try all ROT shifts (Caesar cipher)"""
        for shift in range(1, 26):
            if shift == 13:  # Already checked ROT13
                continue
            try:
                decoded = self._caesar_shift(data, shift)
                if self._has_common_words(decoded) or self._has_flag_pattern(decoded):
                    self._add_result(f'ROT{shift}/Caesar', data, decoded)
                    break  # Only report first match
            except:
                pass
    
    def _caesar_shift(self, text: str, shift: int) -> str:
        """Apply Caesar cipher shift"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    def _detect_morse(self, data: str):
        """Detect and decode Morse code"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '-----': '0', '': ' '
        }
        
        # Check if it looks like Morse code
        if re.match(r'^[\.\-\s/|]+$', data):
            try:
                # Split by word separators
                words = re.split(r'\s{2,}|/|\|', data)
                decoded_words = []
                
                for word in words:
                    letters = word.strip().split()
                    decoded_word = ''.join(morse_dict.get(l, '?') for l in letters)
                    decoded_words.append(decoded_word)
                
                decoded = ' '.join(decoded_words)
                if decoded and '?' not in decoded:
                    self._add_result('Morse Code', data, decoded)
            except:
                pass
    
    def _detect_unicode_escape(self, data: str):
        """Detect and decode Unicode escapes"""
        if '\\u' in data or '\\x' in data:
            try:
                decoded = data.encode().decode('unicode_escape')
                if decoded != data:
                    self._add_result('Unicode Escape', data, decoded)
            except:
                pass
    
    def _detect_html_entities(self, data: str):
        """Detect and decode HTML entities"""
        import html
        if '&' in data and ';' in data:
            try:
                decoded = html.unescape(data)
                if decoded != data:
                    self._add_result('HTML Entities', data, decoded)
            except:
                pass
    
    def _detect_base58(self, data: str):
        """Detect and decode Base58 (Bitcoin alphabet)"""
        b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        if all(c in b58_alphabet for c in data) and len(data) >= 4:
            try:
                # Base58 decode
                num = 0
                for char in data:
                    num = num * 58 + b58_alphabet.index(char)
                
                # Convert to bytes
                result = []
                while num > 0:
                    result.append(num % 256)
                    num //= 256
                
                decoded = bytes(reversed(result)).decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    self._add_result('Base58', data, decoded)
            except:
                pass
    
    def _detect_base85(self, data: str):
        """Detect and decode Base85/ASCII85"""
        try:
            decoded = base64.a85decode(data).decode('utf-8', errors='ignore')
            if decoded and self._is_printable(decoded):
                self._add_result('Base85/ASCII85', data, decoded)
        except:
            pass
        
        try:
            decoded = base64.b85decode(data).decode('utf-8', errors='ignore')
            if decoded and self._is_printable(decoded):
                self._add_result('Base85', data, decoded)
        except:
            pass
    
    def _detect_reversed(self, data: str):
        """Check for reversed strings"""
        reversed_data = data[::-1]
        if self._has_common_words(reversed_data) or self._has_flag_pattern(reversed_data):
            self._add_result('Reversed', data, reversed_data)
    
    def _recursive_decode(self, data: str, max_depth: int = 5, current_depth: int = 0):
        """Recursively decode nested encodings"""
        if current_depth >= max_depth:
            return
        
        # Try Base64 → other encodings
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if decoded and self._is_printable(decoded) and decoded != data:
                # Check if result is also encoded
                for encoding_check in [self._detect_base64, self._detect_base16_hex]:
                    try:
                        encoding_check(decoded)
                    except:
                        pass
                
                self._recursive_decode(decoded, max_depth, current_depth + 1)
                
                if self._has_flag_pattern(decoded):
                    self.results['encoding_chain'].append({
                        'depth': current_depth + 1,
                        'decoded': decoded
                    })
        except:
            pass
    
    def _search_flags(self, flag_format: str):
        """Search for flags in all decoded values"""
        # Extract prefix from format (e.g., "flag{}" -> "flag")
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        
        patterns = [
            rf'{prefix}\{{[^}}]+\}}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]
        
        for item in self.results['decoded_values']:
            decoded = item['decoded']
            for pattern in patterns:
                matches = re.findall(pattern, decoded, re.IGNORECASE)
                for match in matches:
                    if match not in self.results['possible_flags']:
                        self.results['possible_flags'].append(match)
    
    def _is_printable(self, text: str) -> bool:
        """Check if text is mostly printable"""
        if not text:
            return False
        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable_count / len(text) > 0.8
    
    def _has_common_words(self, text: str) -> bool:
        """Check if text contains common English words"""
        common_words = ['the', 'flag', 'is', 'and', 'for', 'are', 'but', 'not', 
                       'you', 'all', 'can', 'her', 'was', 'one', 'our', 'out',
                       'ctf', 'key', 'password', 'secret', 'hidden']
        text_lower = text.lower()
        return any(word in text_lower for word in common_words)
    
    def _has_flag_pattern(self, text: str) -> bool:
        """Check if text contains flag-like patterns"""
        patterns = [r'\w+\{[^}]+\}', r'flag', r'ctf', r'key']
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)
    
    def _print_results(self):
        """Print analysis results"""
        if not self.results['decoded_values']:
            print("  ℹ️  No encodings detected")
            return
        
        print(f"\n  📊 Found {len(self.results['decoded_values'])} encoding(s):\n")
        
        for item in self.results['decoded_values']:
            print(f"  🔹 {item['encoding']}:")
            print(f"     Decoded: {item['decoded'][:200]}")
            print()
        
        if self.results['possible_flags']:
            print(f"\n  🚩 Possible Flags Found:")
            for flag in self.results['possible_flags']:
                print(f"     ⭐ {flag}")


def analyze_encoding(data: str, flag_format: str = "flag{}") -> Dict:
    """Convenience function for encoding analysis"""
    detector = EncodingDetector()
    return detector.analyze(data, flag_format)


if __name__ == "__main__":
    # Test examples
    test_cases = [
        "SGVsbG8gV29ybGQh",  # Base64
        "48656c6c6f",  # Hex
        "01001000 01101001",  # Binary
        ".- -... -.-.",  # Morse
        "synt{grfg}",  # ROT13
    ]
    
    for test in test_cases:
        print(f"\n{'='*50}")
        print(f"Testing: {test}")
        analyze_encoding(test)
