#!/usr/bin/env python3
"""
Deep Crypto Analyzer - In-Depth Cryptographic Analysis
Comprehensive cipher detection and cracking
"""

import re
import string
import base64
import hashlib
import itertools
from typing import Dict, List, Tuple, Optional
from collections import Counter
import math


class DeepCryptoAnalyzer:
    """
    Comprehensive cryptographic analysis that tries everything.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.flags_found = []
        self.successful_decryptions = []
        
        self.flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'THM\{[^}]+\}'
        ]
        
        # English letter frequency
        self.english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
            's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
            'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
            'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
            'q': 0.10, 'z': 0.07
        }
        
        self.common_words = [
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
            'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her',
            'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there',
            'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get',
            'flag', 'ctf', 'key', 'password', 'secret', 'hidden', 'answer',
            'congratulations', 'well', 'done', 'you', 'found'
        ]
    
    def analyze(self, ciphertext: str) -> Dict:
        """Comprehensive crypto analysis"""
        print(f"\n[DEEP CRYPTO] Analyzing ciphertext...")
        print(f"    Input: {ciphertext[:80]}{'...' if len(ciphertext) > 80 else ''}")
        print("=" * 60)
        
        results = {
            'input': ciphertext,
            'detected_type': None,
            'successful_decryptions': [],
            'all_attempts': [],
            'flags_found': []
        }
        
        # Clean input
        ciphertext = ciphertext.strip()
        
        # 1. Multi-layer encoding detection
        print("[*] Checking multi-layer encodings...")
        decoded = self._decode_all_layers(ciphertext)
        if decoded != ciphertext:
            results['decoded_layers'] = decoded
            self._search_flags(decoded)
        
        # 2. Try all classical ciphers
        print("[*] Trying classical ciphers...")
        
        # Caesar/ROT variations
        for shift in range(1, 26):
            plain = self._caesar(ciphertext, shift)
            score = self._score_text(plain)
            if score > 2.0:
                results['all_attempts'].append({
                    'cipher': f'Caesar (shift {shift})',
                    'result': plain[:200],
                    'score': score
                })
                self._search_flags(plain)
        
        # ROT47
        plain = self._rot47(ciphertext)
        if self._score_text(plain) > 2.0:
            results['all_attempts'].append({
                'cipher': 'ROT47',
                'result': plain[:200],
                'score': self._score_text(plain)
            })
            self._search_flags(plain)
        
        # Atbash
        plain = self._atbash(ciphertext)
        if self._score_text(plain) > 2.0:
            results['all_attempts'].append({
                'cipher': 'Atbash',
                'result': plain[:200],
                'score': self._score_text(plain)
            })
            self._search_flags(plain)
        
        # Vigenere with common keys
        print("[*] Trying Vigenere with common keys...")
        vigenere_results = self._try_vigenere(ciphertext)
        results['all_attempts'].extend(vigenere_results)
        
        # Affine cipher (all valid a,b combinations)
        print("[*] Trying Affine cipher...")
        affine_results = self._try_affine(ciphertext)
        results['all_attempts'].extend(affine_results)
        
        # XOR with single byte and multi-byte keys
        print("[*] Trying XOR decryption...")
        xor_results = self._try_xor(ciphertext)
        results['all_attempts'].extend(xor_results)
        
        # Substitution cipher
        print("[*] Trying substitution cipher (frequency analysis)...")
        sub_result = self._try_substitution(ciphertext)
        if sub_result:
            results['all_attempts'].append(sub_result)
        
        # Rail fence
        print("[*] Trying Rail Fence cipher...")
        rail_results = self._try_rail_fence(ciphertext)
        results['all_attempts'].extend(rail_results)
        
        # Columnar transposition
        print("[*] Trying Columnar Transposition...")
        col_results = self._try_columnar(ciphertext)
        results['all_attempts'].extend(col_results)
        
        # Playfair
        print("[*] Trying Playfair cipher...")
        playfair_results = self._try_playfair(ciphertext)
        results['all_attempts'].extend(playfair_results)
        
        # Beaufort
        print("[*] Trying Beaufort cipher...")
        beaufort_results = self._try_beaufort(ciphertext)
        results['all_attempts'].extend(beaufort_results)
        
        # Bacon cipher
        if set(ciphertext.upper().replace(' ', '')) <= {'A', 'B'}:
            print("[*] Trying Bacon cipher...")
            bacon_result = self._bacon_decode(ciphertext)
            if bacon_result:
                results['all_attempts'].append({
                    'cipher': 'Bacon',
                    'result': bacon_result,
                    'score': self._score_text(bacon_result)
                })
                self._search_flags(bacon_result)
        
        # Morse code
        if set(ciphertext.replace(' ', '').replace('/', '')) <= {'.', '-', ' '}:
            print("[*] Trying Morse code...")
            morse_result = self._morse_decode(ciphertext)
            if morse_result:
                results['all_attempts'].append({
                    'cipher': 'Morse',
                    'result': morse_result,
                    'score': self._score_text(morse_result)
                })
                self._search_flags(morse_result)
        
        # A1Z26
        if re.match(r'^[\d\s,.-]+$', ciphertext):
            print("[*] Trying A1Z26...")
            a1z26_result = self._a1z26_decode(ciphertext)
            if a1z26_result:
                results['all_attempts'].append({
                    'cipher': 'A1Z26',
                    'result': a1z26_result,
                    'score': self._score_text(a1z26_result)
                })
                self._search_flags(a1z26_result)
        
        # Reverse
        plain = ciphertext[::-1]
        if self._score_text(plain) > self._score_text(ciphertext):
            results['all_attempts'].append({
                'cipher': 'Reversed',
                'result': plain,
                'score': self._score_text(plain)
            })
            self._search_flags(plain)
        
        # Sort by score
        results['all_attempts'].sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Get best results
        if results['all_attempts']:
            results['successful_decryptions'] = [
                a for a in results['all_attempts'] if a.get('score', 0) > 3.0
            ][:10]
        
        results['flags_found'] = self.flags_found
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] CRYPTO ANALYSIS SUMMARY")
        print("=" * 60)
        
        if self.flags_found:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.flags_found)}")
            for flag in self.flags_found:
                print(f"    {flag}")
        
        if results['successful_decryptions']:
            print(f"\n[+] TOP DECRYPTIONS:")
            for dec in results['successful_decryptions'][:5]:
                print(f"    {dec['cipher']}: {dec['result'][:60]}... (score: {dec['score']:.2f})")
        
        return results
    
    # ==================== ENCODING DETECTION ====================
    
    def _decode_all_layers(self, text: str, max_layers: int = 10) -> str:
        """Recursively decode all encoding layers"""
        current = text
        layers = 0
        
        while layers < max_layers:
            decoded = self._try_single_decode(current)
            if decoded == current:
                break
            current = decoded
            layers += 1
        
        return current
    
    def _try_single_decode(self, text: str) -> str:
        """Try single layer decoding"""
        
        # Base64
        try:
            if re.match(r'^[A-Za-z0-9+/]+=*$', text.strip()):
                decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded
        except:
            pass
        
        # Base32
        try:
            if re.match(r'^[A-Z2-7]+=*$', text.strip().upper()):
                decoded = base64.b32decode(text.strip().upper()).decode('utf-8', errors='ignore')
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded
        except:
            pass
        
        # Base16/Hex
        try:
            if re.match(r'^[0-9A-Fa-f]+$', text.strip()) and len(text) % 2 == 0:
                decoded = bytes.fromhex(text.strip()).decode('utf-8', errors='ignore')
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.7:
                    return decoded
        except:
            pass
        
        # Binary
        try:
            if re.match(r'^[01\s]+$', text.strip()):
                clean = text.replace(' ', '')
                if len(clean) % 8 == 0:
                    decoded = ''.join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
                    if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                        return decoded
        except:
            pass
        
        # Octal
        try:
            if re.match(r'^[0-7\s]+$', text.strip()):
                parts = text.split()
                decoded = ''.join(chr(int(p, 8)) for p in parts if p)
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded
        except:
            pass
        
        # Decimal ASCII
        try:
            if re.match(r'^[\d\s,]+$', text.strip()):
                parts = re.split(r'[\s,]+', text)
                decoded = ''.join(chr(int(p)) for p in parts if p and int(p) < 256)
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    return decoded
        except:
            pass
        
        # URL decode
        try:
            if '%' in text:
                from urllib.parse import unquote
                decoded = unquote(text)
                if decoded != text:
                    return decoded
        except:
            pass
        
        # Unicode escape
        try:
            if '\\u' in text or '\\x' in text:
                decoded = text.encode().decode('unicode_escape')
                if decoded != text:
                    return decoded
        except:
            pass
        
        return text
    
    # ==================== CLASSICAL CIPHERS ====================
    
    def _caesar(self, text: str, shift: int) -> str:
        """Caesar cipher decrypt"""
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)
    
    def _rot47(self, text: str) -> str:
        """ROT47 decrypt"""
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr((ord(c) - 33 + 47) % 94 + 33))
            else:
                result.append(c)
        return ''.join(result)
    
    def _atbash(self, text: str) -> str:
        """Atbash cipher"""
        result = []
        for c in text:
            if c.isalpha():
                if c.isupper():
                    result.append(chr(ord('Z') - (ord(c) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(c) - ord('a'))))
            else:
                result.append(c)
        return ''.join(result)
    
    def _try_vigenere(self, text: str) -> List[Dict]:
        """Try Vigenere with many keys"""
        results = []
        
        common_keys = [
            'key', 'flag', 'ctf', 'secret', 'password', 'cipher', 'crypto',
            'hack', 'code', 'hidden', 'security', 'admin', 'test', 'abc',
            'xyz', 'aaa', 'the', 'enigma', 'mystery', 'puzzle', 'answer',
            'vigenere', 'keyword', 'pass', 'linux', 'windows', 'python',
            'java', 'hello', 'world', 'attack', 'defend'
        ]
        
        # Also try key length detection
        potential_lengths = self._kasiski(text)
        
        for key in common_keys:
            plain = self._vigenere_decrypt(text, key)
            score = self._score_text(plain)
            
            if score > 2.5:
                results.append({
                    'cipher': f'Vigenere (key: {key})',
                    'result': plain[:200],
                    'score': score
                })
                self._search_flags(plain)
        
        return results
    
    def _vigenere_decrypt(self, text: str, key: str) -> str:
        """Vigenere decrypt"""
        result = []
        key = key.lower()
        key_idx = 0
        
        for c in text:
            if c.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('a')
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
                key_idx += 1
            else:
                result.append(c)
        
        return ''.join(result)
    
    def _kasiski(self, text: str) -> List[int]:
        """Kasiski examination for Vigenere key length"""
        clean = ''.join(c.lower() for c in text if c.isalpha())
        sequences = {}
        
        for length in range(3, 6):
            for i in range(len(clean) - length):
                seq = clean[i:i+length]
                if seq in sequences:
                    sequences[seq].append(i)
                else:
                    sequences[seq] = [i]
        
        distances = []
        for seq, positions in sequences.items():
            if len(positions) > 1:
                for i in range(len(positions) - 1):
                    distances.append(positions[i+1] - positions[i])
        
        if distances:
            from math import gcd
            from functools import reduce
            g = reduce(gcd, distances)
            return [g, g*2, g*3] if g > 1 else [3, 4, 5]
        
        return [3, 4, 5, 6]
    
    def _try_affine(self, text: str) -> List[Dict]:
        """Try all Affine cipher combinations"""
        results = []
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        
        for a in valid_a:
            a_inv = self._mod_inverse(a, 26)
            if a_inv is None:
                continue
                
            for b in range(26):
                plain = self._affine_decrypt(text, a, b, a_inv)
                score = self._score_text(plain)
                
                if score > 2.5:
                    results.append({
                        'cipher': f'Affine (a={a}, b={b})',
                        'result': plain[:200],
                        'score': score
                    })
                    self._search_flags(plain)
        
        return results
    
    def _affine_decrypt(self, text: str, a: int, b: int, a_inv: int) -> str:
        """Affine cipher decrypt"""
        result = []
        for c in text:
            if c.isalpha():
                x = ord(c.upper()) - ord('A')
                p = (a_inv * (x - b)) % 26
                result.append(chr(p + (ord('A') if c.isupper() else ord('a'))))
            else:
                result.append(c)
        return ''.join(result)
    
    def _mod_inverse(self, a: int, m: int) -> Optional[int]:
        """Modular multiplicative inverse"""
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None
    
    def _try_xor(self, text: str) -> List[Dict]:
        """Try XOR with various keys"""
        results = []
        
        # Convert to bytes
        try:
            if re.match(r'^[0-9a-fA-F]+$', text.replace(' ', '')):
                data = bytes.fromhex(text.replace(' ', ''))
            else:
                data = text.encode()
        except:
            data = text.encode()
        
        # Single byte XOR
        for key in range(256):
            decrypted = bytes([b ^ key for b in data])
            try:
                plain = decrypted.decode('utf-8', errors='ignore')
                score = self._score_text(plain)
                
                if score > 2.0:
                    results.append({
                        'cipher': f'XOR (key: {hex(key)})',
                        'result': plain[:200],
                        'score': score
                    })
                    self._search_flags(plain)
            except:
                pass
        
        # Multi-byte XOR with common keys
        common_keys = [b'key', b'flag', b'ctf', b'secret', b'password', b'the']
        for key in common_keys:
            decrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            try:
                plain = decrypted.decode('utf-8', errors='ignore')
                score = self._score_text(plain)
                
                if score > 2.0:
                    results.append({
                        'cipher': f'XOR (key: {key.decode()})',
                        'result': plain[:200],
                        'score': score
                    })
                    self._search_flags(plain)
            except:
                pass
        
        return results
    
    def _try_substitution(self, text: str) -> Optional[Dict]:
        """Try substitution cipher via frequency analysis"""
        letters = [c.lower() for c in text if c.isalpha()]
        if len(letters) < 30:
            return None
        
        freq = Counter(letters)
        sorted_cipher = [item[0] for item in freq.most_common()]
        sorted_english = list('etaoinshrdlcumwfgypbvkjxqz')
        
        sub_map = {}
        for i, c in enumerate(sorted_cipher):
            if i < len(sorted_english):
                sub_map[c] = sorted_english[i]
        
        result = []
        for c in text:
            if c.lower() in sub_map:
                new_c = sub_map[c.lower()]
                result.append(new_c.upper() if c.isupper() else new_c)
            else:
                result.append(c)
        
        plain = ''.join(result)
        score = self._score_text(plain)
        
        if score > 2.0:
            self._search_flags(plain)
            return {
                'cipher': 'Substitution (frequency)',
                'result': plain[:200],
                'score': score
            }
        
        return None
    
    def _try_rail_fence(self, text: str) -> List[Dict]:
        """Try Rail Fence cipher"""
        results = []
        
        for rails in range(2, min(10, len(text))):
            plain = self._rail_fence_decrypt(text, rails)
            score = self._score_text(plain)
            
            if score > 2.0:
                results.append({
                    'cipher': f'Rail Fence ({rails} rails)',
                    'result': plain[:200],
                    'score': score
                })
                self._search_flags(plain)
        
        return results
    
    def _rail_fence_decrypt(self, text: str, rails: int) -> str:
        """Rail Fence decrypt"""
        if rails < 2 or rails >= len(text):
            return text
        
        fence = [['' for _ in range(len(text))] for _ in range(rails)]
        
        rail, direction = 0, 1
        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        idx = 0
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] == '*' and idx < len(text):
                    fence[i][j] = text[idx]
                    idx += 1
        
        result = []
        rail, direction = 0, 1
        for i in range(len(text)):
            result.append(fence[rail][i])
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join(result)
    
    def _try_columnar(self, text: str) -> List[Dict]:
        """Try Columnar Transposition"""
        results = []
        
        for cols in range(2, min(10, len(text) // 2)):
            for order in itertools.permutations(range(cols)):
                plain = self._columnar_decrypt(text, list(order))
                score = self._score_text(plain)
                
                if score > 3.0:
                    results.append({
                        'cipher': f'Columnar ({cols} cols, order: {order})',
                        'result': plain[:200],
                        'score': score
                    })
                    self._search_flags(plain)
                    
            if len(results) > 5:  # Limit results
                break
        
        return results[:5]
    
    def _columnar_decrypt(self, text: str, order: List[int]) -> str:
        """Columnar Transposition decrypt"""
        cols = len(order)
        rows = math.ceil(len(text) / cols)
        
        # Create grid
        grid = [[''] * cols for _ in range(rows)]
        
        idx = 0
        for col_idx in order:
            for row in range(rows):
                if idx < len(text):
                    grid[row][col_idx] = text[idx]
                    idx += 1
        
        return ''.join(''.join(row) for row in grid)
    
    def _try_playfair(self, text: str) -> List[Dict]:
        """Try Playfair with common keys"""
        results = []
        
        keys = ['key', 'secret', 'playfair', 'cipher', 'crypto', 'monarchy', 'keyword']
        
        for key in keys:
            plain = self._playfair_decrypt(text, key)
            score = self._score_text(plain)
            
            if score > 2.0:
                results.append({
                    'cipher': f'Playfair (key: {key})',
                    'result': plain[:200],
                    'score': score
                })
                self._search_flags(plain)
        
        return results
    
    def _playfair_decrypt(self, text: str, key: str) -> str:
        """Playfair decrypt"""
        # Create key square
        key = key.upper().replace('J', 'I')
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        
        key_square = ''
        for c in key + alphabet:
            if c not in key_square:
                key_square += c
        
        def find_pos(c):
            idx = key_square.index(c.upper())
            return idx // 5, idx % 5
        
        clean = ''.join(c.upper() for c in text if c.isalpha()).replace('J', 'I')
        if len(clean) % 2:
            clean += 'X'
        
        result = []
        for i in range(0, len(clean), 2):
            r1, c1 = find_pos(clean[i])
            r2, c2 = find_pos(clean[i+1])
            
            if r1 == r2:
                result.append(key_square[r1*5 + (c1-1) % 5])
                result.append(key_square[r2*5 + (c2-1) % 5])
            elif c1 == c2:
                result.append(key_square[((r1-1) % 5)*5 + c1])
                result.append(key_square[((r2-1) % 5)*5 + c2])
            else:
                result.append(key_square[r1*5 + c2])
                result.append(key_square[r2*5 + c1])
        
        return ''.join(result)
    
    def _try_beaufort(self, text: str) -> List[Dict]:
        """Try Beaufort cipher"""
        results = []
        
        keys = ['key', 'flag', 'secret', 'cipher', 'beaufort']
        
        for key in keys:
            plain = self._beaufort_decrypt(text, key)
            score = self._score_text(plain)
            
            if score > 2.0:
                results.append({
                    'cipher': f'Beaufort (key: {key})',
                    'result': plain[:200],
                    'score': score
                })
                self._search_flags(plain)
        
        return results
    
    def _beaufort_decrypt(self, text: str, key: str) -> str:
        """Beaufort decrypt (symmetric)"""
        result = []
        key = key.upper()
        key_idx = 0
        
        for c in text:
            if c.isalpha():
                k = ord(key[key_idx % len(key)]) - ord('A')
                x = ord(c.upper()) - ord('A')
                p = (k - x) % 26
                result.append(chr(p + (ord('A') if c.isupper() else ord('a'))))
                key_idx += 1
            else:
                result.append(c)
        
        return ''.join(result)
    
    def _bacon_decode(self, text: str) -> Optional[str]:
        """Bacon cipher decode"""
        bacon = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        clean = text.upper().replace(' ', '')
        result = []
        
        for i in range(0, len(clean) - 4, 5):
            chunk = clean[i:i+5]
            if chunk in bacon:
                result.append(bacon[chunk])
        
        return ''.join(result) if result else None
    
    def _morse_decode(self, text: str) -> Optional[str]:
        """Morse code decode"""
        morse = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9'
        }
        
        result = []
        words = text.split('/')
        
        for word in words:
            letters = word.split()
            for letter in letters:
                if letter in morse:
                    result.append(morse[letter])
            result.append(' ')
        
        return ''.join(result).strip() if result else None
    
    def _a1z26_decode(self, text: str) -> Optional[str]:
        """A1Z26 decode"""
        parts = re.split(r'[\s,.-]+', text)
        result = []
        
        for part in parts:
            try:
                n = int(part)
                if 1 <= n <= 26:
                    result.append(chr(n + ord('A') - 1))
            except:
                pass
        
        return ''.join(result) if result else None
    
    # ==================== SCORING ====================
    
    def _score_text(self, text: str) -> float:
        """Score how likely text is English/contains flag"""
        if not text:
            return 0
        
        score = 0
        text_lower = text.lower()
        
        # Flag patterns (highest priority)
        for pattern in self.flag_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 10.0
        
        # Common words
        words_found = sum(1 for w in self.common_words if w in text_lower)
        score += words_found * 0.3
        
        # Printable ratio
        printable = sum(1 for c in text if c.isprintable())
        score += (printable / len(text)) * 0.5
        
        # Letter frequency
        if len(text) > 20:
            letters = [c.lower() for c in text if c.isalpha()]
            if letters:
                freq = Counter(letters)
                total = len(letters)
                
                freq_score = 0
                for letter, expected in self.english_freq.items():
                    actual = (freq.get(letter, 0) / total) * 100
                    diff = abs(expected - actual)
                    freq_score += max(0, 1 - diff / 10)
                
                score += (freq_score / 26) * 2.0
        
        return score
    
    def _search_flags(self, text: str):
        """Search for flags"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if m not in self.flags_found:
                    self.flags_found.append(m)
                    print(f"    [FLAG] {m}")
