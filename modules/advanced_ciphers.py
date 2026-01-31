#!/usr/bin/env python3
"""
Advanced Cipher Module
Additional cipher cracking algorithms for CTF challenges
"""

import re
import string
from typing import Dict, List, Optional, Tuple
from collections import Counter
import itertools


class AdvancedCiphers:
    """Additional cipher crackers for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'attempts': [],
            'successful_decryptions': [],
            'flags_found': []
        }
        
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}'
        ]
        
        # English letter frequencies
        self.english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
            'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
            'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
            'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
            'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        }
        
        # Playfair key square helper
        self.alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # No J
    
    def _search_flags(self, text: str) -> List[str]:
        """Search for flags"""
        found = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags_found']:
                    self.results['flags_found'].append(match)
                    found.append(match)
                    print(f"[FLAG] Found: {match}")
        return found
    
    def _score_english(self, text: str) -> float:
        """Score how likely text is English"""
        text = text.lower()
        text_freq = Counter(c for c in text if c.isalpha())
        total = sum(text_freq.values())
        
        if total == 0:
            return 0
        
        score = 0
        for char, count in text_freq.items():
            expected = self.english_freq.get(char, 0)
            actual = (count / total) * 100
            score += min(expected, actual)
        
        # Bonus for common words
        common_words = ['the', 'and', 'flag', 'ctf', 'is', 'to', 'of', 'in', 'for']
        for word in common_words:
            if word in text.lower():
                score += 5
        
        return score
    
    # ==================== PLAYFAIR CIPHER ====================
    
    def _playfair_create_matrix(self, key: str) -> List[List[str]]:
        """Create Playfair cipher matrix"""
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key + self.alphabet))
        
        matrix = []
        for i in range(5):
            row = []
            for j in range(5):
                row.append(key[i * 5 + j])
            matrix.append(row)
        
        return matrix
    
    def _playfair_find_position(self, matrix: List[List[str]], char: str) -> Tuple[int, int]:
        """Find character position in Playfair matrix"""
        char = char.upper()
        if char == 'J':
            char = 'I'
        
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return (i, j)
        return (-1, -1)
    
    def playfair_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Playfair cipher"""
        matrix = self._playfair_create_matrix(key)
        ciphertext = ciphertext.upper().replace('J', 'I')
        ciphertext = ''.join(c for c in ciphertext if c.isalpha())
        
        # Ensure even length
        if len(ciphertext) % 2 != 0:
            ciphertext += 'X'
        
        plaintext = ''
        
        for i in range(0, len(ciphertext), 2):
            c1, c2 = ciphertext[i], ciphertext[i + 1]
            r1, col1 = self._playfair_find_position(matrix, c1)
            r2, col2 = self._playfair_find_position(matrix, c2)
            
            if r1 == r2:  # Same row
                plaintext += matrix[r1][(col1 - 1) % 5]
                plaintext += matrix[r2][(col2 - 1) % 5]
            elif col1 == col2:  # Same column
                plaintext += matrix[(r1 - 1) % 5][col1]
                plaintext += matrix[(r2 - 1) % 5][col2]
            else:  # Rectangle
                plaintext += matrix[r1][col2]
                plaintext += matrix[r2][col1]
        
        return plaintext
    
    def crack_playfair(self, ciphertext: str, wordlist: List[str] = None) -> List[Dict]:
        """Try to crack Playfair cipher with common keys"""
        print("[*] Attempting Playfair cipher crack...")
        
        if wordlist is None:
            wordlist = [
                'secret', 'key', 'password', 'cipher', 'crypto', 'flag',
                'playfair', 'puzzle', 'hidden', 'mystery', 'security',
                'keyword', 'matrix', 'square', 'monarch', 'example'
            ]
        
        results = []
        
        for key in wordlist:
            plaintext = self.playfair_decrypt(ciphertext, key)
            score = self._score_english(plaintext)
            
            if score > 30:
                results.append({
                    'key': key,
                    'plaintext': plaintext,
                    'score': score
                })
                self._search_flags(plaintext)
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:5]
    
    # ==================== BEAUFORT CIPHER ====================
    
    def beaufort_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Beaufort cipher (symmetric - same as encrypt)"""
        plaintext = ''
        key = key.upper()
        ciphertext = ciphertext.upper()
        
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                k = ord(key[key_index % len(key)]) - ord('A')
                c = ord(char) - ord('A')
                p = (k - c) % 26
                plaintext += chr(p + ord('A'))
                key_index += 1
            else:
                plaintext += char
        
        return plaintext
    
    def crack_beaufort(self, ciphertext: str, wordlist: List[str] = None) -> List[Dict]:
        """Try to crack Beaufort cipher"""
        print("[*] Attempting Beaufort cipher crack...")
        
        if wordlist is None:
            wordlist = [
                'key', 'secret', 'flag', 'ctf', 'password', 'cipher',
                'crypto', 'beaufort', 'decrypt', 'hidden', 'code'
            ]
        
        results = []
        
        for key in wordlist:
            plaintext = self.beaufort_decrypt(ciphertext, key)
            score = self._score_english(plaintext)
            
            if score > 30:
                results.append({
                    'key': key,
                    'plaintext': plaintext,
                    'score': score
                })
                self._search_flags(plaintext)
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:5]
    
    # ==================== AFFINE CIPHER ====================
    
    def _mod_inverse(self, a: int, m: int) -> Optional[int]:
        """Calculate modular multiplicative inverse"""
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None
    
    def affine_decrypt(self, ciphertext: str, a: int, b: int) -> str:
        """Decrypt Affine cipher: D(x) = a^-1 * (x - b) mod 26"""
        a_inv = self._mod_inverse(a, 26)
        if a_inv is None:
            return ""
        
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                x = ord(char.upper()) - ord('A')
                p = (a_inv * (x - b)) % 26
                if char.isupper():
                    plaintext += chr(p + ord('A'))
                else:
                    plaintext += chr(p + ord('a'))
            else:
                plaintext += char
        
        return plaintext
    
    def crack_affine(self, ciphertext: str) -> List[Dict]:
        """Brute force Affine cipher"""
        print("[*] Attempting Affine cipher crack...")
        
        # Valid 'a' values (coprime with 26)
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        
        results = []
        
        for a in valid_a:
            for b in range(26):
                plaintext = self.affine_decrypt(ciphertext, a, b)
                score = self._score_english(plaintext)
                
                if score > 35:
                    results.append({
                        'a': a,
                        'b': b,
                        'plaintext': plaintext,
                        'score': score
                    })
                    self._search_flags(plaintext)
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:5]
    
    # ==================== BACON CIPHER ====================
    
    def bacon_decrypt(self, ciphertext: str, use_ab: bool = True) -> str:
        """Decrypt Bacon cipher"""
        bacon_table = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
            'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
            'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
            'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P',
            'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
            'BBAAA': 'Y', 'BBAAB': 'Z'
        }
        
        if use_ab:
            # Already in A/B format
            binary = ciphertext.upper().replace(' ', '')
        else:
            # Convert from uppercase/lowercase
            binary = ''
            for char in ciphertext:
                if char.isalpha():
                    binary += 'A' if char.isupper() else 'B'
        
        # Clean and decode
        binary = ''.join(c for c in binary if c in 'AB')
        
        plaintext = ''
        for i in range(0, len(binary) - 4, 5):
            chunk = binary[i:i+5]
            if chunk in bacon_table:
                plaintext += bacon_table[chunk]
        
        self._search_flags(plaintext)
        return plaintext
    
    # ==================== POLYBIUS SQUARE ====================
    
    def polybius_decrypt(self, ciphertext: str, key: str = 'ABCDEFGHIKLMNOPQRSTUVWXYZ') -> str:
        """Decrypt Polybius square cipher"""
        # Create grid
        grid = []
        for i in range(5):
            row = key[i*5:(i+1)*5]
            grid.append(row)
        
        # Clean input - expect pairs of digits
        ciphertext = ''.join(c for c in ciphertext if c.isdigit())
        
        plaintext = ''
        for i in range(0, len(ciphertext) - 1, 2):
            row = int(ciphertext[i]) - 1
            col = int(ciphertext[i + 1]) - 1
            
            if 0 <= row < 5 and 0 <= col < 5:
                plaintext += grid[row][col]
        
        self._search_flags(plaintext)
        return plaintext
    
    # ==================== AUTOKEY CIPHER ====================
    
    def autokey_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Autokey/Running key cipher"""
        plaintext = ''
        full_key = key.upper()
        ciphertext = ciphertext.upper()
        
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                k = ord(full_key[i % len(full_key)]) - ord('A')
                c = ord(char) - ord('A')
                p = (c - k) % 26
                p_char = chr(p + ord('A'))
                plaintext += p_char
                full_key += p_char  # Key extends with plaintext
            else:
                plaintext += char
        
        self._search_flags(plaintext)
        return plaintext
    
    # ==================== BIFID CIPHER ====================
    
    def bifid_decrypt(self, ciphertext: str, key: str = 'ABCDEFGHIKLMNOPQRSTUVWXYZ') -> str:
        """Decrypt Bifid cipher"""
        # Create Polybius square
        key = key.upper().replace('J', 'I')
        key = ''.join(dict.fromkeys(key))
        
        def char_to_pos(c):
            idx = key.index(c)
            return (idx // 5, idx % 5)
        
        def pos_to_char(r, c):
            return key[r * 5 + c]
        
        ciphertext = ciphertext.upper().replace('J', 'I')
        ciphertext = ''.join(c for c in ciphertext if c.isalpha())
        
        # Get row and column values
        rows = []
        cols = []
        for char in ciphertext:
            r, c = char_to_pos(char)
            rows.append(r)
            cols.append(c)
        
        # Combine and split
        combined = rows + cols
        mid = len(combined) // 2
        
        plaintext = ''
        for i in range(mid):
            r = combined[i]
            c = combined[i + mid]
            plaintext += pos_to_char(r, c)
        
        self._search_flags(plaintext)
        return plaintext
    
    # ==================== GRONSFELD CIPHER ====================
    
    def gronsfeld_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Gronsfeld cipher (Vigenere with numeric key)"""
        if not key.isdigit():
            return ""
        
        plaintext = ''
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                shift = int(key[key_index % len(key)])
                base = ord('A') if char.isupper() else ord('a')
                p = (ord(char) - base - shift) % 26
                plaintext += chr(p + base)
                key_index += 1
            else:
                plaintext += char
        
        self._search_flags(plaintext)
        return plaintext
    
    def crack_gronsfeld(self, ciphertext: str) -> List[Dict]:
        """Try common numeric keys for Gronsfeld"""
        print("[*] Attempting Gronsfeld cipher crack...")
        
        # Common numeric patterns
        keys = [
            '123', '1234', '12345', '314159', '271828',
            '111', '222', '333', '123456', '654321',
            '2718', '3141', '1111', '0123', '9876'
        ]
        
        results = []
        
        for key in keys:
            plaintext = self.gronsfeld_decrypt(ciphertext, key)
            score = self._score_english(plaintext)
            
            if score > 30:
                results.append({
                    'key': key,
                    'plaintext': plaintext,
                    'score': score
                })
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:5]
    
    # ==================== MASTER CRACK FUNCTION ====================
    
    def crack_all(self, ciphertext: str) -> Dict:
        """Try all cipher types"""
        print(f"\n[*] Attempting to crack: {ciphertext[:50]}...")
        print("=" * 60)
        
        all_results = {}
        
        # Affine
        affine_results = self.crack_affine(ciphertext)
        if affine_results:
            all_results['affine'] = affine_results
            print(f"[+] Affine: Found {len(affine_results)} potential decryptions")
        
        # Playfair
        playfair_results = self.crack_playfair(ciphertext)
        if playfair_results:
            all_results['playfair'] = playfair_results
            print(f"[+] Playfair: Found {len(playfair_results)} potential decryptions")
        
        # Beaufort
        beaufort_results = self.crack_beaufort(ciphertext)
        if beaufort_results:
            all_results['beaufort'] = beaufort_results
            print(f"[+] Beaufort: Found {len(beaufort_results)} potential decryptions")
        
        # Gronsfeld
        gronsfeld_results = self.crack_gronsfeld(ciphertext)
        if gronsfeld_results:
            all_results['gronsfeld'] = gronsfeld_results
            print(f"[+] Gronsfeld: Found {len(gronsfeld_results)} potential decryptions")
        
        # Bacon (if looks like A/B pattern)
        if set(ciphertext.upper().replace(' ', '')) <= {'A', 'B'}:
            bacon_result = self.bacon_decrypt(ciphertext)
            if bacon_result:
                all_results['bacon'] = bacon_result
                print(f"[+] Bacon: {bacon_result}")
        
        # Polybius (if digits)
        if ciphertext.replace(' ', '').isdigit():
            polybius_result = self.polybius_decrypt(ciphertext)
            if polybius_result:
                all_results['polybius'] = polybius_result
                print(f"[+] Polybius: {polybius_result}")
        
        # Summary
        print("\n" + "=" * 60)
        if self.results['flags_found']:
            print(f"[FLAG] FLAGS FOUND: {len(self.results['flags_found'])}")
            for flag in self.results['flags_found']:
                print(f"  -> {flag}")
        
        return all_results
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        lines = ["Advanced Cipher Analysis", "=" * 40]
        lines.append(f"Flags found: {len(self.results['flags_found'])}")
        
        if self.results['flags_found']:
            lines.append("\nFlags:")
            for flag in self.results['flags_found']:
                lines.append(f"  {flag}")
        
        return '\n'.join(lines)
