#!/usr/bin/env python3
"""
Cipher Cracker - Auto-crack common CTF ciphers
Author: Prudhvi (CTFHunter)
Version: 2.2.0
"""

import re
import string
from typing import Dict, List, Tuple, Optional
from collections import Counter


class CipherCracker:
    """Automatically detect and crack common CTF ciphers"""
    
    # English letter frequency for analysis
    ENGLISH_FREQ = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
        'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }
    
    # Common English words for validation
    COMMON_WORDS = [
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
        'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
        'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
        'flag', 'ctf', 'key', 'password', 'secret', 'hidden', 'answer'
    ]
    
    def __init__(self, config=None):
        self.config = config or {}
        self.results = {
            'detected_cipher': None,
            'cracked_text': None,
            'possible_keys': [],
            'all_attempts': []
        }
    
    def analyze(self, ciphertext: str, flag_format: str = "flag{}") -> Dict:
        """Analyze and attempt to crack cipher"""
        print(f"\n🔓 Analyzing cipher...")
        print(f"   Input: {ciphertext[:80]}{'...' if len(ciphertext) > 80 else ''}")
        
        ciphertext = ciphertext.strip()
        
        # Try all cipher types
        self._try_caesar(ciphertext, flag_format)
        self._try_rot13(ciphertext, flag_format)
        self._try_atbash(ciphertext, flag_format)
        self._try_vigenere(ciphertext, flag_format)
        self._try_xor_single(ciphertext, flag_format)
        self._try_substitution(ciphertext, flag_format)
        self._try_reverse(ciphertext, flag_format)
        self._try_rail_fence(ciphertext, flag_format)
        self._try_a1z26(ciphertext, flag_format)
        
        self._print_results(flag_format)
        return self.results
    
    def _add_attempt(self, cipher_name: str, key: str, plaintext: str, score: float):
        """Add a decryption attempt"""
        self.results['all_attempts'].append({
            'cipher': cipher_name,
            'key': key,
            'plaintext': plaintext[:200],
            'score': score
        })
        
        # Update best result
        if not self.results['cracked_text'] or score > self.results['all_attempts'][0].get('score', 0):
            best = max(self.results['all_attempts'], key=lambda x: x['score'])
            if best['score'] > 0.3:  # Minimum threshold
                self.results['detected_cipher'] = best['cipher']
                self.results['cracked_text'] = best['plaintext']
                if best['key'] not in self.results['possible_keys']:
                    self.results['possible_keys'].append(best['key'])
    
    def _score_text(self, text: str, flag_format: str = "flag{}") -> float:
        """Score how likely text is valid English/contains flag"""
        if not text:
            return 0
        
        score = 0
        text_lower = text.lower()
        
        # Check for flag pattern (highest priority)
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        if re.search(rf'{prefix}\{{[^}}]+\}}', text, re.IGNORECASE):
            score += 5.0
        if re.search(r'flag\{[^}]+\}', text, re.IGNORECASE):
            score += 5.0
        if re.search(r'ctf\{[^}]+\}', text, re.IGNORECASE):
            score += 5.0
        
        # Check for common words
        word_count = sum(1 for word in self.COMMON_WORDS if word in text_lower)
        score += word_count * 0.2
        
        # Check printable ratio
        printable = sum(1 for c in text if c.isprintable())
        score += (printable / len(text)) * 0.5
        
        # Check letter frequency similarity
        if len(text) > 20:
            freq_score = self._frequency_score(text)
            score += freq_score * 0.3
        
        return score
    
    def _frequency_score(self, text: str) -> float:
        """Score based on English letter frequency"""
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0
        
        freq = Counter(letters)
        total = len(letters)
        
        score = 0
        for letter, expected in self.ENGLISH_FREQ.items():
            actual = (freq.get(letter, 0) / total) * 100
            diff = abs(expected - actual)
            score += max(0, 1 - diff / 10)
        
        return score / 26
    
    def _try_caesar(self, ciphertext: str, flag_format: str):
        """Try all Caesar cipher shifts"""
        for shift in range(1, 26):
            plaintext = self._caesar_decrypt(ciphertext, shift)
            score = self._score_text(plaintext, flag_format)
            
            if score > 0.3:
                self._add_attempt(f'Caesar (shift {shift})', str(shift), plaintext, score)
    
    def _caesar_decrypt(self, text: str, shift: int) -> str:
        """Decrypt Caesar cipher"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base - shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    def _try_rot13(self, ciphertext: str, flag_format: str):
        """Try ROT13"""
        plaintext = self._caesar_decrypt(ciphertext, 13)
        score = self._score_text(plaintext, flag_format)
        
        if score > 0.3:
            self._add_attempt('ROT13', 'N/A', plaintext, score)
    
    def _try_atbash(self, ciphertext: str, flag_format: str):
        """Try Atbash cipher"""
        result = []
        for char in ciphertext:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('Z') - (ord(char) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        
        plaintext = ''.join(result)
        score = self._score_text(plaintext, flag_format)
        
        if score > 0.3:
            self._add_attempt('Atbash', 'N/A', plaintext, score)
    
    def _try_vigenere(self, ciphertext: str, flag_format: str):
        """Try Vigenere cipher with common keys"""
        common_keys = [
            'key', 'flag', 'ctf', 'secret', 'password', 'cipher', 'crypto',
            'hack', 'code', 'hidden', 'security', 'admin', 'test', 'abc',
            'xyz', 'aaa', 'the', 'enigma', 'mystery', 'puzzle'
        ]
        
        # Also try to find key length using Kasiski method
        potential_lengths = self._kasiski_examination(ciphertext)
        
        for key in common_keys:
            plaintext = self._vigenere_decrypt(ciphertext, key)
            score = self._score_text(plaintext, flag_format)
            
            if score > 0.5:
                self._add_attempt(f'Vigenere', key, plaintext, score)
    
    def _vigenere_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Vigenere cipher"""
        result = []
        key = key.lower()
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('a')
                if char.isupper():
                    result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def _kasiski_examination(self, ciphertext: str) -> List[int]:
        """Find potential Vigenere key lengths"""
        # Find repeated sequences
        sequences = {}
        clean = ''.join(c.lower() for c in ciphertext if c.isalpha())
        
        for length in range(3, 6):
            for i in range(len(clean) - length):
                seq = clean[i:i+length]
                if seq in sequences:
                    sequences[seq].append(i)
                else:
                    sequences[seq] = [i]
        
        # Find GCD of distances
        distances = []
        for seq, positions in sequences.items():
            if len(positions) > 1:
                for i in range(len(positions) - 1):
                    distances.append(positions[i+1] - positions[i])
        
        # Common factors
        if distances:
            from math import gcd
            from functools import reduce
            potential = reduce(gcd, distances)
            return [potential, potential * 2, potential * 3]
        
        return [3, 4, 5, 6]
    
    def _try_xor_single(self, ciphertext: str, flag_format: str):
        """Try single-byte XOR"""
        # Convert to bytes if hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in ciphertext.replace(' ', '')):
                data = bytes.fromhex(ciphertext.replace(' ', ''))
            else:
                data = ciphertext.encode()
        except:
            data = ciphertext.encode()
        
        for key in range(256):
            try:
                decrypted = bytes([b ^ key for b in data])
                plaintext = decrypted.decode('utf-8', errors='ignore')
                score = self._score_text(plaintext, flag_format)
                
                if score > 0.5:
                    self._add_attempt('XOR (single byte)', hex(key), plaintext, score)
            except:
                pass
    
    def _try_substitution(self, ciphertext: str, flag_format: str):
        """Try simple substitution analysis"""
        # Frequency analysis
        letters = [c.lower() for c in ciphertext if c.isalpha()]
        if len(letters) < 20:
            return
        
        freq = Counter(letters)
        sorted_cipher = [item[0] for item in freq.most_common()]
        sorted_english = list('etaoinshrdlcumwfgypbvkjxqz')
        
        # Create substitution map
        sub_map = {}
        for i, c in enumerate(sorted_cipher):
            if i < len(sorted_english):
                sub_map[c] = sorted_english[i]
        
        # Apply substitution
        result = []
        for char in ciphertext:
            if char.lower() in sub_map:
                new_char = sub_map[char.lower()]
                result.append(new_char.upper() if char.isupper() else new_char)
            else:
                result.append(char)
        
        plaintext = ''.join(result)
        score = self._score_text(plaintext, flag_format)
        
        if score > 0.3:
            self._add_attempt('Substitution (freq analysis)', 'frequency-based', plaintext, score)
    
    def _try_reverse(self, ciphertext: str, flag_format: str):
        """Try simple string reversal"""
        plaintext = ciphertext[::-1]
        score = self._score_text(plaintext, flag_format)
        
        if score > 0.3:
            self._add_attempt('Reversed', 'N/A', plaintext, score)
    
    def _try_rail_fence(self, ciphertext: str, flag_format: str):
        """Try Rail Fence cipher"""
        for rails in range(2, 6):
            plaintext = self._rail_fence_decrypt(ciphertext, rails)
            score = self._score_text(plaintext, flag_format)
            
            if score > 0.3:
                self._add_attempt(f'Rail Fence ({rails} rails)', str(rails), plaintext, score)
    
    def _rail_fence_decrypt(self, ciphertext: str, rails: int) -> str:
        """Decrypt Rail Fence cipher"""
        if rails < 2 or rails >= len(ciphertext):
            return ciphertext
        
        # Build the fence pattern
        fence = [['' for _ in range(len(ciphertext))] for _ in range(rails)]
        
        rail = 0
        direction = 1
        
        for i in range(len(ciphertext)):
            fence[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        # Fill in the characters
        index = 0
        for i in range(rails):
            for j in range(len(ciphertext)):
                if fence[i][j] == '*' and index < len(ciphertext):
                    fence[i][j] = ciphertext[index]
                    index += 1
        
        # Read off the plaintext
        result = []
        rail = 0
        direction = 1
        
        for i in range(len(ciphertext)):
            result.append(fence[rail][i])
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join(result)
    
    def _try_a1z26(self, ciphertext: str, flag_format: str):
        """Try A1Z26 cipher (numbers to letters)"""
        # Check if input looks like numbers
        numbers = re.findall(r'\d+', ciphertext)
        if not numbers:
            return
        
        try:
            # Convert numbers to letters
            result = []
            for num in numbers:
                n = int(num)
                if 1 <= n <= 26:
                    result.append(chr(ord('a') + n - 1))
                else:
                    result.append('?')
            
            plaintext = ''.join(result)
            score = self._score_text(plaintext, flag_format)
            
            if score > 0.2:
                self._add_attempt('A1Z26', 'N/A', plaintext, score)
        except:
            pass
    
    def _print_results(self, flag_format: str):
        """Print cracking results"""
        if not self.results['all_attempts']:
            print("\n  ℹ️  No successful decryptions found")
            print("  💡 Try: CyberChef, dcode.fr, or manual analysis")
            return
        
        # Sort by score
        sorted_attempts = sorted(
            self.results['all_attempts'], 
            key=lambda x: x['score'], 
            reverse=True
        )
        
        print(f"\n  📊 Top Results:\n")
        
        for i, attempt in enumerate(sorted_attempts[:5]):
            print(f"  {i+1}. {attempt['cipher']}")
            print(f"     Key: {attempt['key']}")
            print(f"     Result: {attempt['plaintext'][:100]}")
            print(f"     Score: {attempt['score']:.2f}")
            print()
        
        # Check for flags in results
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        for attempt in sorted_attempts:
            flags = re.findall(rf'{prefix}\{{[^}}]+\}}', attempt['plaintext'], re.IGNORECASE)
            flags += re.findall(r'flag\{[^}]+\}', attempt['plaintext'], re.IGNORECASE)
            if flags:
                print(f"  🚩 FLAG FOUND: {flags[0]}")
                break


def crack_cipher(ciphertext: str, flag_format: str = "flag{}") -> Dict:
    """Convenience function for cipher cracking"""
    cracker = CipherCracker()
    return cracker.analyze(ciphertext, flag_format)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        crack_cipher(' '.join(sys.argv[1:]))
    else:
        # Test examples
        tests = [
            "Uryyb Jbeyq!",  # ROT13
            "Khoor Zruog",  # Caesar shift 3
            "gsv uzoo rh xfgv",  # Atbash
            "synt{grfg_pvcure}",  # ROT13 with flag
        ]
        
        for test in tests:
            print(f"\n{'='*50}")
            print(f"Testing: {test}")
            crack_cipher(test)
