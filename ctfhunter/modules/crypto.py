"""
CTFHunter - Cryptography Module
===============================

Analyzes encoded and encrypted data, identifies hash types,
and attempts common cryptographic challenge solutions.
"""

import os
import re
import base64
import binascii
import codecs
import hashlib
import subprocess
import shutil
from typing import List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """Result from running a tool."""
    tool_name: str
    command: str
    success: bool
    output: str
    error: str
    execution_time: float
    flags_found: List[str] = field(default_factory=list)


class CryptoModule:
    """
    Cryptography analysis module.
    
    Handles:
    - Base64, hex, binary, octal encoding detection
    - ROT13/ROT47 and Caesar cipher
    - Morse code
    - Binary to text
    - Hash identification
    - Simple substitution ciphers
    """
    
    # Common hash patterns
    HASH_PATTERNS = {
        r'^[a-fA-F0-9]{32}$': 'MD5',
        r'^[a-fA-F0-9]{40}$': 'SHA-1',
        r'^[a-fA-F0-9]{64}$': 'SHA-256',
        r'^[a-fA-F0-9]{128}$': 'SHA-512',
        r'^\$1\$': 'MD5 Crypt',
        r'^\$2[ayb]\$': 'Bcrypt',
        r'^\$5\$': 'SHA-256 Crypt',
        r'^\$6\$': 'SHA-512 Crypt',
        r'^[a-fA-F0-9]{16}$': 'MySQL 3.x / LM Hash',
        r'^\*[a-fA-F0-9]{40}$': 'MySQL 5.x',
    }
    
    # Morse code dictionary
    MORSE_CODE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9',
        '/': ' ', ' ': ''
    }
    
    def __init__(self):
        """Initialize the crypto module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check available crypto tools."""
        tools = ['john', 'hashcat', 'hashid', 'hash-identifier']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str,
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a file for cryptographic content.
        
        Args:
            target: Path to target file
            output_dir: Directory for output files
            extracted_dir: Directory for extracted files
            mode: Analysis mode
            
        Returns:
            List of ToolResult objects
        """
        results = []
        
        # Read file content
        try:
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            content = ""
        
        # Also read as binary
        try:
            with open(target, 'rb') as f:
                binary_content = f.read()
        except Exception:
            binary_content = b""
        
        # Try various decodings
        results.append(self._try_base64(content, output_dir))
        results.append(self._try_hex(content, output_dir))
        results.append(self._try_binary(content, output_dir))
        results.append(self._try_rot13(content, output_dir))
        results.append(self._try_caesar_all(content, output_dir))
        results.append(self._try_morse(content, output_dir))
        results.append(self._identify_hashes(content, output_dir))
        
        # Try to decode any base64-looking strings in the file
        results.append(self._find_and_decode_base64(content, output_dir))
        
        return results
    
    def _try_base64(self, content: str, output_dir: str) -> ToolResult:
        """Try to decode base64."""
        results = []
        flags = []
        
        # Clean the content
        cleaned = content.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        
        # Try standard base64
        try:
            decoded = base64.b64decode(cleaned).decode('utf-8', errors='ignore')
            if decoded and self._is_readable(decoded):
                results.append(f"Base64 decoded:\n{decoded}")
                flags.extend(self._extract_flags(decoded))
                
                # Try decoding again (nested base64)
                try:
                    double_decoded = base64.b64decode(decoded.strip()).decode('utf-8', errors='ignore')
                    if double_decoded and self._is_readable(double_decoded):
                        results.append(f"\nDouble base64 decoded:\n{double_decoded}")
                        flags.extend(self._extract_flags(double_decoded))
                except Exception:
                    pass
        except Exception:
            pass
        
        # Try base32
        try:
            decoded = base64.b32decode(cleaned.upper()).decode('utf-8', errors='ignore')
            if decoded and self._is_readable(decoded):
                results.append(f"Base32 decoded:\n{decoded}")
                flags.extend(self._extract_flags(decoded))
        except Exception:
            pass
        
        # Try base85
        try:
            decoded = base64.b85decode(cleaned).decode('utf-8', errors='ignore')
            if decoded and self._is_readable(decoded):
                results.append(f"Base85 decoded:\n{decoded}")
                flags.extend(self._extract_flags(decoded))
        except Exception:
            pass
        
        output = '\n'.join(results) if results else "No valid base64/32/85 encoding detected"
        
        # Save output
        with open(os.path.join(output_dir, "base64_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="base64_decode",
            command="base64 -d",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _try_hex(self, content: str, output_dir: str) -> ToolResult:
        """Try to decode hexadecimal."""
        results = []
        flags = []
        
        # Clean and extract hex
        hex_pattern = re.compile(r'[0-9a-fA-F]+')
        matches = hex_pattern.findall(content)
        
        for match in matches:
            if len(match) >= 4 and len(match) % 2 == 0:
                try:
                    decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                    if decoded and self._is_readable(decoded) and len(decoded) >= 2:
                        results.append(f"Hex '{match[:20]}...' decoded: {decoded}")
                        flags.extend(self._extract_flags(decoded))
                except Exception:
                    pass
        
        # Also try the entire content as hex
        cleaned = re.sub(r'[^0-9a-fA-F]', '', content)
        if len(cleaned) >= 4 and len(cleaned) % 2 == 0:
            try:
                decoded = bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
                if decoded and self._is_readable(decoded):
                    results.append(f"Full content as hex:\n{decoded}")
                    flags.extend(self._extract_flags(decoded))
            except Exception:
                pass
        
        output = '\n'.join(results) if results else "No valid hex encoding detected"
        
        with open(os.path.join(output_dir, "hex_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="hex_decode",
            command="xxd -r",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _try_binary(self, content: str, output_dir: str) -> ToolResult:
        """Try to decode binary (0s and 1s)."""
        results = []
        flags = []
        
        # Extract binary patterns
        binary_pattern = re.compile(r'[01\s]+')
        matches = binary_pattern.findall(content)
        
        for match in matches:
            # Clean binary string
            binary = re.sub(r'[^01]', '', match)
            
            if len(binary) >= 8 and len(binary) % 8 == 0:
                try:
                    # Convert binary to text
                    decoded = ''.join(
                        chr(int(binary[i:i+8], 2))
                        for i in range(0, len(binary), 8)
                    )
                    if decoded and self._is_readable(decoded):
                        results.append(f"Binary decoded: {decoded}")
                        flags.extend(self._extract_flags(decoded))
                except Exception:
                    pass
        
        output = '\n'.join(results) if results else "No valid binary encoding detected"
        
        with open(os.path.join(output_dir, "binary_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="binary_decode",
            command="binary to ASCII",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _try_rot13(self, content: str, output_dir: str) -> ToolResult:
        """Try ROT13 decoding."""
        decoded = codecs.decode(content, 'rot_13')
        flags = self._extract_flags(decoded)
        
        output = f"ROT13 decoded:\n{decoded}"
        
        with open(os.path.join(output_dir, "rot13_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="rot13_decode",
            command="tr 'A-Za-z' 'N-ZA-Mn-za-m'",
            success=True,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=flags
        )
    
    def _try_caesar_all(self, content: str, output_dir: str) -> ToolResult:
        """Try all Caesar cipher shifts."""
        results = []
        flags = []
        
        for shift in range(1, 26):
            decoded = self._caesar_shift(content, shift)
            found_flags = self._extract_flags(decoded)
            
            if found_flags:
                results.append(f"ROT{shift}: {decoded}")
                flags.extend(found_flags)
            elif shift in [7, 11, 13, 19, 23]:  # Common shifts
                results.append(f"ROT{shift}: {decoded[:100]}...")
        
        output = '\n\n'.join(results) if results else "No flags found in Caesar shifts"
        
        with open(os.path.join(output_dir, "caesar_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="caesar_decode",
            command="Caesar cipher brute force",
            success=len(flags) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _caesar_shift(self, text: str, shift: int) -> str:
        """Shift text by given amount."""
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    def _try_morse(self, content: str, output_dir: str) -> ToolResult:
        """Try to decode Morse code."""
        results = []
        flags = []
        
        # Detect if content looks like morse code
        morse_chars = set('.-/ \n\t')
        content_chars = set(content.replace(' ', '').replace('\n', ''))
        
        if content_chars.issubset(morse_chars) or '.-' in content or '-.' in content:
            # Try to decode
            decoded = self._decode_morse(content)
            if decoded:
                results.append(f"Morse decoded: {decoded}")
                flags.extend(self._extract_flags(decoded))
        
        output = '\n'.join(results) if results else "No morse code detected"
        
        with open(os.path.join(output_dir, "morse_decode.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="morse_decode",
            command="Morse code decoder",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _decode_morse(self, morse: str) -> str:
        """Decode morse code to text."""
        # Normalize separators
        morse = morse.replace('/', ' / ')
        morse = re.sub(r'\s+', ' ', morse)
        
        words = morse.strip().split(' / ')
        decoded_words = []
        
        for word in words:
            letters = word.strip().split(' ')
            decoded_word = ''
            for letter in letters:
                letter = letter.strip()
                if letter in self.MORSE_CODE:
                    decoded_word += self.MORSE_CODE[letter]
            if decoded_word:
                decoded_words.append(decoded_word)
        
        return ' '.join(decoded_words)
    
    def _identify_hashes(self, content: str, output_dir: str) -> ToolResult:
        """Identify hash types in content."""
        results = []
        
        # Find potential hashes
        words = content.split()
        
        for word in words:
            word = word.strip()
            for pattern, hash_type in self.HASH_PATTERNS.items():
                if re.match(pattern, word):
                    results.append(f"Possible {hash_type}: {word}")
                    break
        
        output = '\n'.join(results) if results else "No hashes identified"
        
        with open(os.path.join(output_dir, "hash_identify.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="hash_identify",
            command="Hash identification",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=[]
        )
    
    def _find_and_decode_base64(self, content: str, output_dir: str) -> ToolResult:
        """Find and decode base64 strings within content."""
        results = []
        flags = []
        
        # Pattern for base64 strings
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        matches = b64_pattern.findall(content)
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and self._is_readable(decoded):
                    results.append(f"Found base64 '{match[:30]}...' -> {decoded}")
                    flags.extend(self._extract_flags(decoded))
            except Exception:
                pass
        
        output = '\n'.join(results) if results else "No embedded base64 found"
        
        with open(os.path.join(output_dir, "embedded_base64.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="embedded_base64",
            command="Extract and decode embedded base64",
            success=len(results) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _is_readable(self, text: str) -> bool:
        """Check if text is human-readable."""
        if not text or len(text) < 2:
            return False
        
        # Count printable characters
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        ratio = printable / len(text)
        
        return ratio > 0.7
    
    def _extract_flags(self, text: str) -> List[str]:
        """Extract flags from text."""
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'THM\{[^}]+\}',
        ]
        
        flags = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
