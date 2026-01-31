"""
CTFHunter - Flag Finder Module
==============================

Automatically searches for CTF flags using regex patterns
in files, text, and command outputs.
"""

import re
import os
from typing import List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class FlagMatch:
    """Data class representing a found flag."""
    flag: str
    pattern_name: str
    source: str
    context: str
    line_number: Optional[int] = None


class FlagFinder:
    """
    Flag finder for CTF challenges.
    
    Searches for common CTF flag formats using regex patterns.
    Supports custom flag patterns and context extraction.
    """
    
    # Standard CTF flag patterns
    DEFAULT_PATTERNS = {
        'flag': r'flag\{[^}]+\}',
        'FLAG': r'FLAG\{[^}]+\}',
        'ctf': r'ctf\{[^}]+\}',
        'CTF': r'CTF\{[^}]+\}',
        'htb': r'HTB\{[^}]+\}',
        'htb_lower': r'htb\{[^}]+\}',
        'thm': r'THM\{[^}]+\}',
        'thm_lower': r'thm\{[^}]+\}',
        'picoctf': r'picoCTF\{[^}]+\}',
        'pico': r'pico\{[^}]+\}',
        'hack': r'hack\{[^}]+\}',
        'HACK': r'HACK\{[^}]+\}',
        'root': r'root\{[^}]+\}',
        'user': r'user\{[^}]+\}',
        'key': r'key\{[^}]+\}',
        'KEY': r'KEY\{[^}]+\}',
        'secret': r'secret\{[^}]+\}',
        'SECRET': r'SECRET\{[^}]+\}',
        'password': r'password\{[^}]+\}',
        'digitalcyberhunt': r'digitalcyberhunt\{[^}]+\}',
        'dch': r'DCH\{[^}]+\}',
        'cyberhunt': r'cyberhunt\{[^}]+\}',
    }
    
    # Additional patterns for common encoded flags
    ENCODED_PATTERNS = {
        'base64_flag': r'ZmxhZ3s[A-Za-z0-9+/=]+',  # base64 of 'flag{'
        'hex_flag': r'666c61677b[0-9a-fA-F]+7d',   # hex of 'flag{...}'
    }
    
    def __init__(self, custom_patterns: Optional[dict] = None):
        """
        Initialize the flag finder.
        
        Args:
            custom_patterns: Additional custom patterns to search for
        """
        self.patterns = dict(self.DEFAULT_PATTERNS)
        self.encoded_patterns = dict(self.ENCODED_PATTERNS)
        
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        # Compile all patterns for efficiency
        self._compiled = {name: re.compile(pattern, re.IGNORECASE) 
                         for name, pattern in self.patterns.items()}
        self._compiled_encoded = {name: re.compile(pattern) 
                                  for name, pattern in self.encoded_patterns.items()}
    
    def search_text(self, text: str, source: str = "text") -> List[FlagMatch]:
        """
        Search for flags in a text string.
        
        Args:
            text: Text to search
            source: Description of the text source
            
        Returns:
            List of FlagMatch objects
        """
        found_flags: List[FlagMatch] = []
        seen: Set[str] = set()
        
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Search standard patterns
            for name, pattern in self._compiled.items():
                for match in pattern.finditer(line):
                    flag = match.group(0)
                    if flag not in seen:
                        seen.add(flag)
                        context = self._extract_context(lines, line_num - 1)
                        found_flags.append(FlagMatch(
                            flag=flag,
                            pattern_name=name,
                            source=source,
                            context=context,
                            line_number=line_num
                        ))
        
        return found_flags
    
    def search_file(self, file_path: str) -> List[FlagMatch]:
        """
        Search for flags in a file.
        
        Args:
            file_path: Path to the file to search
            
        Returns:
            List of FlagMatch objects
        """
        if not os.path.exists(file_path):
            return []
        
        found_flags: List[FlagMatch] = []
        
        # Try reading as text
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            found_flags.extend(self.search_text(content, file_path))
        except Exception:
            pass
        
        # Also search binary content
        try:
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Extract printable strings from binary
            strings = self._extract_strings(binary_content)
            for s in strings:
                matches = self.search_text(s, f"{file_path} (binary strings)")
                for match in matches:
                    if match.flag not in [f.flag for f in found_flags]:
                        found_flags.append(match)
        except Exception:
            pass
        
        return found_flags
    
    def search_directory(self, dir_path: str, recursive: bool = True) -> List[FlagMatch]:
        """
        Search for flags in all files in a directory.
        
        Args:
            dir_path: Path to the directory
            recursive: Whether to search recursively
            
        Returns:
            List of FlagMatch objects
        """
        found_flags: List[FlagMatch] = []
        seen_flags: Set[str] = set()
        
        if recursive:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    matches = self.search_file(file_path)
                    for match in matches:
                        if match.flag not in seen_flags:
                            seen_flags.add(match.flag)
                            found_flags.append(match)
        else:
            for item in os.listdir(dir_path):
                item_path = os.path.join(dir_path, item)
                if os.path.isfile(item_path):
                    matches = self.search_file(item_path)
                    for match in matches:
                        if match.flag not in seen_flags:
                            seen_flags.add(match.flag)
                            found_flags.append(match)
        
        return found_flags
    
    def search_bytes(self, data: bytes, source: str = "bytes") -> List[FlagMatch]:
        """
        Search for flags in binary data.
        
        Args:
            data: Binary data to search
            source: Description of the data source
            
        Returns:
            List of FlagMatch objects
        """
        found_flags: List[FlagMatch] = []
        
        # Try decoding as text
        try:
            text = data.decode('utf-8', errors='ignore')
            found_flags.extend(self.search_text(text, source))
        except Exception:
            pass
        
        # Extract and search strings
        strings = self._extract_strings(data)
        for s in strings:
            matches = self.search_text(s, f"{source} (strings)")
            for match in matches:
                if match.flag not in [f.flag for f in found_flags]:
                    found_flags.append(match)
        
        return found_flags
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from binary data.
        
        Args:
            data: Binary data
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    def _extract_context(self, lines: List[str], line_index: int, context_lines: int = 2) -> str:
        """
        Extract context around a match.
        
        Args:
            lines: All lines of text
            line_index: Index of the matching line
            context_lines: Number of context lines before/after
            
        Returns:
            Context string
        """
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        
        context_parts = []
        for i in range(start, end):
            prefix = ">>> " if i == line_index else "    "
            context_parts.append(f"{prefix}{lines[i]}")
        
        return '\n'.join(context_parts)
    
    def add_pattern(self, name: str, pattern: str):
        """
        Add a custom flag pattern.
        
        Args:
            name: Pattern name
            pattern: Regex pattern string
        """
        self.patterns[name] = pattern
        self._compiled[name] = re.compile(pattern, re.IGNORECASE)
    
    def remove_pattern(self, name: str):
        """
        Remove a flag pattern.
        
        Args:
            name: Pattern name to remove
        """
        if name in self.patterns:
            del self.patterns[name]
            del self._compiled[name]
    
    def validate_flag(self, flag: str) -> Tuple[bool, str]:
        """
        Validate if a string looks like a valid CTF flag.
        
        Args:
            flag: String to validate
            
        Returns:
            Tuple of (is_valid, pattern_name)
        """
        for name, pattern in self._compiled.items():
            if pattern.fullmatch(flag):
                return True, name
        return False, ""
    
    def get_all_patterns(self) -> dict:
        """Get all registered flag patterns."""
        return dict(self.patterns)
    
    def format_results(self, matches: List[FlagMatch], show_context: bool = True) -> str:
        """
        Format flag matches for display.
        
        Args:
            matches: List of flag matches
            show_context: Whether to show context
            
        Returns:
            Formatted string
        """
        if not matches:
            return "No flags found."
        
        lines = [f"Found {len(matches)} flag(s):\n"]
        
        for i, match in enumerate(matches, 1):
            lines.append(f"  [{i}] {match.flag}")
            lines.append(f"      Pattern: {match.pattern_name}")
            lines.append(f"      Source: {match.source}")
            if match.line_number:
                lines.append(f"      Line: {match.line_number}")
            if show_context and match.context:
                lines.append(f"      Context:")
                for ctx_line in match.context.split('\n'):
                    lines.append(f"        {ctx_line}")
            lines.append("")
        
        return '\n'.join(lines)
