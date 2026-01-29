#!/usr/bin/env python3
"""
Pattern Extractor - Extract hidden patterns, URLs, flags, and data from files
Author: Prudhvi (CTFHunter)
Version: 2.2.0
"""

import re
import os
import subprocess
from typing import Dict, List, Optional


class PatternExtractor:
    """Extract various patterns and hidden data from files and text"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.results = {
            'flags': [],
            'urls': [],
            'emails': [],
            'ip_addresses': [],
            'hashes': [],
            'base64_strings': [],
            'hex_strings': [],
            'credentials': [],
            'file_paths': [],
            'domains': [],
            'phone_numbers': [],
            'social_media': [],
            'crypto_addresses': [],
            'api_keys': [],
            'interesting_strings': []
        }
    
    # Comprehensive regex patterns
    PATTERNS = {
        'flag_generic': r'[A-Za-z0-9_]+\{[^}]{3,100}\}',
        'flag_common': r'(?:flag|FLAG|ctf|CTF|key|KEY|secret|SECRET|pass|PASS)\{[^}]+\}',
        
        'url': r'https?://[^\s<>"\']+',
        'url_no_proto': r'(?:www\.)[a-zA-Z0-9][a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s]*',
        
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv4_port': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b',
        'ipv6': r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
        
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'sha512': r'\b[a-fA-F0-9]{128}\b',
        
        'base64': r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        'hex_string': r'(?:0x)?[a-fA-F0-9]{8,}',
        
        'password_field': r'(?:password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']?([^"\'&\s]+)',
        'username_field': r'(?:username|user|login|usr)["\']?\s*[:=]\s*["\']?([^"\'&\s]+)',
        'api_key': r'(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
        'token': r'(?:token|auth|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_.-]{20,})',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        
        'unix_path': r'(?:/[a-zA-Z0-9_.-]+)+',
        'windows_path': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        
        'phone_us': r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'phone_intl': r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        
        'twitter': r'(?:@|twitter\.com/)[a-zA-Z0-9_]{1,15}',
        'github': r'github\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?',
        
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        'ssh_key': r'ssh-(?:rsa|dss|ed25519) [A-Za-z0-9+/]+',
    }
    
    def analyze_file(self, filepath: str, flag_format: str = "flag{}") -> Dict:
        """Analyze a file for patterns"""
        print(f"\n🔎 Extracting patterns from: {os.path.basename(filepath)}")
        
        if not os.path.exists(filepath):
            print(f"  ❌ File not found: {filepath}")
            return self.results
        
        # Read file content
        content = self._read_file(filepath)
        
        if content:
            self._extract_all_patterns(content, flag_format)
        
        # Also run strings command for binary files
        strings_output = self._run_strings(filepath)
        if strings_output:
            self._extract_all_patterns(strings_output, flag_format)
        
        self._print_results()
        return self.results
    
    def analyze_text(self, text: str, flag_format: str = "flag{}") -> Dict:
        """Analyze text for patterns"""
        print(f"\n🔎 Extracting patterns from text...")
        self._extract_all_patterns(text, flag_format)
        self._print_results()
        return self.results
    
    def _read_file(self, filepath: str) -> Optional[str]:
        """Read file content"""
        try:
            # Try text mode first
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            try:
                # Try binary mode
                with open(filepath, 'rb') as f:
                    return f.read().decode('utf-8', errors='ignore')
            except:
                return None
    
    def _run_strings(self, filepath: str) -> Optional[str]:
        """Run strings command on file"""
        try:
            result = subprocess.run(
                ['strings', '-a', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except:
            return None
    
    def _extract_all_patterns(self, content: str, flag_format: str):
        """Extract all patterns from content"""
        
        # Custom flag format
        prefix = flag_format.replace('{}', '').replace('{', '').replace('}', '')
        custom_flag_pattern = rf'{re.escape(prefix)}\{{[^}}]+\}}'
        
        # Extract flags
        self._add_unique(self.results['flags'], 
                        re.findall(custom_flag_pattern, content, re.IGNORECASE))
        self._add_unique(self.results['flags'], 
                        re.findall(self.PATTERNS['flag_common'], content))
        self._add_unique(self.results['flags'], 
                        re.findall(self.PATTERNS['flag_generic'], content))
        
        # Extract URLs
        self._add_unique(self.results['urls'], 
                        re.findall(self.PATTERNS['url'], content))
        
        # Extract emails
        self._add_unique(self.results['emails'], 
                        re.findall(self.PATTERNS['email'], content))
        
        # Extract IPs
        self._add_unique(self.results['ip_addresses'], 
                        re.findall(self.PATTERNS['ipv4'], content))
        self._add_unique(self.results['ip_addresses'], 
                        re.findall(self.PATTERNS['ipv4_port'], content))
        
        # Extract hashes
        for hash_val in re.findall(self.PATTERNS['sha256'], content):
            self._add_unique(self.results['hashes'], [f"SHA256: {hash_val}"])
        for hash_val in re.findall(self.PATTERNS['sha1'], content):
            if len(hash_val) == 40:  # Exact SHA1 length
                self._add_unique(self.results['hashes'], [f"SHA1: {hash_val}"])
        for hash_val in re.findall(self.PATTERNS['md5'], content):
            if len(hash_val) == 32:  # Exact MD5 length
                self._add_unique(self.results['hashes'], [f"MD5: {hash_val}"])
        
        # Extract Base64 strings (min 20 chars)
        b64_matches = re.findall(self.PATTERNS['base64'], content)
        for match in b64_matches:
            if len(match) >= 20 and not match.isalnum():
                self._add_unique(self.results['base64_strings'], [match[:100]])
        
        # Extract credentials
        for match in re.finditer(self.PATTERNS['password_field'], content, re.IGNORECASE):
            self._add_unique(self.results['credentials'], [f"Password: {match.group(1)}"])
        for match in re.finditer(self.PATTERNS['username_field'], content, re.IGNORECASE):
            self._add_unique(self.results['credentials'], [f"Username: {match.group(1)}"])
        
        # Extract JWTs
        jwts = re.findall(self.PATTERNS['jwt'], content)
        self._add_unique(self.results['api_keys'], [f"JWT: {jwt[:50]}..." for jwt in jwts])
        
        # Extract API keys
        for match in re.finditer(self.PATTERNS['api_key'], content, re.IGNORECASE):
            self._add_unique(self.results['api_keys'], [f"API Key: {match.group(1)}"])
        
        # AWS keys
        aws_keys = re.findall(self.PATTERNS['aws_key'], content)
        self._add_unique(self.results['api_keys'], [f"AWS Key: {k}" for k in aws_keys])
        
        # Extract crypto addresses
        btc = re.findall(self.PATTERNS['bitcoin'], content)
        eth = re.findall(self.PATTERNS['ethereum'], content)
        self._add_unique(self.results['crypto_addresses'], [f"BTC: {a}" for a in btc])
        self._add_unique(self.results['crypto_addresses'], [f"ETH: {a}" for a in eth])
        
        # Extract interesting strings (potential flags or secrets)
        self._find_interesting_strings(content)
    
    def _find_interesting_strings(self, content: str):
        """Find interesting strings that might be flags or secrets"""
        # Look for strings in common CTF patterns
        patterns = [
            r'(?:secret|hidden|flag|key|password|cipher|decode|encrypt)[:\s]+([^\n]{5,50})',
            r'(?:The answer is|Flag is|Key is)[:\s]+([^\n]{5,50})',
            r'<!--\s*([^>]{5,100})\s*-->',  # HTML comments
            r'#\s*TODO[:\s]+([^\n]+)',  # TODO comments
            r'(?:base64|hex|rot13|caesar)[:\s]+([^\n]{5,100})',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.strip()) > 3:
                    self._add_unique(self.results['interesting_strings'], [match.strip()[:100]])
    
    def _add_unique(self, target_list: List, items: List):
        """Add unique items to list"""
        for item in items:
            if item and item not in target_list:
                target_list.append(item)
    
    def _print_results(self):
        """Print extraction results"""
        total = sum(len(v) for v in self.results.values())
        
        if total == 0:
            print("  ℹ️  No patterns found")
            return
        
        print(f"\n  📊 Extracted {total} pattern(s):\n")
        
        categories = [
            ('flags', '🚩 Flags'),
            ('urls', '🔗 URLs'),
            ('emails', '📧 Emails'),
            ('ip_addresses', '🌐 IP Addresses'),
            ('hashes', '#️⃣ Hashes'),
            ('credentials', '🔐 Credentials'),
            ('api_keys', '🔑 API Keys/Tokens'),
            ('crypto_addresses', '💰 Crypto Addresses'),
            ('base64_strings', '📝 Base64 Strings'),
            ('interesting_strings', '⭐ Interesting Strings'),
        ]
        
        for key, label in categories:
            if self.results[key]:
                print(f"  {label}:")
                for item in self.results[key][:10]:  # Limit to 10 per category
                    print(f"     • {item}")
                if len(self.results[key]) > 10:
                    print(f"     ... and {len(self.results[key]) - 10} more")
                print()


def extract_patterns(filepath: str, flag_format: str = "flag{}") -> Dict:
    """Convenience function for pattern extraction"""
    extractor = PatternExtractor()
    return extractor.analyze_file(filepath, flag_format)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        extract_patterns(sys.argv[1])
    else:
        # Test with sample text
        test_text = """
        Check out flag{this_is_a_test_flag}
        Email: admin@example.com
        Server: 192.168.1.100:8080
        Hash: 5d41402abc4b2a76b9719d911017c592
        Secret: SGVsbG8gV29ybGQ=
        API_KEY=sk_live_1234567890abcdef
        """
        extractor = PatternExtractor()
        extractor.analyze_text(test_text)
