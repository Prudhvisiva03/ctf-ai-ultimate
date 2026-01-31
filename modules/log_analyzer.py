#!/usr/bin/env python3
"""
Log File Analyzer Module
Parse and analyze various log formats for CTF clues
"""

import re
import os
from typing import Dict, List, Optional
from datetime import datetime
from collections import Counter


class LogAnalyzer:
    """Analyze log files for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'log_type': None,
            'total_lines': 0,
            'ip_addresses': [],
            'urls': [],
            'user_agents': [],
            'credentials': [],
            'suspicious_entries': [],
            'encoded_data': [],
            'flags_found': [],
            'statistics': {}
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
        
        # Log format patterns
        self.log_patterns = {
            'apache_combined': r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(\w+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"',
            'apache_common': r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(\w+) ([^"]+)" (\d+) (\d+)',
            'nginx': r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(\w+) ([^"]+)" (\d+) (\d+)',
            'auth_log': r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)',
            'syslog': r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)',
            'windows_event': r'(\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+(\S+)\s+(\S+)\s+(.*)',
        }
        
        # Suspicious patterns to look for
        self.suspicious_patterns = {
            'sql_injection': [
                r"('|\")\s*(OR|AND)\s*('|\")?1('|\")?=('|\")?1",
                r"UNION\s+SELECT",
                r"DROP\s+TABLE",
                r"INSERT\s+INTO",
                r"--\s*$",
                r";\s*DROP",
            ],
            'xss': [
                r"<script[^>]*>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
                r"eval\s*\(",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"/etc/shadow",
                r"C:\\Windows",
            ],
            'command_injection': [
                r";\s*(ls|cat|wget|curl|nc|bash)",
                r"\|\s*(ls|cat|wget|curl|nc|bash)",
                r"`[^`]+`",
                r"\$\([^)]+\)",
            ],
            'brute_force': [
                r"Failed password",
                r"authentication failure",
                r"Invalid user",
                r"401\s+Unauthorized",
            ],
        }
    
    def _search_flags(self, text: str):
        """Search for flags in text"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags_found']:
                    self.results['flags_found'].append(match)
                    print(f"[FLAG] Found: {match}")
    
    def detect_log_type(self, content: str) -> str:
        """Detect the type of log file"""
        lines = content.split('\n')[:100]  # Check first 100 lines
        
        for line in lines:
            for log_type, pattern in self.log_patterns.items():
                if re.match(pattern, line):
                    self.results['log_type'] = log_type
                    return log_type
        
        # Check for common keywords
        if 'sshd' in content or 'pam_unix' in content:
            self.results['log_type'] = 'auth_log'
            return 'auth_log'
        elif 'HTTP' in content or 'GET /' in content or 'POST /' in content:
            self.results['log_type'] = 'web_access'
            return 'web_access'
        elif 'EventID' in content or 'Windows' in content:
            self.results['log_type'] = 'windows_event'
            return 'windows_event'
        
        self.results['log_type'] = 'unknown'
        return 'unknown'
    
    def extract_ip_addresses(self, content: str) -> List[str]:
        """Extract all IP addresses"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        
        # Count occurrences
        ip_counts = Counter(ips)
        
        self.results['ip_addresses'] = ip_counts.most_common(50)
        self.results['statistics']['unique_ips'] = len(ip_counts)
        
        return list(ip_counts.keys())
    
    def extract_urls(self, content: str) -> List[str]:
        """Extract URLs and paths"""
        # Full URLs
        url_pattern = r'https?://[^\s<>"\']+|/[^\s<>"\'?#]+'
        urls = re.findall(url_pattern, content)
        
        url_counts = Counter(urls)
        self.results['urls'] = url_counts.most_common(50)
        
        # Check for interesting paths
        interesting_paths = []
        keywords = ['flag', 'admin', 'secret', 'hidden', 'backup', 'config', 
                   'password', 'login', 'upload', 'shell', 'cmd']
        
        for url in urls:
            for keyword in keywords:
                if keyword in url.lower():
                    interesting_paths.append(url)
                    break
        
        if interesting_paths:
            self.results['suspicious_entries'].extend(
                [f"Interesting path: {p}" for p in set(interesting_paths)]
            )
        
        return list(url_counts.keys())
    
    def extract_user_agents(self, content: str) -> List[str]:
        """Extract User-Agent strings"""
        ua_pattern = r'"([^"]*(?:Mozilla|curl|wget|python|bot|spider|crawler)[^"]*)"'
        user_agents = re.findall(ua_pattern, content, re.IGNORECASE)
        
        ua_counts = Counter(user_agents)
        self.results['user_agents'] = ua_counts.most_common(20)
        
        # Check for suspicious user agents
        suspicious_ua = ['sqlmap', 'nikto', 'nmap', 'dirb', 'gobuster', 
                        'wfuzz', 'burp', 'hydra', 'medusa']
        
        for ua in user_agents:
            for sus in suspicious_ua:
                if sus in ua.lower():
                    self.results['suspicious_entries'].append(f"Suspicious UA: {ua[:100]}")
                    break
        
        return list(ua_counts.keys())
    
    def find_credentials(self, content: str) -> List[str]:
        """Search for credentials in logs"""
        credentials = []
        
        # Username/password patterns
        patterns = [
            r'user(?:name)?[=:]\s*([^\s&]+)',
            r'pass(?:word)?[=:]\s*([^\s&]+)',
            r'login[=:]\s*([^\s&]+)',
            r'pwd[=:]\s*([^\s&]+)',
            r'auth[=:]\s*([^\s&]+)',
            r'token[=:]\s*([^\s&]+)',
            r'api[_-]?key[=:]\s*([^\s&]+)',
            r'secret[=:]\s*([^\s&]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and match not in ['admin', 'root', 'user']:
                    credentials.append(f"{pattern.split('[')[0]}: {match}")
        
        # Base64 encoded data in URLs
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        b64_matches = re.findall(b64_pattern, content)
        
        for match in b64_matches[:10]:
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded.isprintable() and len(decoded) > 5:
                    self.results['encoded_data'].append(f"Base64: {match[:30]}... -> {decoded[:50]}")
                    self._search_flags(decoded)
            except:
                pass
        
        self.results['credentials'] = list(set(credentials))
        return credentials
    
    def detect_attacks(self, content: str) -> Dict[str, List[str]]:
        """Detect attack patterns in logs"""
        attacks = {}
        
        for attack_type, patterns in self.suspicious_patterns.items():
            findings = []
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.extend(matches[:5])  # Limit per pattern
            
            if findings:
                attacks[attack_type] = findings
                self.results['suspicious_entries'].append(
                    f"{attack_type}: {len(findings)} occurrences"
                )
        
        return attacks
    
    def analyze_timeline(self, content: str) -> Dict:
        """Analyze time-based patterns"""
        timeline = {}
        
        # Common timestamp patterns
        timestamp_patterns = [
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',  # Apache
            r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})',  # Syslog
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # ISO
        ]
        
        timestamps = []
        for pattern in timestamp_patterns:
            matches = re.findall(pattern, content)
            if matches:
                timestamps = matches
                break
        
        if timestamps:
            timeline['first_entry'] = timestamps[0]
            timeline['last_entry'] = timestamps[-1]
            timeline['total_entries'] = len(timestamps)
            
            # Check for rapid requests (potential brute force)
            if len(timestamps) > 100:
                self.results['statistics']['entries_per_minute'] = 'High activity detected'
        
        return timeline
    
    def extract_encoded_strings(self, content: str) -> List[str]:
        """Find and decode encoded strings"""
        encoded = []
        
        # Hex strings
        hex_pattern = r'(?:0x)?[0-9a-fA-F]{16,}'
        hex_matches = re.findall(hex_pattern, content)
        
        for match in hex_matches[:10]:
            try:
                decoded = bytes.fromhex(match.replace('0x', '')).decode('utf-8', errors='ignore')
                if decoded.isprintable() and len(decoded) > 3:
                    encoded.append(f"Hex: {match[:20]}... -> {decoded[:50]}")
                    self._search_flags(decoded)
            except:
                pass
        
        # URL encoded
        url_encoded = r'%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2})+'
        url_matches = re.findall(url_encoded, content)
        
        for match in url_matches[:10]:
            try:
                from urllib.parse import unquote
                decoded = unquote(match)
                if decoded != match:
                    encoded.append(f"URL: {match[:20]}... -> {decoded[:50]}")
                    self._search_flags(decoded)
            except:
                pass
        
        self.results['encoded_data'].extend(encoded)
        return encoded
    
    def analyze(self, filepath: str) -> Dict:
        """Full log analysis"""
        print(f"\n[*] Analyzing log file: {filepath}")
        print("=" * 60)
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return self.results
        
        # Read file
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return self.results
        
        self.results['total_lines'] = content.count('\n')
        print(f"[*] Total lines: {self.results['total_lines']}")
        
        # Search for flags first
        self._search_flags(content)
        
        # Detect log type
        log_type = self.detect_log_type(content)
        print(f"[*] Log type detected: {log_type}")
        
        # Run analyses
        print("[*] Extracting IP addresses...")
        self.extract_ip_addresses(content)
        print(f"[+] Found {self.results['statistics'].get('unique_ips', 0)} unique IPs")
        
        print("[*] Extracting URLs...")
        self.extract_urls(content)
        print(f"[+] Found {len(self.results['urls'])} URLs")
        
        print("[*] Extracting User-Agents...")
        self.extract_user_agents(content)
        
        print("[*] Searching for credentials...")
        self.find_credentials(content)
        print(f"[+] Found {len(self.results['credentials'])} credential entries")
        
        print("[*] Detecting attack patterns...")
        attacks = self.detect_attacks(content)
        if attacks:
            print(f"[!] Detected attacks: {', '.join(attacks.keys())}")
        
        print("[*] Extracting encoded strings...")
        self.extract_encoded_strings(content)
        
        print("[*] Analyzing timeline...")
        self.analyze_timeline(content)
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] Log Analysis Summary")
        print("=" * 60)
        
        if self.results['flags_found']:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.results['flags_found'])}")
            for flag in self.results['flags_found']:
                print(f"  -> {flag}")
        
        if self.results['suspicious_entries']:
            print(f"\n[!] SUSPICIOUS ENTRIES: {len(self.results['suspicious_entries'])}")
            for entry in self.results['suspicious_entries'][:10]:
                print(f"  -> {entry}")
        
        if self.results['credentials']:
            print(f"\n[+] CREDENTIALS: {len(self.results['credentials'])}")
            for cred in self.results['credentials'][:10]:
                print(f"  -> {cred}")
        
        if self.results['encoded_data']:
            print(f"\n[+] ENCODED DATA: {len(self.results['encoded_data'])}")
            for data in self.results['encoded_data'][:10]:
                print(f"  -> {data}")
        
        # Top IPs
        if self.results['ip_addresses']:
            print(f"\n[*] TOP IPs:")
            for ip, count in self.results['ip_addresses'][:5]:
                print(f"  -> {ip}: {count} requests")
        
        return self.results
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        lines = ["Log File Analysis Results", "=" * 40]
        
        lines.append(f"Log type: {self.results['log_type']}")
        lines.append(f"Total lines: {self.results['total_lines']}")
        lines.append(f"Unique IPs: {self.results['statistics'].get('unique_ips', 0)}")
        lines.append(f"URLs found: {len(self.results['urls'])}")
        lines.append(f"Credentials: {len(self.results['credentials'])}")
        lines.append(f"Suspicious entries: {len(self.results['suspicious_entries'])}")
        lines.append(f"Flags found: {len(self.results['flags_found'])}")
        
        if self.results['flags_found']:
            lines.append("\nFlags:")
            for flag in self.results['flags_found']:
                lines.append(f"  {flag}")
        
        return '\n'.join(lines)
