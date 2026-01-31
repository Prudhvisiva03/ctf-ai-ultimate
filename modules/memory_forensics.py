#!/usr/bin/env python3
"""
Memory Forensics Module
Analyze memory dumps using Volatility framework
"""

import subprocess
import os
import re
from typing import Dict, List, Optional


class MemoryForensics:
    """Analyze memory dumps for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'profile': None,
            'processes': [],
            'network_connections': [],
            'credentials': [],
            'command_history': [],
            'files': [],
            'registry_keys': [],
            'flags_found': [],
            'suspicious_items': []
        }
        
        # Common flag patterns
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}'
        ]
    
    def is_volatility_available(self) -> bool:
        """Check if Volatility is installed"""
        for cmd in ['vol.py', 'volatility', 'vol', 'volatility3', 'vol3']:
            try:
                result = subprocess.run([cmd, '-h'], capture_output=True, timeout=10)
                if result.returncode == 0:
                    self.vol_cmd = cmd
                    return True
            except:
                continue
        return False
    
    def detect_profile(self, filepath: str) -> Optional[str]:
        """Detect memory image profile"""
        print("[*] Detecting memory profile...")
        
        if not self.is_volatility_available():
            print("[!] Volatility not installed")
            return None
        
        try:
            # Try Volatility 3 first
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.info'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                self.results['profile'] = 'Windows (Volatility 3)'
                return 'windows'
            
            # Try Volatility 2 imageinfo
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'imageinfo'],
                capture_output=True, text=True, timeout=120
            )
            
            if 'Suggested Profile' in result.stdout:
                match = re.search(r'Suggested Profile\(s\) : ([^\n]+)', result.stdout)
                if match:
                    profile = match.group(1).split(',')[0].strip()
                    self.results['profile'] = profile
                    print(f"[+] Detected profile: {profile}")
                    return profile
                    
        except Exception as e:
            print(f"[!] Profile detection error: {e}")
        
        return None
    
    def list_processes(self, filepath: str, profile: str = None) -> List[Dict]:
        """List running processes"""
        print("[*] Listing processes...")
        
        try:
            # Volatility 3
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.pslist'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode != 0 and profile:
                # Volatility 2
                result = subprocess.run(
                    [self.vol_cmd, '-f', filepath, '--profile=' + profile, 'pslist'],
                    capture_output=True, text=True, timeout=120
                )
            
            processes = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('Volatility'):
                    processes.append(line.strip())
                    # Check for suspicious processes
                    suspicious = ['mimikatz', 'pwdump', 'procdump', 'nc.exe', 'netcat']
                    for s in suspicious:
                        if s.lower() in line.lower():
                            self.results['suspicious_items'].append(f"Suspicious process: {line}")
            
            self.results['processes'] = processes[:50]  # Limit output
            print(f"[+] Found {len(processes)} processes")
            
            # Search for flags in process names
            self._search_flags(result.stdout)
            
            return processes
            
        except Exception as e:
            print(f"[!] Process listing error: {e}")
            return []
    
    def dump_credentials(self, filepath: str, profile: str = None) -> List[str]:
        """Attempt to extract credentials"""
        print("[*] Searching for credentials...")
        
        credentials = []
        
        try:
            # Try hashdump
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.hashdump'],
                capture_output=True, text=True, timeout=180
            )
            
            if result.returncode != 0 and profile:
                result = subprocess.run(
                    [self.vol_cmd, '-f', filepath, '--profile=' + profile, 'hashdump'],
                    capture_output=True, text=True, timeout=180
                )
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith('Volatility'):
                        credentials.append(line.strip())
                        
            # Try lsadump
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.lsadump'],
                capture_output=True, text=True, timeout=180
            )
            
            if result.stdout:
                self._search_flags(result.stdout)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        credentials.append(line.strip())
            
            self.results['credentials'] = credentials
            print(f"[+] Found {len(credentials)} credential entries")
            
        except Exception as e:
            print(f"[!] Credential extraction error: {e}")
        
        return credentials
    
    def get_network_connections(self, filepath: str, profile: str = None) -> List[str]:
        """Get network connections"""
        print("[*] Extracting network connections...")
        
        try:
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.netscan'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode != 0 and profile:
                result = subprocess.run(
                    [self.vol_cmd, '-f', filepath, '--profile=' + profile, 'netscan'],
                    capture_output=True, text=True, timeout=120
                )
            
            connections = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('Volatility'):
                    connections.append(line.strip())
            
            self.results['network_connections'] = connections[:30]
            print(f"[+] Found {len(connections)} network connections")
            
            self._search_flags(result.stdout)
            
            return connections
            
        except Exception as e:
            print(f"[!] Network extraction error: {e}")
            return []
    
    def get_command_history(self, filepath: str, profile: str = None) -> List[str]:
        """Extract command history"""
        print("[*] Extracting command history...")
        
        try:
            # Try cmdscan
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.cmdscan'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode != 0 and profile:
                result = subprocess.run(
                    [self.vol_cmd, '-f', filepath, '--profile=' + profile, 'cmdscan'],
                    capture_output=True, text=True, timeout=120
                )
            
            self._search_flags(result.stdout)
            
            # Also try consoles
            result2 = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.consoles'],
                capture_output=True, text=True, timeout=120
            )
            
            self._search_flags(result2.stdout)
            
            commands = []
            for output in [result.stdout, result2.stdout]:
                for line in output.split('\n'):
                    if line.strip():
                        commands.append(line.strip())
            
            self.results['command_history'] = commands[:50]
            print(f"[+] Found {len(commands)} command entries")
            
            return commands
            
        except Exception as e:
            print(f"[!] Command history error: {e}")
            return []
    
    def scan_for_files(self, filepath: str, profile: str = None) -> List[str]:
        """Scan for interesting files"""
        print("[*] Scanning for files...")
        
        try:
            result = subprocess.run(
                [self.vol_cmd, '-f', filepath, 'windows.filescan'],
                capture_output=True, text=True, timeout=180
            )
            
            if result.returncode != 0 and profile:
                result = subprocess.run(
                    [self.vol_cmd, '-f', filepath, '--profile=' + profile, 'filescan'],
                    capture_output=True, text=True, timeout=180
                )
            
            interesting_files = []
            interesting_keywords = ['flag', 'secret', 'password', 'key', 'ctf', 
                                   'hidden', 'private', 'credential', '.txt', '.kdbx']
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                for keyword in interesting_keywords:
                    if keyword in line_lower:
                        interesting_files.append(line.strip())
                        break
            
            self.results['files'] = interesting_files[:30]
            print(f"[+] Found {len(interesting_files)} interesting files")
            
            self._search_flags(result.stdout)
            
            return interesting_files
            
        except Exception as e:
            print(f"[!] File scan error: {e}")
            return []
    
    def extract_strings_from_memory(self, filepath: str) -> List[str]:
        """Extract strings and search for flags"""
        print("[*] Extracting strings from memory dump...")
        
        try:
            result = subprocess.run(
                ['strings', '-a', filepath],
                capture_output=True, text=True, timeout=300
            )
            
            self._search_flags(result.stdout)
            
            # Look for interesting strings
            interesting = []
            keywords = ['password', 'secret', 'flag', 'key', 'admin', 'root', 'credential']
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                for keyword in keywords:
                    if keyword in line_lower and len(line) < 200:
                        interesting.append(line.strip())
                        break
            
            return interesting[:100]
            
        except Exception as e:
            print(f"[!] String extraction error: {e}")
            return []
    
    def _search_flags(self, text: str):
        """Search for flag patterns in text"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags_found']:
                    self.results['flags_found'].append(match)
                    print(f"[FLAG] Found: {match}")
    
    def analyze(self, filepath: str) -> Dict:
        """Full memory analysis"""
        print(f"\n[*] Analyzing memory dump: {filepath}")
        print("=" * 60)
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return self.results
        
        # Check file size
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"[*] Memory dump size: {size_mb:.2f} MB")
        
        # Detect profile
        profile = self.detect_profile(filepath)
        
        if self.is_volatility_available():
            # Run all analyses
            self.list_processes(filepath, profile)
            self.get_command_history(filepath, profile)
            self.get_network_connections(filepath, profile)
            self.scan_for_files(filepath, profile)
            self.dump_credentials(filepath, profile)
        else:
            print("[!] Volatility not found - using basic analysis")
        
        # Always try strings
        self.extract_strings_from_memory(filepath)
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] Memory Analysis Summary")
        print("=" * 60)
        
        if self.results['flags_found']:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.results['flags_found'])}")
            for flag in self.results['flags_found']:
                print(f"  -> {flag}")
        
        if self.results['suspicious_items']:
            print(f"\n[!] SUSPICIOUS ITEMS: {len(self.results['suspicious_items'])}")
            for item in self.results['suspicious_items']:
                print(f"  -> {item}")
        
        return self.results
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        lines = ["Memory Forensics Analysis Results", "=" * 40]
        
        if self.results['profile']:
            lines.append(f"Profile: {self.results['profile']}")
        
        lines.append(f"Processes found: {len(self.results['processes'])}")
        lines.append(f"Network connections: {len(self.results['network_connections'])}")
        lines.append(f"Credentials found: {len(self.results['credentials'])}")
        lines.append(f"Interesting files: {len(self.results['files'])}")
        lines.append(f"Flags found: {len(self.results['flags_found'])}")
        
        if self.results['flags_found']:
            lines.append("\nFlags:")
            for flag in self.results['flags_found']:
                lines.append(f"  {flag}")
        
        return '\n'.join(lines)
