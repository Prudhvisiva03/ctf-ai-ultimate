#!/usr/bin/env python3
"""
Hash Identifier - Detect hash types and attempt to crack common hashes
For CTF challenges involving hash cracking
Author: Prudhvi (CTFHunter)
Version: 2.1.0
"""

import re
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple


# Hash patterns and their characteristics
HASH_PATTERNS = {
    'MD5': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'MD5 (128-bit)',
        'example': '5d41402abc4b2a76b9719d911017c592'
    },
    'SHA1': {
        'length': 40,
        'pattern': r'^[a-fA-F0-9]{40}$',
        'description': 'SHA-1 (160-bit)',
        'example': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    },
    'SHA224': {
        'length': 56,
        'pattern': r'^[a-fA-F0-9]{56}$',
        'description': 'SHA-224 (224-bit)',
        'example': ''
    },
    'SHA256': {
        'length': 64,
        'pattern': r'^[a-fA-F0-9]{64}$',
        'description': 'SHA-256 (256-bit)',
        'example': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    },
    'SHA384': {
        'length': 96,
        'pattern': r'^[a-fA-F0-9]{96}$',
        'description': 'SHA-384 (384-bit)',
        'example': ''
    },
    'SHA512': {
        'length': 128,
        'pattern': r'^[a-fA-F0-9]{128}$',
        'description': 'SHA-512 (512-bit)',
        'example': ''
    },
    'NTLM': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'NTLM (Windows)',
        'example': ''
    },
    'MySQL5': {
        'length': 40,
        'pattern': r'^\*[a-fA-F0-9]{40}$',
        'description': 'MySQL 5.x',
        'example': '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
    },
    'bcrypt': {
        'length': 60,
        'pattern': r'^\$2[ayb]\$.{56}$',
        'description': 'bcrypt',
        'example': '$2a$10$N9qo8uLOickgx2ZMRZoMye'
    },
    'MD5_Unix': {
        'length': 34,
        'pattern': r'^\$1\$.{8}\$.{22}$',
        'description': 'MD5 Unix',
        'example': '$1$salt$hash'
    },
    'SHA256_Unix': {
        'length': None,
        'pattern': r'^\$5\$.+\$.{43}$',
        'description': 'SHA-256 Unix',
        'example': ''
    },
    'SHA512_Unix': {
        'length': None,
        'pattern': r'^\$6\$.+\$.{86}$',
        'description': 'SHA-512 Unix',
        'example': ''
    }
}

# Common weak passwords for quick checks
COMMON_PASSWORDS = [
    'password', '123456', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'master', 'qwerty', 'login',
    'password123', 'admin123', 'root', 'toor', 'pass',
    'test', 'guest', 'hello', 'love', 'secret',
    'flag', 'ctf', 'hacker', 'security', 'cyber'
]


class HashIdentifier:
    """Identify hash types and attempt to crack them"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'hash': '',
            'possible_types': [],
            'cracked': None,
            'findings': []
        }
    
    def identify(self, hash_string: str) -> Dict:
        """Identify the type of hash"""
        hash_string = hash_string.strip()
        self.results['hash'] = hash_string
        
        # Check against known patterns
        for hash_type, info in HASH_PATTERNS.items():
            if re.match(info['pattern'], hash_string):
                self.results['possible_types'].append({
                    'type': hash_type,
                    'description': info['description'],
                    'confidence': 'High' if info['length'] and len(hash_string) == info['length'] else 'Medium'
                })
        
        # Add findings
        if self.results['possible_types']:
            types_str = ', '.join([t['type'] for t in self.results['possible_types']])
            self.results['findings'].append(f"🔍 Possible hash types: {types_str}")
        else:
            self.results['findings'].append("❓ Unknown hash format")
        
        return self.results
    
    def crack(self, hash_string: str, wordlist: List[str] = None) -> Optional[str]:
        """Attempt to crack the hash using common passwords"""
        hash_string = hash_string.strip().lower()
        passwords = wordlist or COMMON_PASSWORDS
        
        # Identify hash type first
        self.identify(hash_string)
        
        # Try to crack based on identified type
        for pwd in passwords:
            # Try MD5
            if hashlib.md5(pwd.encode()).hexdigest().lower() == hash_string:
                self.results['cracked'] = pwd
                self.results['findings'].append(f"🔓 CRACKED (MD5): {pwd}")
                return pwd
            
            # Try SHA1
            if hashlib.sha1(pwd.encode()).hexdigest().lower() == hash_string:
                self.results['cracked'] = pwd
                self.results['findings'].append(f"🔓 CRACKED (SHA1): {pwd}")
                return pwd
            
            # Try SHA256
            if hashlib.sha256(pwd.encode()).hexdigest().lower() == hash_string:
                self.results['cracked'] = pwd
                self.results['findings'].append(f"🔓 CRACKED (SHA256): {pwd}")
                return pwd
            
            # Try SHA512
            if hashlib.sha512(pwd.encode()).hexdigest().lower() == hash_string:
                self.results['cracked'] = pwd
                self.results['findings'].append(f"🔓 CRACKED (SHA512): {pwd}")
                return pwd
        
        self.results['findings'].append("❌ Could not crack with common passwords")
        self.results['findings'].append("💡 Try: hashcat, john, or crackstation.net")
        return None
    
    def crack_with_hashcat(self, hash_string: str, hash_type: int = None) -> Optional[str]:
        """Try to crack using hashcat (if available)"""
        try:
            # This is a basic implementation - hashcat requires proper setup
            result = subprocess.run(
                ['hashcat', '--identify', hash_string],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self.results['findings'].append(f"📋 Hashcat analysis: {result.stdout.strip()}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        summary = []
        summary.append("\n" + "="*50)
        summary.append("🔢 HASH IDENTIFICATION RESULTS")
        summary.append("="*50)
        
        summary.append(f"\n📝 Hash: {self.results['hash'][:64]}...")
        summary.append(f"   Length: {len(self.results['hash'])} characters")
        
        if self.results['possible_types']:
            summary.append(f"\n🎯 Possible Types:")
            for t in self.results['possible_types']:
                summary.append(f"   • {t['type']} - {t['description']} ({t['confidence']})")
        
        if self.results['cracked']:
            summary.append(f"\n🔓 CRACKED: {self.results['cracked']}")
        
        if self.results['findings']:
            summary.append(f"\n📋 Analysis:")
            for finding in self.results['findings']:
                summary.append(f"   {finding}")
        
        # Helpful tips
        summary.append(f"\n💡 Cracking Tips:")
        summary.append(f"   • Online: crackstation.net, hashes.com")
        summary.append(f"   • Tools: hashcat -m <mode> hash.txt wordlist.txt")
        summary.append(f"   • John: john --format=<type> hash.txt")
        
        summary.append("="*50 + "\n")
        return "\n".join(summary)


def identify_hash(hash_string: str) -> Dict:
    """Convenience function to identify a hash"""
    identifier = HashIdentifier()
    return identifier.identify(hash_string)


def crack_hash(hash_string: str, wordlist: List[str] = None) -> Optional[str]:
    """Convenience function to crack a hash"""
    identifier = HashIdentifier()
    return identifier.crack(hash_string, wordlist)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python hash_identifier.py <hash>")
        print("\nHash Identifier - Detect hash types and crack common hashes")
        print("\nExamples:")
        print("  python hash_identifier.py 5d41402abc4b2a76b9719d911017c592")
        print("  python hash_identifier.py '$2a$10$...'")
        sys.exit(1)
    
    identifier = HashIdentifier()
    identifier.identify(sys.argv[1])
    identifier.crack(sys.argv[1])
    print(identifier.get_summary())
