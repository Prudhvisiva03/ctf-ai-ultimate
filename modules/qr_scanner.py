#!/usr/bin/env python3
"""
QR Code Scanner - Detect and decode QR codes from images
For CTF challenges with hidden QR codes
Author: Prudhvi (CTFHunter)
Version: 2.1.0
"""

import subprocess
import os
import re
from typing import Dict, List, Optional


class QRScanner:
    """QR Code detection and decoding for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'qr_codes': [],
            'flags': [],
            'urls': [],
            'text': [],
            'findings': []
        }
        self.flag_patterns = self.config.get('flag_patterns', [
            r'digitalcyberhunt\{[^}]+\}',
            r'DCH\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}',
            r'picoCTF\{[^}]+\}'
        ])
    
    def scan(self, filepath: str) -> Dict:
        """Scan image for QR codes"""
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}
        
        # Try multiple QR decoding methods
        self._try_zbarimg(filepath)
        self._try_zxing(filepath)
        self._try_python_qr(filepath)
        
        # Search for flags in decoded content
        self._search_flags()
        
        return self.results
    
    def _try_zbarimg(self, filepath: str):
        """Try zbarimg tool (most common on Linux)"""
        try:
            result = subprocess.run(
                ['zbarimg', '--raw', '-q', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                decoded = result.stdout.strip()
                self.results['qr_codes'].append({
                    'method': 'zbarimg',
                    'content': decoded
                })
                self.results['findings'].append(f"📱 QR Code found (zbarimg): {decoded}")
                self._categorize_content(decoded)
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    def _try_zxing(self, filepath: str):
        """Try zxing decoder"""
        try:
            result = subprocess.run(
                ['zxing', '--raw', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                decoded = result.stdout.strip()
                if not any(qr['content'] == decoded for qr in self.results['qr_codes']):
                    self.results['qr_codes'].append({
                        'method': 'zxing',
                        'content': decoded
                    })
                    self.results['findings'].append(f"📱 QR Code found (zxing): {decoded}")
                    self._categorize_content(decoded)
                    
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    def _try_python_qr(self, filepath: str):
        """Try Python QR libraries"""
        try:
            # Try pyzbar
            from PIL import Image
            from pyzbar.pyzbar import decode
            
            img = Image.open(filepath)
            decoded_objects = decode(img)
            
            for obj in decoded_objects:
                content = obj.data.decode('utf-8', errors='ignore')
                if not any(qr['content'] == content for qr in self.results['qr_codes']):
                    self.results['qr_codes'].append({
                        'method': 'pyzbar',
                        'content': content,
                        'type': obj.type
                    })
                    self.results['findings'].append(f"📱 QR/{obj.type} found: {content}")
                    self._categorize_content(content)
                    
        except ImportError:
            # pyzbar not installed
            pass
        except Exception as e:
            pass
    
    def _categorize_content(self, content: str):
        """Categorize decoded content"""
        # Check for URLs
        if re.match(r'https?://', content, re.IGNORECASE):
            self.results['urls'].append(content)
        else:
            self.results['text'].append(content)
    
    def _search_flags(self):
        """Search for flags in all decoded content"""
        all_content = ' '.join([qr['content'] for qr in self.results['qr_codes']])
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags']:
                    self.results['flags'].append(match)
                    self.results['findings'].append(f"🚩 FLAG FOUND IN QR: {match}")
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        summary = []
        summary.append("\n" + "="*50)
        summary.append("📱 QR CODE SCAN RESULTS")
        summary.append("="*50)
        
        if self.results['qr_codes']:
            summary.append(f"\n✅ Found {len(self.results['qr_codes'])} QR code(s):")
            for i, qr in enumerate(self.results['qr_codes'], 1):
                summary.append(f"\n   [{i}] Method: {qr['method']}")
                summary.append(f"       Content: {qr['content'][:100]}...")
        
        if self.results['flags']:
            summary.append(f"\n🚩 FLAGS FOUND:")
            for flag in self.results['flags']:
                summary.append(f"   {flag}")
        
        if self.results['urls']:
            summary.append(f"\n🔗 URLs Found:")
            for url in self.results['urls']:
                summary.append(f"   {url}")
        
        if not self.results['qr_codes']:
            summary.append("\n   No QR codes detected.")
            summary.append("   💡 Try: Adjusting image contrast or using stegsolve")
        
        summary.append("="*50 + "\n")
        return "\n".join(summary)


def scan_qr(filepath: str, config: Dict = None) -> Dict:
    """Convenience function to scan QR codes"""
    scanner = QRScanner(config)
    return scanner.scan(filepath)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python qr_scanner.py <image_file>")
        print("\nQR Code Scanner - Decode QR codes from images")
        sys.exit(1)
    
    scanner = QRScanner()
    results = scanner.scan(sys.argv[1])
    print(scanner.get_summary())
