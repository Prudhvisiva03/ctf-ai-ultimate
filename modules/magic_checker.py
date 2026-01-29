#!/usr/bin/env python3
"""
Magic Bytes Checker - Detect file types by magic bytes/signatures
Author: Prudhvi (CTFHunter)
Version: 2.2.0
"""

import os
import struct
from typing import Dict, List, Tuple, Optional


class MagicChecker:
    """Detect file types by magic bytes and find corrupted/renamed files"""
    
    # Comprehensive magic bytes database
    SIGNATURES = {
        # Images
        b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'mime': 'image/png', 'desc': 'PNG Image'},
        b'\xff\xd8\xff': {'ext': 'jpg', 'mime': 'image/jpeg', 'desc': 'JPEG Image'},
        b'GIF87a': {'ext': 'gif', 'mime': 'image/gif', 'desc': 'GIF Image (87a)'},
        b'GIF89a': {'ext': 'gif', 'mime': 'image/gif', 'desc': 'GIF Image (89a)'},
        b'BM': {'ext': 'bmp', 'mime': 'image/bmp', 'desc': 'BMP Image'},
        b'RIFF': {'ext': 'webp', 'mime': 'image/webp', 'desc': 'WebP/RIFF (check WEBP)'},
        b'II*\x00': {'ext': 'tiff', 'mime': 'image/tiff', 'desc': 'TIFF Image (LE)'},
        b'MM\x00*': {'ext': 'tiff', 'mime': 'image/tiff', 'desc': 'TIFF Image (BE)'},
        b'\x00\x00\x01\x00': {'ext': 'ico', 'mime': 'image/x-icon', 'desc': 'ICO Icon'},
        
        # Archives
        b'PK\x03\x04': {'ext': 'zip', 'mime': 'application/zip', 'desc': 'ZIP Archive'},
        b'PK\x05\x06': {'ext': 'zip', 'mime': 'application/zip', 'desc': 'ZIP Archive (empty)'},
        b'PK\x07\x08': {'ext': 'zip', 'mime': 'application/zip', 'desc': 'ZIP Archive (spanned)'},
        b'Rar!\x1a\x07\x00': {'ext': 'rar', 'mime': 'application/x-rar', 'desc': 'RAR Archive v4'},
        b'Rar!\x1a\x07\x01\x00': {'ext': 'rar', 'mime': 'application/x-rar', 'desc': 'RAR Archive v5'},
        b'\x1f\x8b\x08': {'ext': 'gz', 'mime': 'application/gzip', 'desc': 'GZIP Archive'},
        b'BZh': {'ext': 'bz2', 'mime': 'application/x-bzip2', 'desc': 'BZIP2 Archive'},
        b'\xfd7zXZ\x00': {'ext': 'xz', 'mime': 'application/x-xz', 'desc': 'XZ Archive'},
        b'7z\xbc\xaf\x27\x1c': {'ext': '7z', 'mime': 'application/x-7z-compressed', 'desc': '7-Zip Archive'},
        b'\x75\x73\x74\x61\x72': {'ext': 'tar', 'mime': 'application/x-tar', 'desc': 'TAR Archive', 'offset': 257},
        
        # Documents
        b'%PDF': {'ext': 'pdf', 'mime': 'application/pdf', 'desc': 'PDF Document'},
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'ext': 'doc', 'mime': 'application/msword', 'desc': 'MS Office (old)'},
        b'PK\x03\x04': {'ext': 'docx', 'mime': 'application/vnd.openxmlformats', 'desc': 'MS Office (new)/ZIP'},
        
        # Audio
        b'ID3': {'ext': 'mp3', 'mime': 'audio/mpeg', 'desc': 'MP3 Audio (ID3)'},
        b'\xff\xfb': {'ext': 'mp3', 'mime': 'audio/mpeg', 'desc': 'MP3 Audio'},
        b'\xff\xfa': {'ext': 'mp3', 'mime': 'audio/mpeg', 'desc': 'MP3 Audio'},
        b'OggS': {'ext': 'ogg', 'mime': 'audio/ogg', 'desc': 'OGG Audio'},
        b'fLaC': {'ext': 'flac', 'mime': 'audio/flac', 'desc': 'FLAC Audio'},
        b'FORM': {'ext': 'aiff', 'mime': 'audio/aiff', 'desc': 'AIFF Audio'},
        
        # Video
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': {'ext': 'mp4', 'mime': 'video/mp4', 'desc': 'MP4 Video'},
        b'\x00\x00\x00\x20\x66\x74\x79\x70': {'ext': 'mp4', 'mime': 'video/mp4', 'desc': 'MP4 Video'},
        b'\x1a\x45\xdf\xa3': {'ext': 'mkv', 'mime': 'video/x-matroska', 'desc': 'Matroska Video'},
        b'\x00\x00\x01\xba': {'ext': 'mpg', 'mime': 'video/mpeg', 'desc': 'MPEG Video'},
        b'\x00\x00\x01\xb3': {'ext': 'mpg', 'mime': 'video/mpeg', 'desc': 'MPEG Video'},
        b'FLV\x01': {'ext': 'flv', 'mime': 'video/x-flv', 'desc': 'Flash Video'},
        
        # Executables
        b'MZ': {'ext': 'exe', 'mime': 'application/x-executable', 'desc': 'Windows Executable'},
        b'\x7fELF': {'ext': 'elf', 'mime': 'application/x-executable', 'desc': 'Linux ELF Binary'},
        b'\xca\xfe\xba\xbe': {'ext': 'class', 'mime': 'application/java', 'desc': 'Java Class / Mach-O Fat'},
        b'\xfe\xed\xfa\xce': {'ext': 'macho', 'mime': 'application/x-mach-binary', 'desc': 'Mach-O 32-bit'},
        b'\xfe\xed\xfa\xcf': {'ext': 'macho', 'mime': 'application/x-mach-binary', 'desc': 'Mach-O 64-bit'},
        b'\xcf\xfa\xed\xfe': {'ext': 'macho', 'mime': 'application/x-mach-binary', 'desc': 'Mach-O 64-bit (LE)'},
        b'dex\n': {'ext': 'dex', 'mime': 'application/x-dex', 'desc': 'Android DEX'},
        
        # Disk/Forensics
        b'KDMV': {'ext': 'vmdk', 'mime': 'application/x-vmdk', 'desc': 'VMware Disk'},
        b'conectix': {'ext': 'vhd', 'mime': 'application/x-vhd', 'desc': 'Virtual Hard Disk'},
        b'QFI\xfb': {'ext': 'qcow2', 'mime': 'application/x-qcow2', 'desc': 'QEMU QCOW2'},
        b'SQLite format 3': {'ext': 'sqlite', 'mime': 'application/x-sqlite3', 'desc': 'SQLite Database'},
        
        # Crypto/Certificates
        b'-----BEGIN': {'ext': 'pem', 'mime': 'application/x-pem-file', 'desc': 'PEM Certificate/Key'},
        
        # Data formats
        b'<?xml': {'ext': 'xml', 'mime': 'application/xml', 'desc': 'XML Document'},
        b'<!DOCTYPE html': {'ext': 'html', 'mime': 'text/html', 'desc': 'HTML Document'},
        b'<html': {'ext': 'html', 'mime': 'text/html', 'desc': 'HTML Document'},
        b'{\n': {'ext': 'json', 'mime': 'application/json', 'desc': 'JSON (possible)'},
        b'{"': {'ext': 'json', 'mime': 'application/json', 'desc': 'JSON Document'},
        
        # Scripts
        b'#!/bin/bash': {'ext': 'sh', 'mime': 'text/x-shellscript', 'desc': 'Bash Script'},
        b'#!/bin/sh': {'ext': 'sh', 'mime': 'text/x-shellscript', 'desc': 'Shell Script'},
        b'#!/usr/bin/python': {'ext': 'py', 'mime': 'text/x-python', 'desc': 'Python Script'},
        b'#!/usr/bin/env python': {'ext': 'py', 'mime': 'text/x-python', 'desc': 'Python Script'},
    }
    
    # File trailers (endings)
    TRAILERS = {
        'png': b'\x49\x45\x4e\x44\xae\x42\x60\x82',  # IEND
        'jpg': b'\xff\xd9',
        'gif': b'\x00\x3b',
        'pdf': b'%%EOF',
        'zip': b'\x50\x4b\x05\x06',  # End of central directory
    }
    
    def __init__(self, config=None):
        self.config = config or {}
        self.results = {
            'detected_type': None,
            'extension_match': True,
            'is_corrupted': False,
            'embedded_files': [],
            'anomalies': [],
            'recommendations': []
        }
    
    def analyze(self, filepath: str) -> Dict:
        """Analyze file magic bytes"""
        print(f"\n🔮 Analyzing magic bytes: {os.path.basename(filepath)}")
        
        if not os.path.exists(filepath):
            print(f"  ❌ File not found: {filepath}")
            return self.results
        
        # Read file header and footer
        with open(filepath, 'rb') as f:
            header = f.read(512)  # First 512 bytes
            f.seek(0, 2)  # End of file
            file_size = f.tell()
            f.seek(max(0, file_size - 512))
            footer = f.read(512)
        
        # Detect file type
        detected = self._detect_type(header)
        
        # Get actual extension
        actual_ext = os.path.splitext(filepath)[1].lower().lstrip('.')
        
        if detected:
            self.results['detected_type'] = detected
            print(f"  📄 Detected: {detected['desc']} (.{detected['ext']})")
            
            # Check extension mismatch
            if actual_ext and actual_ext != detected['ext']:
                # Handle special cases
                if not self._is_valid_extension_combo(actual_ext, detected['ext']):
                    self.results['extension_match'] = False
                    self.results['anomalies'].append(
                        f"⚠️ Extension mismatch: .{actual_ext} but actually .{detected['ext']}"
                    )
                    self.results['recommendations'].append(
                        f"Rename to .{detected['ext']} or investigate why extension differs"
                    )
        else:
            print(f"  ℹ️  Unknown file type (no matching signature)")
            self.results['anomalies'].append("Unknown file signature")
        
        # Check for corruption
        self._check_corruption(header, footer, filepath)
        
        # Search for embedded files
        self._find_embedded(filepath)
        
        # Check for common CTF tricks
        self._check_ctf_tricks(header, footer, filepath)
        
        self._print_results()
        return self.results
    
    def _detect_type(self, header: bytes) -> Optional[Dict]:
        """Detect file type from magic bytes"""
        for signature, info in self.SIGNATURES.items():
            offset = info.get('offset', 0)
            if offset > 0:
                # Check at specific offset
                if header[offset:offset+len(signature)] == signature:
                    return info
            else:
                if header.startswith(signature):
                    return info
        return None
    
    def _is_valid_extension_combo(self, actual: str, detected: str) -> bool:
        """Check if extension combo is valid (e.g., docx is actually zip)"""
        valid_combos = [
            ('docx', 'zip'), ('xlsx', 'zip'), ('pptx', 'zip'),
            ('odt', 'zip'), ('ods', 'zip'), ('odp', 'zip'),
            ('apk', 'zip'), ('jar', 'zip'), ('epub', 'zip'),
            ('jpeg', 'jpg'), ('tif', 'tiff'),
            ('htm', 'html'), ('mpeg', 'mpg'),
        ]
        return (actual, detected) in valid_combos or (detected, actual) in valid_combos
    
    def _check_corruption(self, header: bytes, footer: bytes, filepath: str):
        """Check for file corruption"""
        detected = self.results.get('detected_type')
        if not detected:
            return
        
        ext = detected['ext']
        
        # Check PNG
        if ext == 'png':
            # Check IHDR chunk
            if b'IHDR' not in header[:50]:
                self.results['is_corrupted'] = True
                self.results['anomalies'].append("PNG missing IHDR chunk")
                self.results['recommendations'].append("PNG header may be corrupted - try pngcheck")
            
            # Check IEND
            if self.TRAILERS['png'] not in footer:
                self.results['anomalies'].append("PNG missing IEND chunk - data may be appended")
                self.results['recommendations'].append("Check for appended data after IEND")
        
        # Check JPEG
        elif ext == 'jpg':
            if self.TRAILERS['jpg'] not in footer[-20:]:
                self.results['anomalies'].append("JPEG missing EOI marker - data may be appended")
        
        # Check PDF
        elif ext == 'pdf':
            if b'%%EOF' not in footer:
                self.results['anomalies'].append("PDF missing %%EOF - may be corrupted or have appended data")
    
    def _find_embedded(self, filepath: str):
        """Find embedded files"""
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Search for file signatures within the file
        for signature, info in self.SIGNATURES.items():
            if info.get('offset', 0) > 0:
                continue  # Skip signatures with offsets
            
            # Find all occurrences
            start = 0
            while True:
                pos = content.find(signature, start)
                if pos == -1:
                    break
                if pos > 0:  # Not at the beginning
                    self.results['embedded_files'].append({
                        'type': info['desc'],
                        'offset': pos,
                        'signature': signature.hex()
                    })
                start = pos + 1
                
                # Limit results
                if len(self.results['embedded_files']) > 20:
                    break
    
    def _check_ctf_tricks(self, header: bytes, footer: bytes, filepath: str):
        """Check for common CTF tricks"""
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Check for null bytes hiding data
        if b'\x00\x00\x00\x00\x00\x00\x00\x00' in content[100:]:
            null_pos = content.find(b'\x00\x00\x00\x00\x00\x00\x00\x00', 100)
            after_nulls = content[null_pos+8:null_pos+50]
            if any(c > 31 and c < 127 for c in after_nulls):
                self.results['anomalies'].append(f"Suspicious null padding at offset {null_pos}")
        
        # Check for strings after file end
        detected = self.results.get('detected_type')
        if detected:
            ext = detected['ext']
            if ext in self.TRAILERS:
                trailer = self.TRAILERS[ext]
                trailer_pos = content.rfind(trailer)
                if trailer_pos != -1 and trailer_pos < len(content) - len(trailer) - 10:
                    after_trailer = content[trailer_pos + len(trailer):]
                    printable = bytes([c for c in after_trailer if 31 < c < 127])
                    if len(printable) > 5:
                        self.results['anomalies'].append(
                            f"Data found after file trailer ({len(after_trailer)} bytes)"
                        )
                        self.results['recommendations'].append(
                            f"Extract data after file end: dd if=file bs=1 skip={trailer_pos + len(trailer)}"
                        )
        
        # Check for steganography indicators
        if b'stegano' in content.lower() or b'hidden' in content.lower():
            self.results['anomalies'].append("File contains stego-related strings")
        
        # Check for unusual EXIF
        if b'Exif' in content:
            exif_pos = content.find(b'Exif')
            self.results['anomalies'].append(f"EXIF data found at offset {exif_pos}")
    
    def _print_results(self):
        """Print analysis results"""
        print()
        
        if self.results['anomalies']:
            print("  🔍 Anomalies Found:")
            for anomaly in self.results['anomalies']:
                print(f"     {anomaly}")
            print()
        
        if self.results['embedded_files']:
            print(f"  📦 Embedded Files ({len(self.results['embedded_files'])}):")
            for emb in self.results['embedded_files'][:5]:
                print(f"     • {emb['type']} at offset {emb['offset']}")
            if len(self.results['embedded_files']) > 5:
                print(f"     ... and {len(self.results['embedded_files']) - 5} more")
            print()
        
        if self.results['recommendations']:
            print("  💡 Recommendations:")
            for rec in self.results['recommendations']:
                print(f"     • {rec}")
            print()
        
        if not self.results['extension_match']:
            print("  ⚠️  FILE TYPE MISMATCH DETECTED!")
            print("     This is a common CTF trick - file extension doesn't match actual content")
            print()


def check_magic(filepath: str) -> Dict:
    """Convenience function for magic byte analysis"""
    checker = MagicChecker()
    return checker.analyze(filepath)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        check_magic(sys.argv[1])
    else:
        print("Usage: python magic_checker.py <file>")
