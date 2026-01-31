#!/usr/bin/env python3
"""
Deep Forensics Analyzer - In-Depth File Forensics
Comprehensive file structure, metadata, and hidden data analysis
"""

import os
import re
import struct
import hashlib
import subprocess
import tempfile
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class DeepForensicsAnalyzer:
    """
    Comprehensive forensic analysis - examines every layer of files.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.flags_found = []
        self.hidden_data_found = []
        
        self.flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'THM\{[^}]+\}'
        ]
        
        # Magic bytes for various file types
        self.magic_bytes = {
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF87a': 'GIF87a',
            b'GIF89a': 'GIF89a',
            b'BM': 'BMP',
            b'PK\x03\x04': 'ZIP/DOCX/JAR',
            b'PK\x05\x06': 'ZIP (empty)',
            b'\x1f\x8b': 'GZIP',
            b'\x42\x5a\x68': 'BZIP2',
            b'\xfd7zXZ\x00': 'XZ',
            b'Rar!\x1a\x07': 'RAR',
            b'7z\xbc\xaf\x27\x1c': '7Z',
            b'\x00\x00\x01\x00': 'ICO',
            b'RIFF': 'RIFF (WAV/AVI)',
            b'ID3': 'MP3 (ID3)',
            b'\xff\xfb': 'MP3',
            b'\xff\xfa': 'MP3',
            b'OggS': 'OGG',
            b'fLaC': 'FLAC',
            b'\x00\x00\x00': 'MP4/MOV (possible)',
            b'%PDF': 'PDF',
            b'\x7fELF': 'ELF',
            b'MZ': 'DOS/PE EXE',
            b'\xca\xfe\xba\xbe': 'Mach-O (universal)',
            b'\xcf\xfa\xed\xfe': 'Mach-O (32-bit)',
            b'\xce\xfa\xed\xfe': 'Mach-O (64-bit)',
            b'\xd0\xcf\x11\xe0': 'MS Office (OLE)',
            b'SQLite format': 'SQLite',
            b'\x1a\x45\xdf\xa3': 'WebM/MKV',
        }
    
    def analyze(self, filepath: str) -> Dict:
        """Comprehensive forensic analysis"""
        print(f"\n[DEEP FORENSICS] Analyzing: {filepath}")
        print("=" * 60)
        
        results = {
            'file': filepath,
            'basic_info': {},
            'hashes': {},
            'magic_analysis': {},
            'structure_analysis': {},
            'metadata': {},
            'strings_analysis': {},
            'embedded_files': [],
            'hidden_data': [],
            'anomalies': [],
            'flags_found': []
        }
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return results
        
        # 1. Basic file info
        print("[*] Phase 1: Basic file information...")
        results['basic_info'] = self._get_basic_info(filepath)
        
        # 2. Hash analysis
        print("[*] Phase 2: Hash calculation...")
        results['hashes'] = self._calculate_hashes(filepath)
        
        # 3. Magic byte analysis
        print("[*] Phase 3: Magic byte analysis...")
        results['magic_analysis'] = self._analyze_magic(filepath)
        
        # 4. File structure analysis
        print("[*] Phase 4: Deep structure analysis...")
        results['structure_analysis'] = self._analyze_structure(filepath)
        
        # 5. Metadata extraction
        print("[*] Phase 5: Metadata extraction...")
        results['metadata'] = self._extract_metadata(filepath)
        
        # 6. Deep string analysis
        print("[*] Phase 6: Deep string analysis...")
        results['strings_analysis'] = self._analyze_strings(filepath)
        
        # 7. Embedded file detection
        print("[*] Phase 7: Embedded file detection...")
        results['embedded_files'] = self._detect_embedded_files(filepath)
        
        # 8. Hidden data detection
        print("[*] Phase 8: Hidden data detection...")
        results['hidden_data'] = self._detect_hidden_data(filepath)
        
        # 9. Anomaly detection
        print("[*] Phase 9: Anomaly detection...")
        results['anomalies'] = self._detect_anomalies(filepath)
        
        # 10. Timestamps analysis
        print("[*] Phase 10: Timestamp analysis...")
        results['timestamps'] = self._analyze_timestamps(filepath)
        
        results['flags_found'] = self.flags_found
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] FORENSICS ANALYSIS SUMMARY")
        print("=" * 60)
        
        if self.flags_found:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.flags_found)}")
            for flag in self.flags_found:
                print(f"    {flag}")
        
        if results['anomalies']:
            print(f"\n[!] ANOMALIES DETECTED: {len(results['anomalies'])}")
            for anomaly in results['anomalies'][:5]:
                print(f"    - {anomaly}")
        
        if results['embedded_files']:
            print(f"\n[+] EMBEDDED FILES: {len(results['embedded_files'])}")
            for ef in results['embedded_files'][:5]:
                print(f"    - {ef.get('type', 'Unknown')} at offset {ef.get('offset', '?')}")
        
        return results
    
    # ==================== BASIC INFO ====================
    
    def _get_basic_info(self, filepath: str) -> Dict:
        """Get basic file information"""
        info = {}
        
        stat = os.stat(filepath)
        info['size'] = stat.st_size
        info['size_human'] = self._human_size(stat.st_size)
        info['permissions'] = oct(stat.st_mode)[-3:]
        info['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        info['accessed'] = datetime.fromtimestamp(stat.st_atime).isoformat()
        
        # File command
        try:
            result = subprocess.run(['file', '-b', filepath], capture_output=True, text=True)
            info['file_type'] = result.stdout.strip()
        except:
            info['file_type'] = 'Unknown'
        
        print(f"    Size: {info['size_human']}")
        print(f"    Type: {info['file_type']}")
        
        return info
    
    def _human_size(self, size: int) -> str:
        """Convert bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
    # ==================== HASHES ====================
    
    def _calculate_hashes(self, filepath: str) -> Dict:
        """Calculate various hashes"""
        hashes = {}
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        # CRC32
        import zlib
        hashes['crc32'] = format(zlib.crc32(data) & 0xffffffff, '08x')
        
        print(f"    MD5: {hashes['md5']}")
        print(f"    SHA1: {hashes['sha1']}")
        print(f"    SHA256: {hashes['sha256'][:32]}...")
        
        return hashes
    
    # ==================== MAGIC ANALYSIS ====================
    
    def _analyze_magic(self, filepath: str) -> Dict:
        """Analyze magic bytes"""
        analysis = {
            'detected_type': None,
            'magic_bytes': None,
            'extension_match': None,
            'possible_types': []
        }
        
        with open(filepath, 'rb') as f:
            header = f.read(32)
        
        analysis['magic_bytes'] = header[:16].hex()
        
        # Check against known signatures
        for magic, ftype in self.magic_bytes.items():
            if header.startswith(magic):
                analysis['detected_type'] = ftype
                break
        
        # Check extension match
        ext = os.path.splitext(filepath)[1].lower()
        if analysis['detected_type']:
            expected_ext = {
                'PNG': '.png', 'JPEG': '.jpg', 'GIF87a': '.gif', 'GIF89a': '.gif',
                'BMP': '.bmp', 'PDF': '.pdf', 'ZIP/DOCX/JAR': '.zip'
            }.get(analysis['detected_type'])
            
            if expected_ext and ext not in [expected_ext, '.jpeg', '.docx', '.jar']:
                analysis['extension_mismatch'] = f"Type {analysis['detected_type']} but extension {ext}"
        
        # Check for multiple signatures
        for offset in [0, 512, 1024, 4096]:
            with open(filepath, 'rb') as f:
                f.seek(offset)
                chunk = f.read(32)
            
            for magic, ftype in self.magic_bytes.items():
                if chunk.startswith(magic):
                    if ftype not in analysis['possible_types']:
                        analysis['possible_types'].append({
                            'type': ftype,
                            'offset': offset
                        })
        
        if analysis['detected_type']:
            print(f"    Detected: {analysis['detected_type']}")
        
        if analysis.get('extension_mismatch'):
            print(f"    [!] {analysis['extension_mismatch']}")
        
        return analysis
    
    # ==================== STRUCTURE ANALYSIS ====================
    
    def _analyze_structure(self, filepath: str) -> Dict:
        """Deep structure analysis based on file type"""
        structure = {}
        
        with open(filepath, 'rb') as f:
            header = f.read(32)
            f.seek(0)
            full_data = f.read()
        
        # PNG structure
        if header.startswith(b'\x89PNG'):
            structure = self._analyze_png_structure(full_data)
        
        # JPEG structure  
        elif header.startswith(b'\xff\xd8\xff'):
            structure = self._analyze_jpeg_structure(full_data)
        
        # PDF structure
        elif header.startswith(b'%PDF'):
            structure = self._analyze_pdf_structure(full_data)
        
        # ZIP structure
        elif header.startswith(b'PK\x03\x04'):
            structure = self._analyze_zip_structure(filepath)
        
        # ELF structure
        elif header.startswith(b'\x7fELF'):
            structure = self._analyze_elf_structure(full_data)
        
        # PE structure
        elif header.startswith(b'MZ'):
            structure = self._analyze_pe_structure(full_data)
        
        return structure
    
    def _analyze_png_structure(self, data: bytes) -> Dict:
        """Analyze PNG structure"""
        structure = {'chunks': [], 'warnings': []}
        
        if len(data) < 8:
            return structure
        
        pos = 8  # Skip PNG signature
        chunk_num = 0
        
        while pos < len(data) - 8:
            try:
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
                chunk_data = data[pos+8:pos+8+length]
                crc = struct.unpack('>I', data[pos+8+length:pos+12+length])[0]
                
                chunk_info = {
                    'num': chunk_num,
                    'type': chunk_type,
                    'length': length,
                    'offset': pos,
                    'crc': hex(crc)
                }
                
                # Extract text from tEXt/zTXt/iTXt
                if chunk_type == 'tEXt':
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode('latin-1')
                        value = chunk_data[null_pos+1:].decode('latin-1', errors='ignore')
                        chunk_info['keyword'] = keyword
                        chunk_info['value'] = value[:200]
                        self._search_flags(value)
                        
                        print(f"    [PNG tEXt] {keyword}: {value[:60]}")
                
                elif chunk_type == 'zTXt':
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode('latin-1')
                        try:
                            import zlib
                            value = zlib.decompress(chunk_data[null_pos+2:]).decode('latin-1', errors='ignore')
                            chunk_info['keyword'] = keyword
                            chunk_info['value'] = value[:200]
                            self._search_flags(value)
                        except:
                            pass
                
                # Check for non-standard chunks
                if chunk_type not in ['IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt', 
                                       'iTXt', 'gAMA', 'cHRM', 'sRGB', 'bKGD', 'pHYs',
                                       'tIME', 'iCCP', 'sBIT', 'hIST', 'tRNS', 'sPLT']:
                    structure['warnings'].append(f"Non-standard chunk: {chunk_type}")
                    print(f"    [!] Non-standard chunk: {chunk_type}")
                
                structure['chunks'].append(chunk_info)
                pos += 12 + length
                chunk_num += 1
                
                if chunk_type == 'IEND':
                    if pos < len(data):
                        structure['data_after_iend'] = len(data) - pos
                        structure['warnings'].append(f"{len(data) - pos} bytes after IEND")
                        print(f"    [!] {len(data) - pos} bytes AFTER IEND chunk!")
                        
                        # Extract data after IEND
                        trailing = data[pos:]
                        self._search_flags(trailing.decode('latin-1', errors='ignore'))
                    break
                
            except Exception as e:
                break
        
        return structure
    
    def _analyze_jpeg_structure(self, data: bytes) -> Dict:
        """Analyze JPEG structure"""
        structure = {'segments': [], 'warnings': []}
        
        pos = 0
        
        while pos < len(data) - 2:
            if data[pos] != 0xFF:
                pos += 1
                continue
            
            marker = data[pos+1]
            
            segment = {
                'marker': hex(marker),
                'offset': pos
            }
            
            # SOI and EOI have no length
            if marker in [0xD8, 0xD9]:
                segment['name'] = 'SOI' if marker == 0xD8 else 'EOI'
                structure['segments'].append(segment)
                
                if marker == 0xD9:  # EOI
                    if pos + 2 < len(data):
                        structure['data_after_eoi'] = len(data) - pos - 2
                        structure['warnings'].append(f"{len(data) - pos - 2} bytes after EOI")
                        print(f"    [!] {len(data) - pos - 2} bytes AFTER EOI marker!")
                        
                        trailing = data[pos+2:]
                        self._search_flags(trailing.decode('latin-1', errors='ignore'))
                    break
                
                pos += 2
                continue
            
            # Other markers have length
            if pos + 4 > len(data):
                break
            
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            segment['length'] = length
            
            # Name common markers
            marker_names = {
                0xE0: 'APP0 (JFIF)', 0xE1: 'APP1 (EXIF/XMP)', 0xE2: 'APP2',
                0xFE: 'COM (Comment)', 0xDB: 'DQT', 0xC0: 'SOF0',
                0xC4: 'DHT', 0xDA: 'SOS'
            }
            segment['name'] = marker_names.get(marker, f'Marker {hex(marker)}')
            
            # Extract comments
            if marker == 0xFE:
                comment = data[pos+4:pos+2+length].decode('latin-1', errors='ignore')
                segment['comment'] = comment[:200]
                print(f"    [JPEG Comment] {comment[:60]}")
                self._search_flags(comment)
            
            # Extract APP segments
            if 0xE0 <= marker <= 0xEF:
                app_data = data[pos+4:pos+2+length]
                segment['data_preview'] = app_data[:50].hex()
                self._search_flags(app_data.decode('latin-1', errors='ignore'))
            
            structure['segments'].append(segment)
            pos += 2 + length
        
        return structure
    
    def _analyze_pdf_structure(self, data: bytes) -> Dict:
        """Analyze PDF structure"""
        structure = {'objects': [], 'streams': [], 'warnings': []}
        
        text = data.decode('latin-1', errors='ignore')
        
        # Find PDF version
        ver_match = re.search(r'%PDF-(\d+\.\d+)', text)
        if ver_match:
            structure['version'] = ver_match.group(1)
        
        # Find objects
        obj_pattern = r'(\d+)\s+(\d+)\s+obj'
        objects = re.findall(obj_pattern, text)
        structure['object_count'] = len(objects)
        
        # Find streams
        stream_count = len(re.findall(r'stream\s', text))
        structure['stream_count'] = stream_count
        
        # Check for JavaScript
        if '/JS' in text or '/JavaScript' in text:
            structure['warnings'].append("Contains JavaScript")
            print("    [!] PDF contains JavaScript!")
        
        # Check for embedded files
        if '/EmbeddedFile' in text:
            structure['warnings'].append("Contains embedded files")
            print("    [!] PDF contains embedded files!")
        
        # Check for encrypted
        if '/Encrypt' in text:
            structure['encrypted'] = True
            print("    [!] PDF is encrypted!")
        
        # Look for hidden text
        self._search_flags(text)
        
        return structure
    
    def _analyze_zip_structure(self, filepath: str) -> Dict:
        """Analyze ZIP structure"""
        import zipfile
        
        structure = {'files': [], 'warnings': []}
        
        try:
            with zipfile.ZipFile(filepath) as zf:
                for info in zf.infolist():
                    file_info = {
                        'name': info.filename,
                        'size': info.file_size,
                        'compressed': info.compress_size,
                        'modified': str(info.date_time)
                    }
                    
                    # Check for suspicious paths
                    if '..' in info.filename or info.filename.startswith('/'):
                        structure['warnings'].append(f"Suspicious path: {info.filename}")
                    
                    # Check for hidden files
                    if info.filename.startswith('.') or '/__' in info.filename:
                        file_info['hidden'] = True
                    
                    structure['files'].append(file_info)
                    
                    # Search content for flags
                    try:
                        content = zf.read(info.filename).decode('utf-8', errors='ignore')
                        self._search_flags(content)
                    except:
                        pass
                
                structure['file_count'] = len(structure['files'])
                
        except zipfile.BadZipFile:
            structure['warnings'].append("Corrupted or invalid ZIP")
        
        return structure
    
    def _analyze_elf_structure(self, data: bytes) -> Dict:
        """Analyze ELF structure"""
        structure = {}
        
        if len(data) < 64:
            return structure
        
        # ELF class (32/64 bit)
        elf_class = data[4]
        structure['bits'] = 32 if elf_class == 1 else 64
        
        # Endianness
        structure['endian'] = 'little' if data[5] == 1 else 'big'
        
        # Type
        e_type = struct.unpack('<H' if structure['endian'] == 'little' else '>H', data[16:18])[0]
        types = {1: 'Relocatable', 2: 'Executable', 3: 'Shared Object', 4: 'Core'}
        structure['type'] = types.get(e_type, 'Unknown')
        
        print(f"    ELF: {structure['bits']}-bit {structure['type']}")
        
        return structure
    
    def _analyze_pe_structure(self, data: bytes) -> Dict:
        """Analyze PE structure"""
        structure = {}
        
        if len(data) < 64:
            return structure
        
        # PE offset
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        if pe_offset + 6 < len(data):
            # Check PE signature
            if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                structure['valid_pe'] = True
                
                # Machine type
                machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                machines = {0x14c: 'i386', 0x8664: 'AMD64', 0x1c0: 'ARM'}
                structure['machine'] = machines.get(machine, hex(machine))
                
                print(f"    PE: {structure['machine']}")
        
        return structure
    
    # ==================== METADATA ====================
    
    def _extract_metadata(self, filepath: str) -> Dict:
        """Extract all metadata"""
        metadata = {}
        
        # ExifTool
        try:
            result = subprocess.run(
                ['exiftool', '-j', filepath],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                if data:
                    metadata['exiftool'] = data[0]
                    
                    # Search for flags in metadata
                    for key, value in data[0].items():
                        if isinstance(value, str):
                            self._search_flags(value)
        except:
            pass
        
        # Strings from metadata sections
        try:
            result = subprocess.run(
                ['strings', '-n', '4', filepath],
                capture_output=True, text=True
            )
            metadata['string_count'] = len(result.stdout.splitlines())
        except:
            pass
        
        return metadata
    
    # ==================== STRING ANALYSIS ====================
    
    def _analyze_strings(self, filepath: str) -> Dict:
        """Deep string analysis"""
        analysis = {
            'ascii_strings': [],
            'unicode_strings': [],
            'urls': [],
            'emails': [],
            'ips': [],
            'base64_candidates': [],
            'interesting': []
        }
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # ASCII strings (min 4 chars)
        ascii_pattern = rb'[\x20-\x7e]{4,}'
        ascii_strings = re.findall(ascii_pattern, data)
        analysis['ascii_count'] = len(ascii_strings)
        
        for s in ascii_strings:
            try:
                text = s.decode('ascii')
                
                # Search for flags
                self._search_flags(text)
                
                # URLs
                if re.match(r'https?://', text):
                    analysis['urls'].append(text)
                
                # Emails
                if re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text):
                    analysis['emails'].append(text)
                
                # IP addresses
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
                    analysis['ips'].append(text)
                
                # Base64 candidates
                if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', text):
                    analysis['base64_candidates'].append(text[:100])
                
                # Interesting strings
                if any(word in text.lower() for word in ['password', 'secret', 'key', 'flag', 'hidden', 'admin']):
                    analysis['interesting'].append(text[:200])
                
            except:
                pass
        
        # Unicode strings (UTF-16)
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){4,}'
        unicode_strings = re.findall(unicode_pattern, data)
        analysis['unicode_count'] = len(unicode_strings)
        
        for s in unicode_strings:
            try:
                text = s.decode('utf-16-le', errors='ignore')
                self._search_flags(text)
            except:
                pass
        
        print(f"    ASCII strings: {analysis['ascii_count']}")
        print(f"    Unicode strings: {analysis['unicode_count']}")
        
        if analysis['urls']:
            print(f"    URLs found: {len(analysis['urls'])}")
        if analysis['interesting']:
            print(f"    Interesting strings: {len(analysis['interesting'])}")
        
        return analysis
    
    # ==================== EMBEDDED FILE DETECTION ====================
    
    def _detect_embedded_files(self, filepath: str) -> List[Dict]:
        """Detect embedded files"""
        embedded = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Search for file signatures
        signatures = [
            (b'\x89PNG\r\n\x1a\n', 'PNG'),
            (b'\xff\xd8\xff', 'JPEG'),
            (b'GIF8', 'GIF'),
            (b'PK\x03\x04', 'ZIP'),
            (b'%PDF', 'PDF'),
            (b'Rar!', 'RAR'),
            (b'7z\xbc\xaf', '7Z'),
            (b'\x1f\x8b', 'GZIP'),
            (b'\x7fELF', 'ELF'),
            (b'MZ', 'PE'),
            (b'<!DOCTYPE', 'HTML'),
            (b'<?xml', 'XML'),
            (b'SQLite', 'SQLite'),
        ]
        
        for sig, ftype in signatures:
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                
                # Skip if at position 0 (main file)
                if pos > 0:
                    embedded.append({
                        'type': ftype,
                        'offset': pos,
                        'signature': sig.hex()
                    })
                    print(f"    [EMBEDDED] {ftype} at offset {pos}")
                
                pos += 1
        
        # Use binwalk
        try:
            result = subprocess.run(
                ['binwalk', '-B', filepath],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[3:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                offset = int(parts[0])
                                desc = ' '.join(parts[2:])
                                
                                if offset > 0 and not any(e['offset'] == offset for e in embedded):
                                    embedded.append({
                                        'type': 'binwalk',
                                        'offset': offset,
                                        'description': desc[:100]
                                    })
                            except:
                                pass
        except:
            pass
        
        return embedded
    
    # ==================== HIDDEN DATA DETECTION ====================
    
    def _detect_hidden_data(self, filepath: str) -> List[Dict]:
        """Detect hidden data"""
        hidden = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Check for data after EOF markers
        # PNG IEND
        iend_pos = data.find(b'IEND')
        if iend_pos > 0:
            iend_end = iend_pos + 8  # IEND + CRC
            if iend_end < len(data):
                trailing = data[iend_end:]
                if len(trailing) > 10:
                    hidden.append({
                        'type': 'PNG trailing data',
                        'offset': iend_end,
                        'size': len(trailing),
                        'preview': trailing[:50].hex()
                    })
                    self._search_flags(trailing.decode('latin-1', errors='ignore'))
        
        # JPEG EOI
        eoi_pos = data.rfind(b'\xff\xd9')
        if eoi_pos > 0 and eoi_pos + 2 < len(data):
            trailing = data[eoi_pos + 2:]
            if len(trailing) > 10:
                hidden.append({
                    'type': 'JPEG trailing data',
                    'offset': eoi_pos + 2,
                    'size': len(trailing),
                    'preview': trailing[:50].hex()
                })
                self._search_flags(trailing.decode('latin-1', errors='ignore'))
        
        # PDF trailer
        eof_pos = data.rfind(b'%%EOF')
        if eof_pos > 0 and eof_pos + 5 < len(data):
            trailing = data[eof_pos + 5:]
            if len(trailing.strip()) > 10:
                hidden.append({
                    'type': 'PDF trailing data',
                    'offset': eof_pos + 5,
                    'size': len(trailing),
                    'preview': trailing[:50].hex()
                })
        
        # Null byte regions
        null_regions = []
        start = None
        for i, b in enumerate(data):
            if b == 0:
                if start is None:
                    start = i
            else:
                if start is not None:
                    length = i - start
                    if length > 100:  # Suspicious null region
                        null_regions.append((start, length))
                    start = None
        
        for start, length in null_regions[:5]:
            hidden.append({
                'type': 'Null byte region',
                'offset': start,
                'size': length
            })
        
        return hidden
    
    # ==================== ANOMALY DETECTION ====================
    
    def _detect_anomalies(self, filepath: str) -> List[str]:
        """Detect file anomalies"""
        anomalies = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        ext = os.path.splitext(filepath)[1].lower()
        
        # Extension vs content mismatch
        if ext == '.png' and not data.startswith(b'\x89PNG'):
            anomalies.append(f"File has .png extension but not PNG content")
        elif ext in ['.jpg', '.jpeg'] and not data.startswith(b'\xff\xd8'):
            anomalies.append(f"File has .jpg extension but not JPEG content")
        elif ext == '.pdf' and not data.startswith(b'%PDF'):
            anomalies.append(f"File has .pdf extension but not PDF content")
        elif ext == '.zip' and not data.startswith(b'PK'):
            anomalies.append(f"File has .zip extension but not ZIP content")
        
        # Double extensions
        if filepath.count('.') > 1:
            parts = filepath.split('.')
            if len(parts) > 2:
                anomalies.append(f"Multiple extensions detected: {'.'.join(parts[-2:])}")
        
        # High entropy sections
        entropy = self._calculate_entropy(data)
        if entropy > 7.5:
            anomalies.append(f"High entropy ({entropy:.2f}) - possibly encrypted/compressed")
        
        # Large null regions
        max_nulls = 0
        current_nulls = 0
        for b in data:
            if b == 0:
                current_nulls += 1
                max_nulls = max(max_nulls, current_nulls)
            else:
                current_nulls = 0
        
        if max_nulls > 1000:
            anomalies.append(f"Large null region detected ({max_nulls} bytes)")
        
        # Unusual file size
        size = len(data)
        if ext == '.png' and size > 50 * 1024 * 1024:  # 50MB PNG is suspicious
            anomalies.append(f"Unusually large PNG ({size} bytes)")
        
        return anomalies
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        from collections import Counter
        counts = Counter(data)
        length = len(data)
        
        entropy = 0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p) if p > 0 else 0
        
        return entropy
    
    # ==================== TIMESTAMP ANALYSIS ====================
    
    def _analyze_timestamps(self, filepath: str) -> Dict:
        """Analyze file timestamps"""
        timestamps = {}
        
        stat = os.stat(filepath)
        timestamps['created'] = datetime.fromtimestamp(stat.st_ctime)
        timestamps['modified'] = datetime.fromtimestamp(stat.st_mtime)
        timestamps['accessed'] = datetime.fromtimestamp(stat.st_atime)
        
        # Check for suspicious timestamps
        now = datetime.now()
        
        if timestamps['modified'] > now:
            timestamps['anomaly'] = "Modified time in future"
        
        if timestamps['created'].year < 1990:
            timestamps['anomaly'] = "Created time suspiciously old"
        
        return timestamps
    
    # ==================== UTILITIES ====================
    
    def _search_flags(self, text: str):
        """Search for flags"""
        if not text:
            return
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if m not in self.flags_found:
                    self.flags_found.append(m)
                    print(f"    [FLAG] {m}")


# Import math for entropy calculation
import math
