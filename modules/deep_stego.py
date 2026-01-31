#!/usr/bin/env python3
"""
Deep Steganography Module - In-Depth Image/Audio Stego Analysis
Goes beyond surface-level tools to find hidden data
"""

import subprocess
import os
import re
import struct
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class DeepStegoAnalyzer:
    """
    In-depth steganography analysis that examines every layer.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = config.get('output_directory', 'output') if config else 'output'
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.flags_found = []
        self.findings = []
        
        self.flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'THM\{[^}]+\}'
        ]
    
    def analyze_image(self, filepath: str) -> Dict:
        """Comprehensive image steganography analysis"""
        print(f"\n[DEEP STEGO] Analyzing image: {filepath}")
        print("=" * 60)
        
        results = {
            'filepath': filepath,
            'chunk_analysis': {},
            'lsb_analysis': {},
            'color_plane_analysis': {},
            'metadata_hidden': {},
            'appended_data': {},
            'tool_results': {},
            'flags_found': []
        }
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Determine image type
        if data.startswith(b'\x89PNG'):
            results['image_type'] = 'PNG'
            results['chunk_analysis'] = self._analyze_png_chunks(data, filepath)
        elif data.startswith(b'\xff\xd8'):
            results['image_type'] = 'JPEG'
            results['chunk_analysis'] = self._analyze_jpeg_markers(data, filepath)
        elif data.startswith(b'GIF'):
            results['image_type'] = 'GIF'
            results['chunk_analysis'] = self._analyze_gif_blocks(data, filepath)
        elif data.startswith(b'BM'):
            results['image_type'] = 'BMP'
            results['chunk_analysis'] = self._analyze_bmp(data, filepath)
        
        # LSB Analysis
        results['lsb_analysis'] = self._deep_lsb_analysis(data, filepath)
        
        # Color plane separation
        results['color_plane_analysis'] = self._analyze_color_planes(filepath)
        
        # Check for data after EOF
        results['appended_data'] = self._check_appended_data(data, filepath)
        
        # Run all stego tools
        results['tool_results'] = self._run_all_stego_tools(filepath)
        
        # Brute force common passwords
        results['password_crack'] = self._try_password_extraction(filepath)
        
        results['flags_found'] = self.flags_found
        
        return results
    
    # ==================== PNG ANALYSIS ====================
    
    def _analyze_png_chunks(self, data: bytes, filepath: str) -> Dict:
        """Deep analysis of PNG chunks"""
        print("[*] Analyzing PNG chunks...")
        
        analysis = {
            'chunks': [],
            'suspicious_chunks': [],
            'hidden_data': []
        }
        
        # Skip PNG signature
        pos = 8
        
        while pos < len(data) - 12:
            # Read chunk header
            length = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
            chunk_data = data[pos+8:pos+8+length]
            crc = struct.unpack('>I', data[pos+8+length:pos+12+length])[0]
            
            chunk_info = {
                'type': chunk_type,
                'offset': pos,
                'length': length,
                'crc': hex(crc)
            }
            analysis['chunks'].append(chunk_info)
            
            # Check for suspicious chunks
            standard_chunks = ['IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt', 'iTXt', 
                             'gAMA', 'cHRM', 'sRGB', 'iCCP', 'bKGD', 'pHYs', 'tIME']
            
            if chunk_type not in standard_chunks:
                msg = f"Non-standard chunk: {chunk_type} at offset {pos}"
                print(f"    [!] {msg}")
                analysis['suspicious_chunks'].append({
                    'type': chunk_type,
                    'offset': pos,
                    'data': chunk_data[:100].hex()
                })
                
                # Extract chunk data
                chunk_path = os.path.join(self.output_dir, f'chunk_{chunk_type}_{pos}.bin')
                with open(chunk_path, 'wb') as f:
                    f.write(chunk_data)
                print(f"    [+] Extracted to: {chunk_path}")
                
                # Search for flags
                self._search_flags(chunk_data)
            
            # Check tEXt, zTXt, iTXt chunks for hidden data
            if chunk_type in ['tEXt', 'zTXt', 'iTXt']:
                print(f"    [*] Found text chunk: {chunk_type}")
                
                if chunk_type == 'tEXt':
                    # Null-separated keyword and text
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode('ascii', errors='ignore')
                        text = chunk_data[null_pos+1:].decode('utf-8', errors='ignore')
                        print(f"        {keyword}: {text[:100]}")
                        self._search_flags(text.encode())
                        
                elif chunk_type == 'zTXt':
                    # Compressed text
                    try:
                        import zlib
                        null_pos = chunk_data.find(b'\x00')
                        if null_pos > 0:
                            keyword = chunk_data[:null_pos].decode('ascii', errors='ignore')
                            compressed = chunk_data[null_pos+2:]  # Skip null and compression method
                            text = zlib.decompress(compressed).decode('utf-8', errors='ignore')
                            print(f"        {keyword} (decompressed): {text[:100]}")
                            self._search_flags(text.encode())
                    except:
                        pass
            
            # Check IDAT for anomalies
            if chunk_type == 'IDAT':
                # Multiple small IDAT chunks can hide data
                if length < 1000:
                    analysis['suspicious_chunks'].append({
                        'type': 'small_IDAT',
                        'offset': pos,
                        'length': length
                    })
            
            pos += 12 + length
            
            if chunk_type == 'IEND':
                # Check for data after IEND
                if pos < len(data):
                    remaining = data[pos:]
                    if len(remaining) > 10:
                        msg = f"Found {len(remaining)} bytes after IEND!"
                        print(f"    [!] {msg}")
                        analysis['hidden_data'].append({
                            'location': 'after_IEND',
                            'size': len(remaining),
                            'preview': remaining[:50].hex()
                        })
                        
                        hidden_path = os.path.join(self.output_dir, 'png_hidden_after_iend.bin')
                        with open(hidden_path, 'wb') as f:
                            f.write(remaining)
                        print(f"    [+] Extracted to: {hidden_path}")
                        self._search_flags(remaining)
                break
        
        return analysis
    
    # ==================== JPEG ANALYSIS ====================
    
    def _analyze_jpeg_markers(self, data: bytes, filepath: str) -> Dict:
        """Deep analysis of JPEG markers"""
        print("[*] Analyzing JPEG markers...")
        
        analysis = {
            'markers': [],
            'app_segments': [],
            'comments': [],
            'suspicious': []
        }
        
        pos = 0
        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                pos += 1
                continue
            
            marker = data[pos+1]
            
            # Get marker name
            marker_names = {
                0xD8: 'SOI', 0xD9: 'EOI', 0xDA: 'SOS',
                0xDB: 'DQT', 0xC0: 'SOF0', 0xC2: 'SOF2',
                0xC4: 'DHT', 0xDD: 'DRI', 0xFE: 'COM',
                0xE0: 'APP0', 0xE1: 'APP1', 0xE2: 'APP2',
                0xE3: 'APP3', 0xE4: 'APP4', 0xE5: 'APP5',
                0xE6: 'APP6', 0xE7: 'APP7', 0xE8: 'APP8',
                0xE9: 'APP9', 0xEA: 'APP10', 0xEB: 'APP11',
                0xEC: 'APP12', 0xED: 'APP13', 0xEE: 'APP14',
                0xEF: 'APP15'
            }
            
            name = marker_names.get(marker, f'0x{marker:02X}')
            
            if marker in [0xD8, 0xD9]:  # SOI, EOI - no length
                analysis['markers'].append({'name': name, 'offset': pos})
                pos += 2
                
                if marker == 0xD9:  # EOI
                    if pos < len(data):
                        remaining = data[pos:]
                        if len(remaining) > 10:
                            print(f"    [!] Found {len(remaining)} bytes after EOI!")
                            hidden_path = os.path.join(self.output_dir, 'jpeg_hidden_after_eoi.bin')
                            with open(hidden_path, 'wb') as f:
                                f.write(remaining)
                            print(f"    [+] Extracted to: {hidden_path}")
                            self._search_flags(remaining)
                    break
                continue
            
            if marker == 0x00:  # Stuffed byte
                pos += 2
                continue
            
            if pos + 4 > len(data):
                break
            
            length = struct.unpack('>H', data[pos+2:pos+4])[0]
            segment_data = data[pos+4:pos+2+length]
            
            analysis['markers'].append({
                'name': name,
                'offset': pos,
                'length': length
            })
            
            # Check APP segments for hidden data
            if 0xE0 <= marker <= 0xEF:
                print(f"    [*] Found {name} segment ({length} bytes)")
                analysis['app_segments'].append({
                    'name': name,
                    'offset': pos,
                    'length': length,
                    'preview': segment_data[:50].hex()
                })
                self._search_flags(segment_data)
                
                # APP1 often contains EXIF - check for unusual data
                if marker == 0xE1 and not segment_data.startswith(b'Exif'):
                    print(f"    [!] APP1 doesn't start with 'Exif' - suspicious!")
                    analysis['suspicious'].append({
                        'type': 'unusual_APP1',
                        'offset': pos,
                        'data': segment_data[:100].hex()
                    })
            
            # Check comments
            if marker == 0xFE:
                comment = segment_data.decode('utf-8', errors='ignore')
                print(f"    [*] Found comment: {comment[:100]}")
                analysis['comments'].append(comment)
                self._search_flags(segment_data)
            
            pos += 2 + length
        
        return analysis
    
    # ==================== GIF ANALYSIS ====================
    
    def _analyze_gif_blocks(self, data: bytes, filepath: str) -> Dict:
        """Deep analysis of GIF blocks"""
        print("[*] Analyzing GIF blocks...")
        
        analysis = {
            'version': data[3:6].decode('ascii'),
            'extension_blocks': [],
            'comment_extensions': [],
            'suspicious': []
        }
        
        # Skip header and logical screen descriptor
        pos = 13
        
        while pos < len(data):
            if data[pos] == 0x21:  # Extension
                ext_type = data[pos+1]
                
                if ext_type == 0xFE:  # Comment extension
                    pos += 2
                    comment = b''
                    while data[pos] != 0:
                        block_size = data[pos]
                        comment += data[pos+1:pos+1+block_size]
                        pos += 1 + block_size
                    pos += 1
                    
                    comment_text = comment.decode('utf-8', errors='ignore')
                    print(f"    [*] Found GIF comment: {comment_text[:100]}")
                    analysis['comment_extensions'].append(comment_text)
                    self._search_flags(comment)
                    
                elif ext_type == 0xFF:  # Application extension
                    pos += 2
                    block_size = data[pos]
                    app_id = data[pos+1:pos+1+block_size]
                    print(f"    [*] Found application extension: {app_id}")
                    pos += 1 + block_size
                    
                    # Read sub-blocks
                    ext_data = b''
                    while data[pos] != 0:
                        sub_size = data[pos]
                        ext_data += data[pos+1:pos+1+sub_size]
                        pos += 1 + sub_size
                    pos += 1
                    
                    self._search_flags(ext_data)
                else:
                    pos += 2
                    while data[pos] != 0:
                        pos += 1 + data[pos]
                    pos += 1
                    
            elif data[pos] == 0x2C:  # Image descriptor
                pos += 10
                if data[pos] & 0x80:  # Local color table
                    pos += 3 * (2 ** ((data[pos] & 0x07) + 1))
                pos += 1
                # Skip image data
                while data[pos] != 0:
                    pos += 1 + data[pos]
                pos += 1
                
            elif data[pos] == 0x3B:  # Trailer
                if pos + 1 < len(data):
                    remaining = data[pos+1:]
                    if len(remaining) > 0:
                        print(f"    [!] Found {len(remaining)} bytes after GIF trailer!")
                        hidden_path = os.path.join(self.output_dir, 'gif_hidden_after_trailer.bin')
                        with open(hidden_path, 'wb') as f:
                            f.write(remaining)
                        self._search_flags(remaining)
                break
            else:
                pos += 1
        
        return analysis
    
    # ==================== BMP ANALYSIS ====================
    
    def _analyze_bmp(self, data: bytes, filepath: str) -> Dict:
        """Deep analysis of BMP files"""
        print("[*] Analyzing BMP structure...")
        
        analysis = {
            'header': {},
            'suspicious': []
        }
        
        # BMP header
        file_size = struct.unpack('<I', data[2:6])[0]
        data_offset = struct.unpack('<I', data[10:14])[0]
        
        analysis['header'] = {
            'file_size_header': file_size,
            'actual_size': len(data),
            'data_offset': data_offset
        }
        
        if file_size != len(data):
            print(f"    [!] File size mismatch! Header: {file_size}, Actual: {len(data)}")
            if len(data) > file_size:
                hidden = data[file_size:]
                print(f"    [!] Found {len(hidden)} hidden bytes!")
                hidden_path = os.path.join(self.output_dir, 'bmp_hidden_data.bin')
                with open(hidden_path, 'wb') as f:
                    f.write(hidden)
                self._search_flags(hidden)
        
        # Check padding between header and pixel data
        header_size = 14 + struct.unpack('<I', data[14:18])[0]
        if data_offset > header_size:
            gap = data[header_size:data_offset]
            if any(b != 0 for b in gap):
                print(f"    [!] Found non-zero data in header gap!")
                self._search_flags(gap)
        
        return analysis
    
    # ==================== LSB ANALYSIS ====================
    
    def _deep_lsb_analysis(self, data: bytes, filepath: str) -> Dict:
        """Deep LSB analysis"""
        print("[*] Performing deep LSB analysis...")
        
        analysis = {
            'lsb_1bit': '',
            'lsb_2bit': '',
            'lsb_patterns': []
        }
        
        # Extract LSBs
        lsb_1 = ''.join(str(b & 1) for b in data[:10000])
        lsb_2 = ''.join(format(b & 3, '02b') for b in data[:5000])
        
        # Convert to bytes
        try:
            lsb_bytes = bytes(int(lsb_1[i:i+8], 2) for i in range(0, len(lsb_1)-7, 8))
            printable = sum(32 <= b < 127 for b in lsb_bytes)
            if printable > len(lsb_bytes) * 0.7:
                text = lsb_bytes.decode('ascii', errors='ignore')
                print(f"    [!] LSB contains text: {text[:100]}")
                analysis['lsb_1bit'] = text
                self._search_flags(lsb_bytes)
        except:
            pass
        
        # Try different bit planes
        for plane in range(8):
            bits = ''.join(str((b >> plane) & 1) for b in data[:10000])
            try:
                plane_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
                printable = sum(32 <= b < 127 for b in plane_bytes)
                if printable > len(plane_bytes) * 0.7:
                    text = plane_bytes.decode('ascii', errors='ignore')
                    print(f"    [!] Bit plane {plane} contains text: {text[:50]}")
                    self._search_flags(plane_bytes)
            except:
                pass
        
        return analysis
    
    # ==================== COLOR PLANE ANALYSIS ====================
    
    def _analyze_color_planes(self, filepath: str) -> Dict:
        """Separate and analyze color planes"""
        print("[*] Analyzing color planes...")
        
        analysis = {}
        
        try:
            from PIL import Image
            img = Image.open(filepath)
            
            if img.mode in ['RGB', 'RGBA']:
                # Separate channels
                channels = img.split()
                channel_names = ['red', 'green', 'blue', 'alpha'][:len(channels)]
                
                for name, channel in zip(channel_names, channels):
                    # Save channel
                    channel_path = os.path.join(self.output_dir, f'{name}_channel.png')
                    channel.save(channel_path)
                    
                    # Analyze channel data
                    channel_data = list(channel.getdata())
                    
                    # Extract LSB from channel
                    lsb_bits = ''.join(str(p & 1) for p in channel_data[:10000])
                    try:
                        lsb_bytes = bytes(int(lsb_bits[i:i+8], 2) for i in range(0, len(lsb_bits)-7, 8))
                        printable = sum(32 <= b < 127 for b in lsb_bytes)
                        if printable > len(lsb_bytes) * 0.6:
                            text = lsb_bytes.decode('ascii', errors='ignore')
                            print(f"    [!] {name} channel LSB: {text[:50]}")
                            self._search_flags(lsb_bytes)
                            analysis[f'{name}_lsb'] = text[:200]
                    except:
                        pass
                    
                print(f"    [+] Saved color planes to output directory")
                
        except ImportError:
            print("    [!] PIL not available for color plane analysis")
        except Exception as e:
            print(f"    [!] Color plane analysis error: {e}")
        
        return analysis
    
    # ==================== APPENDED DATA ====================
    
    def _check_appended_data(self, data: bytes, filepath: str) -> Dict:
        """Check for data appended after file structure"""
        print("[*] Checking for appended data...")
        
        # This is handled in chunk analysis, but double-check here
        return {}
    
    # ==================== STEGO TOOLS ====================
    
    def _run_all_stego_tools(self, filepath: str) -> Dict:
        """Run all available steganography tools"""
        print("[*] Running steganography tools...")
        
        results = {}
        
        # zsteg (PNG/BMP)
        results['zsteg'] = self._run_zsteg(filepath)
        
        # steghide (JPEG)
        results['steghide'] = self._run_steghide(filepath)
        
        # stegseek (fast steghide cracker)
        results['stegseek'] = self._run_stegseek(filepath)
        
        # outguess
        results['outguess'] = self._run_outguess(filepath)
        
        # jsteg
        results['jsteg'] = self._run_jsteg(filepath)
        
        # exiftool
        results['exiftool'] = self._run_exiftool(filepath)
        
        # binwalk
        results['binwalk'] = self._run_binwalk(filepath)
        
        # foremost
        results['foremost'] = self._run_foremost(filepath)
        
        return results
    
    def _run_zsteg(self, filepath: str) -> Dict:
        """Run zsteg with all options"""
        result = {'available': False, 'findings': []}
        
        try:
            # Basic scan
            proc = subprocess.run(
                ['zsteg', '-a', filepath],
                capture_output=True, text=True, timeout=60
            )
            result['available'] = True
            
            if proc.stdout:
                for line in proc.stdout.split('\n'):
                    if line.strip() and 'nothing' not in line.lower():
                        result['findings'].append(line.strip())
                        self._search_flags(line.encode())
                        
                if result['findings']:
                    print(f"    [+] zsteg found {len(result['findings'])} items")
                    
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_steghide(self, filepath: str) -> Dict:
        """Run steghide with various passwords"""
        result = {'available': False, 'extracted': False}
        
        try:
            # Try empty password
            output_path = os.path.join(self.output_dir, 'steghide_extracted.txt')
            proc = subprocess.run(
                ['steghide', 'extract', '-sf', filepath, '-p', '', '-xf', output_path, '-f'],
                capture_output=True, text=True, timeout=30
            )
            result['available'] = True
            
            if proc.returncode == 0 and os.path.exists(output_path):
                result['extracted'] = True
                with open(output_path, 'rb') as f:
                    content = f.read()
                result['content'] = content[:500]
                print(f"    [+] steghide extracted data (empty password)!")
                self._search_flags(content)
                
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_stegseek(self, filepath: str) -> Dict:
        """Run stegseek for fast password cracking"""
        result = {'available': False}
        
        try:
            output_path = os.path.join(self.output_dir, 'stegseek_extracted.txt')
            
            # Try with rockyou if available
            wordlists = [
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/wordlists/rockyou.txt.gz',
                'C:\\wordlists\\rockyou.txt'
            ]
            
            for wordlist in wordlists:
                if os.path.exists(wordlist):
                    proc = subprocess.run(
                        ['stegseek', filepath, wordlist, '-xf', output_path],
                        capture_output=True, text=True, timeout=120
                    )
                    result['available'] = True
                    
                    if proc.returncode == 0:
                        result['cracked'] = True
                        result['output'] = proc.stdout
                        print(f"    [+] stegseek cracked the password!")
                        
                        if os.path.exists(output_path):
                            with open(output_path, 'rb') as f:
                                self._search_flags(f.read())
                    break
                    
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_outguess(self, filepath: str) -> Dict:
        """Run outguess"""
        result = {'available': False}
        
        try:
            output_path = os.path.join(self.output_dir, 'outguess_extracted.txt')
            
            proc = subprocess.run(
                ['outguess', '-r', filepath, output_path],
                capture_output=True, text=True, timeout=30
            )
            result['available'] = True
            
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                result['extracted'] = True
                with open(output_path, 'rb') as f:
                    content = f.read()
                print(f"    [+] outguess extracted data!")
                self._search_flags(content)
                
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_jsteg(self, filepath: str) -> Dict:
        """Run jsteg"""
        result = {'available': False}
        
        try:
            proc = subprocess.run(
                ['jsteg', 'reveal', filepath],
                capture_output=True, timeout=30
            )
            result['available'] = True
            
            if proc.returncode == 0 and proc.stdout:
                result['content'] = proc.stdout[:500]
                print(f"    [+] jsteg found hidden data!")
                self._search_flags(proc.stdout)
                
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_exiftool(self, filepath: str) -> Dict:
        """Run exiftool for comprehensive metadata"""
        result = {'available': False, 'metadata': {}}
        
        try:
            proc = subprocess.run(
                ['exiftool', '-all', '-G', filepath],
                capture_output=True, text=True, timeout=30
            )
            result['available'] = True
            
            for line in proc.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    result['metadata'][key.strip()] = value.strip()
                    self._search_flags(value.encode())
                    
            print(f"    [+] exiftool found {len(result['metadata'])} metadata fields")
            
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_binwalk(self, filepath: str) -> Dict:
        """Run binwalk for embedded files"""
        result = {'available': False, 'findings': []}
        
        try:
            # Scan
            proc = subprocess.run(
                ['binwalk', filepath],
                capture_output=True, text=True, timeout=60
            )
            result['available'] = True
            
            for line in proc.stdout.split('\n'):
                if line.strip() and not line.startswith('DECIMAL'):
                    result['findings'].append(line.strip())
            
            # Extract
            extract_dir = os.path.join(self.output_dir, '_binwalk_extracted')
            proc = subprocess.run(
                ['binwalk', '-e', '-C', extract_dir, filepath],
                capture_output=True, text=True, timeout=120
            )
            
            if os.path.exists(extract_dir):
                result['extracted_to'] = extract_dir
                print(f"    [+] binwalk extracted files to: {extract_dir}")
                
                # Search for flags in extracted files
                for root, dirs, files in os.walk(extract_dir):
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            with open(fpath, 'rb') as fp:
                                self._search_flags(fp.read())
                        except:
                            pass
                            
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_foremost(self, filepath: str) -> Dict:
        """Run foremost for file carving"""
        result = {'available': False}
        
        try:
            output_dir = os.path.join(self.output_dir, '_foremost_output')
            os.makedirs(output_dir, exist_ok=True)
            
            proc = subprocess.run(
                ['foremost', '-i', filepath, '-o', output_dir, '-T'],
                capture_output=True, text=True, timeout=120
            )
            result['available'] = True
            result['output_dir'] = output_dir
            
            # Count carved files
            carved = []
            for root, dirs, files in os.walk(output_dir):
                carved.extend(files)
            
            if carved:
                print(f"    [+] foremost carved {len(carved)} files")
                result['carved_files'] = carved
                
        except FileNotFoundError:
            pass
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    # ==================== PASSWORD CRACKING ====================
    
    def _try_password_extraction(self, filepath: str) -> Dict:
        """Try common passwords for steganography extraction"""
        print("[*] Trying common passwords...")
        
        result = {'tried_passwords': 0, 'success': False}
        
        common_passwords = [
            '', 'password', 'secret', 'flag', 'ctf', 'hidden', 'stego',
            'steganography', '123456', 'admin', 'root', 'test', 'pass',
            'letmein', 'welcome', 'monkey', 'dragon', 'master', 'qwerty',
            'password1', 'abc123', 'iloveyou', 'trustno1', 'sunshine'
        ]
        
        for pwd in common_passwords:
            result['tried_passwords'] += 1
            
            # Try steghide
            try:
                output_path = os.path.join(self.output_dir, f'steghide_pwd_{result["tried_passwords"]}.txt')
                proc = subprocess.run(
                    ['steghide', 'extract', '-sf', filepath, '-p', pwd, '-xf', output_path, '-f'],
                    capture_output=True, text=True, timeout=5
                )
                
                if proc.returncode == 0 and os.path.exists(output_path):
                    result['success'] = True
                    result['password'] = pwd
                    print(f"    [+] SUCCESS! Password: '{pwd}'")
                    
                    with open(output_path, 'rb') as f:
                        content = f.read()
                    result['content'] = content[:500]
                    self._search_flags(content)
                    return result
                    
            except:
                pass
        
        print(f"    [-] Tried {result['tried_passwords']} passwords, none worked")
        return result
    
    # ==================== HELPERS ====================
    
    def _search_flags(self, data):
        """Search for flags in data"""
        if isinstance(data, bytes):
            text = data.decode('utf-8', errors='ignore')
        else:
            text = data
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if m not in self.flags_found:
                    self.flags_found.append(m)
                    print(f"    [FLAG] {m}")
    
    def get_summary(self) -> str:
        """Get analysis summary"""
        lines = [
            "=" * 60,
            "DEEP STEGO ANALYSIS SUMMARY",
            "=" * 60,
            f"Flags Found: {len(self.flags_found)}",
        ]
        
        if self.flags_found:
            lines.append("\nFLAGS:")
            for flag in self.flags_found:
                lines.append(f"  [FLAG] {flag}")
        
        return '\n'.join(lines)
