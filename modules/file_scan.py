"""
File Scanning Module
Detects file types and performs comprehensive scanning
"""

import subprocess
import os
import re
import base64
import binascii
from pathlib import Path

# Handle magic library import for cross-platform support
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None


class FileScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        
    def detect_file_type(self, filepath):
        """Detect file type using magic bytes and file extension"""
        ext = Path(filepath).suffix.lower()
        
        # Try python-magic first if available
        if MAGIC_AVAILABLE:
            try:
                mime_type = magic.from_file(filepath, mime=True)
                file_desc = magic.from_file(filepath)
                return {
                    'mime': mime_type,
                    'description': file_desc,
                    'extension': ext
                }
            except Exception:
                pass
        
        # Fallback: detect by reading magic bytes
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
            
            # Common file signatures
            signatures = {
                b'\x89PNG': ('image/png', 'PNG image'),
                b'\xff\xd8\xff': ('image/jpeg', 'JPEG image'),
                b'GIF87a': ('image/gif', 'GIF image'),
                b'GIF89a': ('image/gif', 'GIF image'),
                b'PK\x03\x04': ('application/zip', 'ZIP archive'),
                b'%PDF': ('application/pdf', 'PDF document'),
                b'\x7fELF': ('application/x-executable', 'ELF executable'),
                b'MZ': ('application/x-dosexec', 'PE executable'),
                b'\xd0\xcf\x11\xe0': ('application/msword', 'MS Office document'),
                b'\x1f\x8b': ('application/gzip', 'Gzip archive'),
                b'BZh': ('application/x-bzip2', 'Bzip2 archive'),
                b'Rar!': ('application/x-rar', 'RAR archive'),
                b'\xfd7zXZ': ('application/x-xz', 'XZ archive'),
            }
            
            for sig, (mime, desc) in signatures.items():
                if header.startswith(sig):
                    return {'mime': mime, 'description': desc, 'extension': ext}
            
            # Try to detect if text
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    f.read(1024)
                return {'mime': 'text/plain', 'description': 'ASCII text', 'extension': ext}
            except:
                return {'mime': 'application/octet-stream', 'description': 'Binary data', 'extension': ext}
                
        except Exception as e:
            return {
                'mime': 'unknown',
                'description': str(e),
                'extension': ext
            }
    
    def run_strings(self, filepath):
        """Extract printable strings from file"""
        results = []
        try:
            # Run strings command
            proc = subprocess.run(
                ['strings', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                strings_output = proc.stdout.split('\n')
                results = [s.strip() for s in strings_output if len(s.strip()) > 3]
                
        except Exception as e:
            results = [f"Error running strings: {str(e)}"]
            
        return results
    
    def search_flags(self, content):
        """Search for flags using regex patterns"""
        flags = []
        
        # Join content if it's a list
        if isinstance(content, list):
            content = '\n'.join(content)
        
        # Search for each flag pattern
        for pattern in self.config.get('flag_patterns', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))  # Remove duplicates
    
    def run_exiftool(self, filepath):
        """Extract metadata using exiftool"""
        metadata = {}
        try:
            proc = subprocess.run(
                ['exiftool', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        metadata[key.strip()] = value.strip()
                        
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata
    
    def run_binwalk(self, filepath):
        """Detect embedded files using binwalk"""
        embedded_files = []
        try:
            # Run binwalk scan
            proc = subprocess.run(
                ['binwalk', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                output = proc.stdout
                
                # Parse binwalk output
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('DECIMAL'):
                        embedded_files.append(line.strip())
                
                # Check if extraction is needed
                if embedded_files and self.config.get('auto_extract', True):
                    self.extract_with_binwalk(filepath)
                    
        except Exception as e:
            embedded_files.append(f"Error: {str(e)}")
            
        return embedded_files
    
    def extract_with_binwalk(self, filepath):
        """Extract embedded files using binwalk"""
        try:
            output_dir = self.config.get('output_directory', 'output')
            extract_dir = os.path.join(output_dir, '_extracted')
            
            proc = subprocess.run(
                ['binwalk', '-e', '-C', extract_dir, filepath],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if proc.returncode == 0:
                self.findings.append({
                    'type': 'extraction',
                    'message': f'Extracted files to {extract_dir}',
                    'status': 'success'
                })
                
                # ✅ AUTO-SCAN EXTRACTED FILES FOR FLAGS
                print("[*] Auto-scanning extracted files for flags...")
                extracted_flags = self.scan_extracted_files(extract_dir)
                if extracted_flags:
                    print(f"🎉 FOUND {len(extracted_flags)} FLAG(S) IN EXTRACTED FILES!")
                    for flag in extracted_flags:
                        print(f"   🚩 {flag}")
                    self.findings.append({
                        'type': 'flag_found',
                        'flags': extracted_flags,
                        'location': 'extracted_files',
                        'status': 'success'
                    })
                
                return True
                
        except Exception as e:
            self.findings.append({
                'type': 'extraction',
                'message': f'Extraction failed: {str(e)}',
                'status': 'error'
            })
            
        return False
    
    def scan_extracted_files(self, extract_dir):
        """Scan all extracted files for flags using strings"""
        flags = []
        
        if not os.path.exists(extract_dir):
            return flags
        
        print(f"   ↳ Scanning directory: {extract_dir}")
        
        # Walk through all extracted files
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    # Run strings on each file
                    proc = subprocess.run(
                        ['strings', filepath],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if proc.returncode == 0:
                        # Search for flags in strings output
                        found_flags = self.search_flags(proc.stdout)
                        if found_flags:
                            print(f"   ✅ Found flag(s) in: {os.path.basename(filepath)}")
                            flags.extend(found_flags)
                            
                except Exception as e:
                    continue  # Skip files that cause errors
        
        return list(set(flags))  # Remove duplicates

    def check_and_decode_base64(self, filepath):
        """Check for and decode large Base64 blobs"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Check if it looks like base64 characters (A-Z, a-z, 0-9, +, /, =)
            # Simple heuristic: remove whitespace, check if valid b64
            cleaned = re.sub(b'[ \t\n\r]', b'', content)
            
            if len(cleaned) > 100:  # Only bother if it's substantial data
                try:
                    # Try decoding
                    decoded_data = base64.b64decode(cleaned, validate=True)
                    
                    # If successful, detect what the decoded data IS
                    mime = magic.from_buffer(decoded_data, mime=True)
                    
                    # Create a filename for it
                    ext = mime.split('/')[-1]
                    if ext == 'octet-stream': ext = 'bin'
                    if 'image' in mime: ext = 'png' # simplification
                    
                    output_filename = f"{os.path.basename(filepath)}_decoded.{ext}"
                    output_path = os.path.join(self.config.get('output_directory', 'output'), output_filename)
                    
                    # Ensure output dir exists
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    with open(output_path, 'wb') as out:
                        out.write(decoded_data)
                        
                    self.findings.append({
                        'type': 'decoding',
                        'message': f'Detected Base64 encoded {mime} data! Decoded to {output_path}',
                        'status': 'success',
                        'new_file': output_path  # Hint for recursion
                    })
                    print(f"🔓 Automatically decoded Base64 data to: {output_path}")
                    return output_path
                    
                except binascii.Error:
                    pass # Not valid base64
                    
        except Exception as e:
            print(f"Error checking base64: {e}")
            
        return None
    
    def scan(self, filepath):
        """Perform comprehensive file scan"""
        print(f"\n[*] Starting file scan on: {filepath}")
        
        # Detect file type
        file_type = self.detect_file_type(filepath)
        print(f"[+] File type: {file_type['description']}")
        print(f"    MIME: {file_type['mime']}")
        
        scan_results = {
            'filepath': filepath,
            'file_type': file_type,
            'findings': []
        }
        
        # 1. Run strings (Basic)
        print("[*] Extracting strings...")
        strings = self.run_strings(filepath)
        flags = self.search_flags(strings)
        if flags:
            print(f"🎉 FOUND {len(flags)} FLAG(S) IN RAW FILE!")
            for flag in flags:
                print(f"   🚩 {flag}")
            scan_results['flags'] = flags
        
        # 2. Robust Archive Extraction & Scan (The Debug Script Logic)
        mime = file_type['mime'].lower()
        if any(x in mime for x in ['zip', 'compressed', 'archive', 'tar', 'gzip', 'bzip']):
            print("[*] Detected archive! Attempting auto-extraction & scan...")
            try:
                output_dir = self.config.get('output_directory', 'output')
                extract_dir = os.path.join(output_dir, '_extracted')
                os.makedirs(extract_dir, exist_ok=True)
                
                # Try 7z extraction (Robust)
                subprocess.run(['7z', 'x', filepath, f'-o{extract_dir}', '-y'], 
                             capture_output=True, check=False)
                
                # Scan Extracted
                found_in_archive = self.scan_extracted_files(extract_dir)
                if found_in_archive:
                    print(f"🎉 FOUND {len(found_in_archive)} FLAG(S) IN EXTRACTED ARCHIVE!")
                    for flag in found_in_archive:
                        print(f"   🚩 {flag}")
                    
                    # Merge findings
                    if 'flags' not in scan_results: scan_results['flags'] = []
                    scan_results['flags'].extend(found_in_archive)
                    self.findings.append({
                        'type': 'flag_found',
                        'flags': found_in_archive,
                        'location': 'archive_extraction',
                        'status': 'success'
                    })
            except Exception as e:
                print(f"⚠️  Archive scan warning: {e}")

        # 3. Binwalk (Embedded Files)
        print("[*] Scanning for embedded files...")
        embedded = self.run_binwalk(filepath)
        if embedded:
            scan_results['embedded_files'] = embedded
            print(f"⚠️  Found {len(embedded)} embedded file signatures")
            # Auto-extract if binwalk found something interesting
            if len(embedded) > 0 and self.config.get('auto_extract', True):
                self.extract_with_binwalk(filepath)

        # 4. Check for Base64
        print("[*] Checking for encoded data...")
        decoded_file = self.check_and_decode_base64(filepath)
        if decoded_file:
            scan_results['decoded_file'] = decoded_file
            
        # 5. Deep Image Scan (LSB + OCR)
        if 'image' in file_type['mime'] and Image:
            print("[*] Performing Deep Image Analysis (LSB & OCR)...")
            image_findings = self.deep_image_scan(filepath)
            if image_findings:
                scan_results['image_analysis'] = image_findings
                if 'flags' in image_findings:
                    if 'flags' not in scan_results: scan_results['flags'] = []
                    scan_results['flags'].extend(image_findings['flags'])
        
        # 6. Advanced Disk Image Scan (Partition Analysis)
        if any(x in file_type['mime'] for x in ['octet-stream', 'x-dosexec']) or filepath.endswith(('.dd', '.img', '.raw')):
            print("[*] Performing Advanced Disk Forensics (Partition Analysis)...")
            partition_findings = self.scan_disk_partitions(filepath)
            if partition_findings:
                # Merge findings
                if 'flags' not in scan_results: scan_results['flags'] = []
                scan_results['flags'].extend(partition_findings.get('flags', []))
                
        # Deduplicate flags
        if 'flags' in scan_results:
             scan_results['flags'] = list(set(scan_results['flags']))
             
        scan_results['findings'] = self.findings
        return scan_results

    def scan_disk_partitions(self, filepath):
        """Analyze disk partitions to isolate flags (avoids decoys)"""
        results = {'flags': []}
        try:
            # 1. Run mmls to find partitions
            # We use subprocess to check if mmls is available
            try:
                proc = subprocess.run(['mmls', filepath], capture_output=True, text=True)
                if proc.returncode != 0:
                    return results # mmls failed or not installed
            except FileNotFoundError:
                print("   ⚠️  'mmls' command not found, skipping partition analysis.")
                return results

            print("   ↳ Analyzing partition table...")
            partitions = []
            for line in proc.stdout.splitlines():
                parts = line.split()
                # Simple parser for mmls output looking for "Linux", "FAT", "NTFS" or generally valid partitions
                if len(parts) > 5 and parts[0].strip().isdigit():
                    # Format usually: Index Slot Start End Length Description
                    # We try to identify the Description and Start/Len
                    try:
                        # Find where the numbers usually are (Start is typically the 3rd or 4th item depending on output format)
                        # Standard TSK mmls: Slot Start End Len Description
                        # finding start sector
                        start = -1
                        length = -1
                        desc = "Unknown"
                        
                        # Heuristic: Find the first large integer that looks like a start sector
                        number_indices = [i for i, p in enumerate(parts) if p.isdigit()]
                        if len(number_indices) >= 3:
                            start = int(parts[number_indices[-3]]) # 3rd to last number
                            length = int(parts[number_indices[-1]]) # last number
                            desc_idx = number_indices[-1] + 1
                            desc = " ".join(parts[desc_idx:])
                        
                        if start > 0 and length > 0:
                            partitions.append({'start': start, 'length': length, 'desc': desc})
                    except:
                        continue

            if not partitions:
                print("   ⚠️  No partitions found or parsing failed.")
                return results

            print(f"   ✅ Found {len(partitions)} partitions. Scanning individually...")
            
            output_dir = self.config.get('output_directory', 'output')
            parts_dir = os.path.join(output_dir, '_partitions')
            os.makedirs(parts_dir, exist_ok=True)

            for i, p in enumerate(partitions):
                p_name = f"p{i}_{p['desc'].replace(' ', '_').replace('/', '-')}.dd"
                p_path = os.path.join(parts_dir, p_name)
                
                print(f"      [P{i}] {p['desc']} (Start: {p['start']}) -> Extracting...")
                
                # Extract partition using dd
                # standard sector size is 512
                # dd if=image of=part skip=START count=LEN
                subprocess.run([
                    'dd', f'if={filepath}', f'of={p_path}', 
                    'bs=512', f'skip={p["start"]}', f'count={p["length"]}'
                ], capture_output=True)
                
                # Scan this partition
                print(f"      ↳ Scanning {p_name} ...")
                p_strings = self.run_strings(p_path)
                p_flags = self.search_flags(p_strings)
                
                if p_flags:
                    print(f"      🔥 FOUND {len(p_flags)} FLAG(S) IN PARTITION: {p['desc']}")
                    for f in p_flags:
                        print(f"         🚩 {f}")
                        
                    results['flags'].extend(p_flags)
                    self.findings.append({
                        'type': 'partition_flag',
                        'partition': p['desc'],
                        'flags': p_flags,
                        'message': f"Found flags in partition {p['desc']}",
                        'status': 'success'
                    })

        except Exception as e:
            print(f"   ⚠️  Partition analysis error: {e}")
            
        return results

    def deep_image_scan(self, filepath):
        """Perform deep steganography and visual analysis on images"""
        results = {'flags': [], 'text': ''}
        
        try:
            img = Image.open(filepath)
            
            # 1. OCR Analysis (Visual Text)
            if pytesseract:
                try:
                    text = pytesseract.image_to_string(img)
                    if len(text.strip()) > 0:
                        results['text'] = text.strip()
                        # Search for flags in visual text
                        visual_flags = self.search_flags(text)
                        if visual_flags:
                            results['flags'].extend(visual_flags)
                            self.findings.append({'type': 'ocr', 'message': f'Found flag visually: {visual_flags}', 'status': 'success'})
                except Exception as e:
                    pass # OCR not available or failed
            
            # 2. LSB Steganography Analysis (Native Python)
            # We scan R, G, B, and RGB modes
            print("   ↳ Scanning LSB planes...")
            if img.mode in ['RGB', 'RGBA']:
                pixels = list(img.getdata())
                
                # Helper to check bits
                def check_bits(bits, channel_name):
                    # dynamic bit string construction
                    data = bytearray()
                    for i in range(0, len(bits), 8):
                        if i+8 > len(bits): break
                        b = bits[i:i+8]
                        data.append(int(b, 2))
                    
                    # Search in decoded bytes
                    try:
                        decoded = data.decode('utf-8', errors='ignore')
                        found = self.search_flags(decoded)
                        if found:
                            results['flags'].extend(found)
                            msg = f'Found LSB flag in {channel_name} channel: {found}'
                            self.findings.append({'type': 'stego', 'message': msg, 'status': 'success'})
                            print(f"   ✅ {msg}")
                    except: pass

                # Collect bits
                # Limit to first 500KB of data to avoid memory issues on huge images
                limit = 500000 * 8 
                
                # R, G, B, RGB channels
                r_bits = ""
                g_bits = ""
                b_bits = ""
                rgb_bits = ""
                
                count = 0
                for p in pixels:
                    # p is (r,g,b) or (r,g,b,a)
                    r, g, b = p[0], p[1], p[2]
                    
                    r_b = str(r & 1)
                    g_b = str(g & 1)
                    b_b = str(b & 1)
                    
                    r_bits += r_b
                    g_bits += g_b
                    b_bits += b_b
                    rgb_bits += r_b + g_b + b_b
                    
                    count += 1
                    if count > 500000: break # enough sample size
                
                check_bits(r_bits, "Red")
                check_bits(g_bits, "Green")
                check_bits(b_bits, "Blue")
                check_bits(rgb_bits, "RGB Combined")
                
        except Exception as e:
            print(f"   ⚠️ Image scan error: {e}")
            
        return results
