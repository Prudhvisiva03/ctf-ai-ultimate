"""
File Scanning Module
Detects file types and performs comprehensive scanning
"""

import subprocess
import os
import re
import magic
import magic
import base64
import binascii
from pathlib import Path
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
        try:
            # Use python-magic for accurate detection
            mime_type = magic.from_file(filepath, mime=True)
            
            # Also get human-readable description
            file_desc = magic.from_file(filepath)
            
            # Get file extension
            ext = Path(filepath).suffix.lower()
            
            return {
                'mime': mime_type,
                'description': file_desc,
                'extension': ext
            }
        except Exception as e:
            return {
                'mime': 'unknown',
                'description': str(e),
                'extension': Path(filepath).suffix.lower()
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
                return True
                
        except Exception as e:
            self.findings.append({
                'type': 'extraction',
                'message': f'Extraction failed: {str(e)}',
                'status': 'error'
            })
            
        return False

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
        
        # Run strings
        print("[*] Extracting strings...")
        strings = self.run_strings(filepath)
        
        # Search for flags in strings
        flags = self.search_flags(strings)
        if flags:
            scan_results['flags'] = flags
            for flag in flags:
                print(f"✅ FLAG FOUND: {flag}")
        
        # Run exiftool
        print("[*] Extracting metadata...")
        metadata = self.run_exiftool(filepath)
        scan_results['metadata'] = metadata
        
        # Check metadata for flags
        meta_flags = self.search_flags(str(metadata))
        if meta_flags:
            if 'flags' not in scan_results:
                scan_results['flags'] = []
            scan_results['flags'].extend(meta_flags)
            for flag in meta_flags:
                print(f"✅ FLAG FOUND IN METADATA: {flag}")
        
        # Run binwalk
        print("[*] Scanning for embedded files...")
        embedded = self.run_binwalk(filepath)
        if embedded:
            scan_results['embedded_files'] = embedded
            print(f"⚠️  Found {len(embedded)} embedded file signatures")
            for emb in embedded[:5]:  # Show first 5
                print(f"    {emb}")

        # Check for Base64
        print("[*] Checking for encoded data...")
        decoded_file = self.check_and_decode_base64(filepath)
        if decoded_file:
            scan_results['decoded_file'] = decoded_file
            
        # Deep Image Scan (LSB + OCR)
        if 'image' in file_type['mime'] and Image:
            print("[*] Performing Deep Image Analysis (LSB & OCR)...")
            image_findings = self.deep_image_scan(filepath)
            if image_findings:
                scan_results['image_analysis'] = image_findings
                # Merge flags
                if 'flags' in image_findings:
                    if 'flags' not in scan_results: scan_results['flags'] = []
                    scan_results['flags'].extend(image_findings['flags'])
                    scan_results['flags'] = list(set(scan_results['flags']))
        
        scan_results['findings'] = self.findings
        return scan_results

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
