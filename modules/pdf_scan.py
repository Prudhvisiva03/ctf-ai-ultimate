"""
PDF Forensics Module
Handles PDF file analysis and hidden content extraction
"""

import subprocess
import os
import re
from pathlib import Path


class PDFScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        
    def run_pdfinfo(self, filepath):
        """Extract PDF metadata using pdfinfo"""
        try:
            print("[*] Extracting PDF metadata...")
            proc = subprocess.run(
                ['pdfinfo', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                print(proc.stdout)
                return proc.stdout
            else:
                print("❌ pdfinfo failed")
                
        except FileNotFoundError:
            print("⚠️  pdfinfo not installed")
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def run_pdftotext(self, filepath):
        """Extract text from PDF"""
        try:
            output_dir = self.config.get('output_directory', 'output')
            output_file = os.path.join(output_dir, 'pdf_text.txt')
            
            print("[*] Extracting text from PDF...")
            proc = subprocess.run(
                ['pdftotext', filepath, output_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r', errors='ignore') as f:
                    content = f.read()
                    
                print(f"[+] Extracted {len(content)} characters")
                
                # Search for flags
                flags = self.search_flags(content)
                if flags:
                    for flag in flags:
                        print(f"✅ FLAG FOUND: {flag}")
                
                return {
                    'output_file': output_file,
                    'content': content,
                    'flags': flags
                }
            else:
                print("❌ Text extraction failed")
                
        except FileNotFoundError:
            print("⚠️  pdftotext not installed")
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def run_exiftool(self, filepath):
        """Extract detailed metadata using exiftool"""
        metadata = {}
        
        try:
            print("[*] Running exiftool on PDF...")
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
                
                # Check for interesting metadata
                interesting_keys = ['Author', 'Creator', 'Producer', 'Title', 'Subject', 'Keywords']
                for key in interesting_keys:
                    if key in metadata:
                        print(f"    {key}: {metadata[key]}")
                
                # Search metadata for flags
                flags = self.search_flags(str(metadata))
                if flags:
                    for flag in flags:
                        print(f"✅ FLAG FOUND IN METADATA: {flag}")
                    metadata['flags'] = flags
                    
        except FileNotFoundError:
            print("⚠️  exiftool not installed")
        except Exception as e:
            metadata['error'] = str(e)
            
        return metadata
    
    def search_flags(self, content):
        """Search for flags in content"""
        flags = []
        
        for pattern in self.config.get('flag_patterns', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def run_strings(self, filepath):
        """Extract strings from PDF"""
        try:
            print("[*] Extracting strings from PDF...")
            proc = subprocess.run(
                ['strings', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                strings_output = proc.stdout
                
                # Search for flags
                flags = self.search_flags(strings_output)
                if flags:
                    for flag in flags:
                        print(f"✅ FLAG FOUND IN STRINGS: {flag}")
                
                # Search for interesting strings
                interesting = []
                keywords = ['flag', 'password', 'key', 'secret', 'hidden']
                
                for line in strings_output.split('\n'):
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in keywords):
                        interesting.append(line)
                
                if interesting:
                    print(f"⚠️  Found {len(interesting)} interesting string(s)")
                    for s in interesting[:10]:
                        print(f"    {s}")
                
                return {
                    'flags': flags,
                    'interesting': interesting
                }
                
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def detect_embedded_files(self, filepath):
        """Detect embedded files in PDF using binwalk"""
        try:
            print("[*] Checking for embedded files...")
            proc = subprocess.run(
                ['binwalk', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                output = proc.stdout
                
                embedded = []
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('DECIMAL'):
                        embedded.append(line.strip())
                
                if embedded:
                    print(f"⚠️  Found {len(embedded)} embedded file signature(s)")
                    for emb in embedded[:5]:
                        print(f"    {emb}")
                    
                    # Auto-extract if configured
                    if self.config.get('auto_extract', True):
                        self.extract_embedded(filepath)
                    
                    return embedded
                else:
                    print("✅ No embedded files detected")
                    
        except FileNotFoundError:
            print("⚠️  binwalk not installed")
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return []
    
    def extract_embedded(self, filepath):
        """Extract embedded files using binwalk"""
        try:
            output_dir = os.path.join(
                self.config.get('output_directory', 'output'),
                '_pdf_extracted'
            )
            
            proc = subprocess.run(
                ['binwalk', '-e', '-C', output_dir, filepath],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if proc.returncode == 0:
                print(f"🔥 Extracted embedded files to {output_dir}")
                return True
                
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return False
    
    def analyze_pdf_structure(self, filepath):
        """Analyze PDF structure for anomalies"""
        try:
            print("[*] Analyzing PDF structure...")
            
            # Use pdfid if available
            proc = subprocess.run(
                ['pdfid', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                print(proc.stdout[:500])
                return proc.stdout
                
        except FileNotFoundError:
            # pdfid not available
            pass
        except Exception as e:
            pass
            
        return None
    
    def scan(self, filepath):
        """Perform comprehensive PDF forensics"""
        print(f"\n[*] Starting PDF analysis on: {filepath}")
        
        scan_results = {
            'filepath': filepath,
            'pdf_findings': []
        }
        
        # Get PDF info
        pdfinfo = self.run_pdfinfo(filepath)
        scan_results['pdfinfo'] = pdfinfo
        
        # Extract text
        text_results = self.run_pdftotext(filepath)
        if text_results:
            scan_results['text'] = text_results
            if text_results.get('flags'):
                scan_results['flags'] = text_results['flags']
        
        # Extract metadata
        metadata = self.run_exiftool(filepath)
        scan_results['metadata'] = metadata
        if metadata.get('flags'):
            if 'flags' not in scan_results:
                scan_results['flags'] = []
            scan_results['flags'].extend(metadata['flags'])
        
        # Run strings
        strings_results = self.run_strings(filepath)
        if strings_results:
            scan_results['strings'] = strings_results
            if strings_results.get('flags'):
                if 'flags' not in scan_results:
                    scan_results['flags'] = []
                scan_results['flags'].extend(strings_results['flags'])
        
        # Detect embedded files
        embedded = self.detect_embedded_files(filepath)
        if embedded:
            scan_results['embedded_files'] = embedded
        
        # Analyze structure
        structure = self.analyze_pdf_structure(filepath)
        if structure:
            scan_results['structure'] = structure
        
        return scan_results
