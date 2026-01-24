"""
File Scanning Module
Detects file types and performs comprehensive scanning
"""

import subprocess
import os
import re
import magic
from pathlib import Path


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
        
        scan_results['findings'] = self.findings
        return scan_results
