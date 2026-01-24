"""
Archive Scanning Module
Handles extraction and recursive scanning of archives
"""

import subprocess
import os
import shutil
from pathlib import Path


class ArchiveScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        self.extracted_paths = []
        
    def detect_archive_type(self, filepath):
        """Detect archive type"""
        ext = Path(filepath).suffix.lower()
        
        archive_types = {
            '.zip': 'zip',
            '.tar': 'tar',
            '.gz': 'gzip',
            '.tgz': 'tar.gz',
            '.bz2': 'bzip2',
            '.rar': 'rar',
            '.7z': '7z',
            '.xz': 'xz'
        }
        
        return archive_types.get(ext, 'unknown')
    
    def extract_archive(self, filepath, output_dir=None):
        """Extract archive based on type"""
        if output_dir is None:
            output_dir = os.path.join(
                self.config.get('output_directory', 'output'),
                '_extracted',
                Path(filepath).stem
            )
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        archive_type = self.detect_archive_type(filepath)
        extracted = False
        
        try:
            if archive_type == 'zip':
                extracted = self._extract_zip(filepath, output_dir)
            elif archive_type in ['tar', 'tar.gz', 'gzip', 'bzip2', 'xz']:
                extracted = self._extract_tar(filepath, output_dir)
            elif archive_type == 'rar':
                extracted = self._extract_rar(filepath, output_dir)
            elif archive_type == '7z':
                extracted = self._extract_7z(filepath, output_dir)
            else:
                print(f"⚠️  Unknown archive type: {archive_type}")
                
            if extracted:
                self.extracted_paths.append(output_dir)
                print(f"🔥 Extracted to: {output_dir}")
                return output_dir
                
        except Exception as e:
            print(f"❌ Extraction failed: {str(e)}")
            
        return None
    
    def _extract_zip(self, filepath, output_dir):
        """Extract ZIP archive"""
        try:
            proc = subprocess.run(
                ['unzip', '-q', '-o', filepath, '-d', output_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            return proc.returncode == 0
        except Exception as e:
            print(f"Error: {str(e)}")
            return False
    
    def _extract_tar(self, filepath, output_dir):
        """Extract TAR/GZ/BZ2 archive"""
        try:
            proc = subprocess.run(
                ['tar', '-xf', filepath, '-C', output_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            return proc.returncode == 0
        except Exception as e:
            print(f"Error: {str(e)}")
            return False
    
    def _extract_rar(self, filepath, output_dir):
        """Extract RAR archive"""
        try:
            proc = subprocess.run(
                ['unrar', 'x', '-o+', filepath, output_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            return proc.returncode == 0
        except Exception as e:
            print(f"Error: {str(e)}")
            return False
    
    def _extract_7z(self, filepath, output_dir):
        """Extract 7Z archive"""
        try:
            proc = subprocess.run(
                ['7z', 'x', f'-o{output_dir}', '-y', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            return proc.returncode == 0
        except Exception as e:
            print(f"Error: {str(e)}")
            return False
    
    def list_contents(self, extracted_dir):
        """List all files in extracted directory"""
        contents = []
        
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, extracted_dir)
                contents.append({
                    'path': filepath,
                    'relative_path': rel_path,
                    'size': os.path.getsize(filepath)
                })
        
        return contents
    
    def search_interesting_files(self, extracted_dir):
        """Search for interesting files like flag.txt, secret.txt, etc."""
        interesting_names = [
            'flag.txt', 'flag', 'secret.txt', 'secret', 
            'password.txt', 'key.txt', 'note.txt', 
            'readme.txt', 'hint.txt'
        ]
        
        found = []
        
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file.lower() in interesting_names:
                    filepath = os.path.join(root, file)
                    found.append(filepath)
                    print(f"⚠️  Found interesting file: {file}")
                    
                    # Read content if it's small
                    if os.path.getsize(filepath) < 10000:  # 10KB
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                print(f"[+] Content preview:\n{content[:500]}")
                        except:
                            pass
        
        return found
    
    def detect_nested_archives(self, extracted_dir):
        """Detect nested archives in extracted directory"""
        nested = []
        
        archive_extensions = ['.zip', '.tar', '.gz', '.tgz', '.bz2', '.rar', '.7z', '.xz']
        
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in archive_extensions:
                    filepath = os.path.join(root, file)
                    nested.append(filepath)
                    print(f"⚠️  Found nested archive: {file}")
        
        return nested
    
    def scan(self, filepath, recursion_depth=0):
        """Perform archive scan with recursive extraction"""
        print(f"\n[*] Starting archive scan on: {filepath}")
        
        max_depth = self.config.get('max_recursion_depth', 5)
        
        if recursion_depth >= max_depth:
            print(f"⚠️  Max recursion depth ({max_depth}) reached")
            return {}
        
        scan_results = {
            'filepath': filepath,
            'archive_type': self.detect_archive_type(filepath),
            'extraction_results': []
        }
        
        # Extract archive
        print(f"[*] Extracting archive (depth: {recursion_depth})...")
        extracted_dir = self.extract_archive(filepath)
        
        if extracted_dir:
            # List contents
            contents = self.list_contents(extracted_dir)
            scan_results['contents'] = contents
            print(f"[+] Extracted {len(contents)} file(s)")
            
            # Search for interesting files
            interesting = self.search_interesting_files(extracted_dir)
            scan_results['interesting_files'] = interesting
            
            # Check for nested archives
            if self.config.get('recursive_scan', True):
                nested = self.detect_nested_archives(extracted_dir)
                
                if nested:
                    scan_results['nested_archives'] = []
                    for nested_archive in nested:
                        print(f"\n[*] Processing nested archive: {nested_archive}")
                        # Recursive scan
                        nested_results = self.scan(nested_archive, recursion_depth + 1)
                        scan_results['nested_archives'].append(nested_results)
        
        return scan_results
