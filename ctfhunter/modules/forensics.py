"""
CTFHunter - Forensics Module
============================

Analyzes files, archives, documents, and disk images
for hidden data and forensic artifacts.
"""

import os
import re
import subprocess
import shutil
import zipfile
import tarfile
import gzip
from typing import List
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """Result from running a tool."""
    tool_name: str
    command: str
    success: bool
    output: str
    error: str
    execution_time: float
    flags_found: List[str] = field(default_factory=list)


class ForensicsModule:
    """
    Forensics analysis module.
    
    Handles:
    - Archive extraction (zip, tar, gz, 7z, rar)
    - PDF analysis
    - Document analysis
    - Disk image analysis
    - File carving
    - Strings extraction
    - Hex dump analysis
    """
    
    def __init__(self):
        """Initialize the forensics module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check available forensics tools."""
        tools = ['binwalk', 'foremost', 'strings', 'xxd', 'file',
                 'unzip', 'tar', '7z', 'unrar', 'pdftotext', 'pdfimages',
                 'volatility', 'bulk_extractor', 'sleuthkit', 'testdisk']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str,
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a file for forensic data.
        
        Args:
            target: Path to target file
            output_dir: Directory for output files
            extracted_dir: Directory for extracted files
            mode: Analysis mode
            
        Returns:
            List of ToolResult objects
        """
        results = []
        extension = os.path.splitext(target)[1].lower()
        
        # Determine file type and run appropriate tools
        if extension in ['.zip']:
            results.extend(self._analyze_zip(target, output_dir, extracted_dir))
        elif extension in ['.tar', '.tgz', '.tar.gz']:
            results.extend(self._analyze_tar(target, output_dir, extracted_dir))
        elif extension in ['.gz'] and '.tar' not in target:
            results.extend(self._analyze_gzip(target, output_dir, extracted_dir))
        elif extension in ['.7z']:
            results.extend(self._analyze_7z(target, output_dir, extracted_dir))
        elif extension in ['.rar']:
            results.extend(self._analyze_rar(target, output_dir, extracted_dir))
        elif extension in ['.pdf']:
            results.extend(self._analyze_pdf(target, output_dir, extracted_dir))
        elif extension in ['.dd', '.img', '.raw', '.iso']:
            results.extend(self._analyze_disk_image(target, output_dir, extracted_dir))
        else:
            # Generic forensics
            results.extend(self._analyze_generic(target, output_dir, extracted_dir))
        
        # Always run strings
        results.append(self._run_strings(target, output_dir))
        
        # Always run binwalk
        results.append(self._run_binwalk(target, output_dir, extracted_dir))
        
        # Run foremost for file carving if deep mode
        if mode in ['auto', 'deep']:
            results.append(self._run_foremost(target, extracted_dir))
        
        return results
    
    def _analyze_zip(self, target: str, output_dir: str,
                     extracted_dir: str) -> List[ToolResult]:
        """Analyze ZIP archives."""
        results = []
        
        # List contents
        results.append(self._list_zip(target, output_dir))
        
        # Extract
        results.append(self._extract_zip(target, extracted_dir))
        
        return results
    
    def _list_zip(self, target: str, output_dir: str) -> ToolResult:
        """List ZIP archive contents."""
        output_lines = []
        
        try:
            with zipfile.ZipFile(target, 'r') as zf:
                output_lines.append(f"ZIP Archive: {target}")
                output_lines.append(f"Comment: {zf.comment.decode('utf-8', errors='ignore')}")
                output_lines.append("-" * 60)
                output_lines.append(f"{'Filename':<40} {'Size':<10} {'Compressed':<10}")
                output_lines.append("-" * 60)
                
                for info in zf.infolist():
                    output_lines.append(
                        f"{info.filename:<40} {info.file_size:<10} {info.compress_size:<10}"
                    )
            
            output = '\n'.join(output_lines)
            flags = self._extract_flags(output)
            
            with open(os.path.join(output_dir, "zip_contents.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="zip_list",
                command=f"unzip -l {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except zipfile.BadZipFile:
            return ToolResult(
                tool_name="zip_list",
                command=f"unzip -l {target}",
                success=False,
                output="",
                error="Invalid or corrupted ZIP file",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="zip_list",
                command=f"unzip -l {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_zip(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract ZIP archive."""
        zip_extract_dir = os.path.join(extracted_dir, "zip_extracted")
        os.makedirs(zip_extract_dir, exist_ok=True)
        
        extracted_files = []
        errors = []
        flags = []
        
        # Try Python extraction first
        try:
            with zipfile.ZipFile(target, 'r') as zf:
                for info in zf.infolist():
                    try:
                        zf.extract(info, zip_extract_dir)
                        extracted_files.append(info.filename)
                    except Exception as e:
                        errors.append(f"Failed to extract {info.filename}: {e}")
        except zipfile.BadZipFile:
            # Try with unzip command (handles some edge cases)
            try:
                result = subprocess.run(
                    ['unzip', '-o', target, '-d', zip_extract_dir],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    extracted_files = os.listdir(zip_extract_dir)
            except Exception as e:
                errors.append(f"unzip failed: {e}")
        
        # Search extracted files for flags
        for root, dirs, files in os.walk(zip_extract_dir):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        flags.extend(self._extract_flags(content))
                except Exception:
                    pass
        
        output = f"Extracted {len(extracted_files)} file(s):\n"
        output += '\n'.join(extracted_files[:50])
        if errors:
            output += f"\n\nErrors:\n" + '\n'.join(errors)
        
        return ToolResult(
            tool_name="zip_extract",
            command=f"unzip {target}",
            success=len(extracted_files) > 0,
            output=output[:5000],
            error='\n'.join(errors) if errors else "",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _analyze_tar(self, target: str, output_dir: str,
                     extracted_dir: str) -> List[ToolResult]:
        """Analyze TAR archives."""
        results = []
        tar_extract_dir = os.path.join(extracted_dir, "tar_extracted")
        os.makedirs(tar_extract_dir, exist_ok=True)
        
        output_lines = []
        extracted_files = []
        flags = []
        
        try:
            # Open tar file (handles .tar, .tar.gz, .tgz)
            mode = 'r:gz' if target.endswith(('.gz', '.tgz')) else 'r'
            
            with tarfile.open(target, mode) as tf:
                output_lines.append(f"TAR Archive: {target}")
                output_lines.append("-" * 60)
                
                for member in tf.getmembers():
                    output_lines.append(f"{member.name} ({member.size} bytes)")
                    extracted_files.append(member.name)
                
                # Extract all
                tf.extractall(tar_extract_dir)
            
            output = '\n'.join(output_lines)
            
            # Save listing
            with open(os.path.join(output_dir, "tar_contents.txt"), 'w') as f:
                f.write(output)
            
            # Search for flags
            for root, dirs, files in os.walk(tar_extract_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            results.append(ToolResult(
                tool_name="tar_extract",
                command=f"tar -xvf {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=list(set(flags))
            ))
            
        except Exception as e:
            results.append(ToolResult(
                tool_name="tar_extract",
                command=f"tar -xvf {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            ))
        
        return results
    
    def _analyze_gzip(self, target: str, output_dir: str,
                      extracted_dir: str) -> List[ToolResult]:
        """Analyze GZIP files."""
        results = []
        output_file = os.path.join(extracted_dir, os.path.basename(target).replace('.gz', ''))
        
        try:
            with gzip.open(target, 'rb') as gz:
                content = gz.read()
            
            with open(output_file, 'wb') as f:
                f.write(content)
            
            # Check for flags in decompressed content
            try:
                text_content = content.decode('utf-8', errors='ignore')
                flags = self._extract_flags(text_content)
            except Exception:
                flags = []
            
            results.append(ToolResult(
                tool_name="gzip_extract",
                command=f"gunzip {target}",
                success=True,
                output=f"Decompressed to: {output_file} ({len(content)} bytes)",
                error="",
                execution_time=0,
                flags_found=flags
            ))
            
        except Exception as e:
            results.append(ToolResult(
                tool_name="gzip_extract",
                command=f"gunzip {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            ))
        
        return results
    
    def _analyze_7z(self, target: str, output_dir: str,
                    extracted_dir: str) -> List[ToolResult]:
        """Analyze 7z archives."""
        results = []
        extract_dir = os.path.join(extracted_dir, "7z_extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            # List contents
            list_result = subprocess.run(
                ['7z', 'l', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            with open(os.path.join(output_dir, "7z_contents.txt"), 'w') as f:
                f.write(list_result.stdout)
            
            # Extract
            extract_result = subprocess.run(
                ['7z', 'x', '-y', f'-o{extract_dir}', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Search for flags
            flags = []
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            results.append(ToolResult(
                tool_name="7z_extract",
                command=f"7z x {target}",
                success=extract_result.returncode == 0,
                output=list_result.stdout[:5000],
                error=extract_result.stderr[:1000] if extract_result.stderr else "",
                execution_time=0,
                flags_found=list(set(flags))
            ))
            
        except FileNotFoundError:
            results.append(ToolResult(
                tool_name="7z_extract",
                command=f"7z x {target}",
                success=False,
                output="",
                error="7z not installed. Install with: apt install p7zip-full",
                execution_time=0,
                flags_found=[]
            ))
        except Exception as e:
            results.append(ToolResult(
                tool_name="7z_extract",
                command=f"7z x {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            ))
        
        return results
    
    def _analyze_rar(self, target: str, output_dir: str,
                     extracted_dir: str) -> List[ToolResult]:
        """Analyze RAR archives."""
        results = []
        extract_dir = os.path.join(extracted_dir, "rar_extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            result = subprocess.run(
                ['unrar', 'x', '-y', target, extract_dir],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Search for flags
            flags = []
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            results.append(ToolResult(
                tool_name="rar_extract",
                command=f"unrar x {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=list(set(flags))
            ))
            
        except FileNotFoundError:
            results.append(ToolResult(
                tool_name="rar_extract",
                command=f"unrar x {target}",
                success=False,
                output="",
                error="unrar not installed. Install with: apt install unrar",
                execution_time=0,
                flags_found=[]
            ))
        except Exception as e:
            results.append(ToolResult(
                tool_name="rar_extract",
                command=f"unrar x {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            ))
        
        return results
    
    def _analyze_pdf(self, target: str, output_dir: str,
                     extracted_dir: str) -> List[ToolResult]:
        """Analyze PDF documents."""
        results = []
        
        # Extract text with pdftotext
        if self.available_tools.get('pdftotext'):
            results.append(self._run_pdftotext(target, output_dir))
        
        # Extract images with pdfimages
        if self.available_tools.get('pdfimages'):
            results.append(self._run_pdfimages(target, extracted_dir))
        
        return results
    
    def _run_pdftotext(self, target: str, output_dir: str) -> ToolResult:
        """Extract text from PDF."""
        output_file = os.path.join(output_dir, "pdf_text.txt")
        
        try:
            result = subprocess.run(
                ['pdftotext', target, output_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Read extracted text
            content = ""
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            
            flags = self._extract_flags(content)
            
            return ToolResult(
                tool_name="pdftotext",
                command=f"pdftotext {target}",
                success=result.returncode == 0,
                output=content[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="pdftotext",
                command=f"pdftotext {target}",
                success=False,
                output="",
                error="pdftotext not installed. Install with: apt install poppler-utils",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="pdftotext",
                command=f"pdftotext {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_pdfimages(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract images from PDF."""
        images_dir = os.path.join(extracted_dir, "pdf_images")
        os.makedirs(images_dir, exist_ok=True)
        
        try:
            result = subprocess.run(
                ['pdfimages', '-all', target, os.path.join(images_dir, "image")],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Count extracted images
            images = [f for f in os.listdir(images_dir) if os.path.isfile(os.path.join(images_dir, f))]
            
            return ToolResult(
                tool_name="pdfimages",
                command=f"pdfimages -all {target}",
                success=True,
                output=f"Extracted {len(images)} image(s) to {images_dir}",
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="pdfimages",
                command=f"pdfimages {target}",
                success=False,
                output="",
                error="pdfimages not installed. Install with: apt install poppler-utils",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="pdfimages",
                command=f"pdfimages {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _analyze_disk_image(self, target: str, output_dir: str,
                            extracted_dir: str) -> List[ToolResult]:
        """Analyze disk images."""
        results = []
        
        # Run file command
        results.append(self._run_file(target, output_dir))
        
        # Run mmls if available
        results.append(self._run_mmls(target, output_dir))
        
        # Run fls if available
        results.append(self._run_fls(target, output_dir))
        
        return results
    
    def _run_mmls(self, target: str, output_dir: str) -> ToolResult:
        """Run mmls for partition listing."""
        try:
            result = subprocess.run(
                ['mmls', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            with open(os.path.join(output_dir, "mmls_output.txt"), 'w') as f:
                f.write(result.stdout)
            
            return ToolResult(
                tool_name="mmls",
                command=f"mmls {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="mmls",
                command=f"mmls {target}",
                success=False,
                output="",
                error="mmls not installed. Install with: apt install sleuthkit",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="mmls",
                command=f"mmls {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_fls(self, target: str, output_dir: str) -> ToolResult:
        """Run fls for file listing."""
        try:
            result = subprocess.run(
                ['fls', '-r', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            with open(os.path.join(output_dir, "fls_output.txt"), 'w') as f:
                f.write(result.stdout)
            
            flags = self._extract_flags(result.stdout)
            
            return ToolResult(
                tool_name="fls",
                command=f"fls -r {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="fls",
                command=f"fls {target}",
                success=False,
                output="",
                error="fls not installed. Install with: apt install sleuthkit",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="fls",
                command=f"fls {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _analyze_generic(self, target: str, output_dir: str,
                         extracted_dir: str) -> List[ToolResult]:
        """Generic file analysis."""
        results = []
        results.append(self._run_file(target, output_dir))
        results.append(self._run_xxd(target, output_dir))
        return results
    
    def _run_file(self, target: str, output_dir: str) -> ToolResult:
        """Run file command."""
        try:
            result = subprocess.run(
                ['file', '-b', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return ToolResult(
                tool_name="file",
                command=f"file {target}",
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="file",
                command=f"file {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_strings(self, target: str, output_dir: str) -> ToolResult:
        """Run strings command."""
        try:
            result = subprocess.run(
                ['strings', '-n', '4', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Save full output
            with open(os.path.join(output_dir, "strings_output.txt"), 'w') as f:
                f.write(result.stdout)
            
            flags = self._extract_flags(result.stdout)
            
            # Show interesting strings
            interesting = []
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['flag', 'pass', 'secret', 'key', 'ctf', 'htb']):
                    interesting.append(line)
            
            output = f"Total strings: {len(result.stdout.split(chr(10)))}\n"
            output += f"Interesting strings ({len(interesting)}):\n"
            output += '\n'.join(interesting[:50])
            
            return ToolResult(
                tool_name="strings",
                command=f"strings -n 4 {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except Exception as e:
            return ToolResult(
                tool_name="strings",
                command=f"strings {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_xxd(self, target: str, output_dir: str) -> ToolResult:
        """Run xxd for hex dump."""
        try:
            result = subprocess.run(
                ['xxd', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Save full hex dump
            with open(os.path.join(output_dir, "hexdump.txt"), 'w') as f:
                f.write(result.stdout)
            
            # Show first and last parts
            lines = result.stdout.split('\n')
            output = "First 20 lines:\n"
            output += '\n'.join(lines[:20])
            output += "\n\n... (see hexdump.txt for full output) ...\n\n"
            output += "Last 20 lines:\n"
            output += '\n'.join(lines[-20:])
            
            return ToolResult(
                tool_name="xxd",
                command=f"xxd {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="xxd",
                command=f"xxd {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_binwalk(self, target: str, output_dir: str,
                     extracted_dir: str) -> ToolResult:
        """Run binwalk for embedded file detection."""
        try:
            # Analyze
            result = subprocess.run(
                ['binwalk', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Extract
            extract_result = subprocess.run(
                ['binwalk', '-e', '-C', extracted_dir, target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = f"=== ANALYSIS ===\n{result.stdout}\n"
            output += f"\n=== EXTRACTION ===\n{extract_result.stdout}"
            
            with open(os.path.join(output_dir, "binwalk_output.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="binwalk",
                command=f"binwalk -e {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="binwalk",
                command=f"binwalk {target}",
                success=False,
                output="",
                error="binwalk not installed. Install with: apt install binwalk",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="binwalk",
                command=f"binwalk {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_foremost(self, target: str, extracted_dir: str) -> ToolResult:
        """Run foremost for file carving."""
        foremost_dir = os.path.join(extracted_dir, "foremost")
        
        try:
            result = subprocess.run(
                ['foremost', '-i', target, '-o', foremost_dir, '-T'],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            # Count carved files
            carved_files = []
            if os.path.exists(foremost_dir):
                for root, dirs, files in os.walk(foremost_dir):
                    for f in files:
                        if f != 'audit.txt':
                            carved_files.append(os.path.join(root, f))
            
            output = f"Carved {len(carved_files)} file(s)\n"
            output += '\n'.join(carved_files[:50])
            
            return ToolResult(
                tool_name="foremost",
                command=f"foremost -i {target}",
                success=len(carved_files) > 0 or result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="foremost",
                command=f"foremost {target}",
                success=False,
                output="",
                error="foremost not installed. Install with: apt install foremost",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="foremost",
                command=f"foremost {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_flags(self, text: str) -> List[str]:
        """Extract flags from text."""
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'THM\{[^}]+\}',
        ]
        
        flags = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
