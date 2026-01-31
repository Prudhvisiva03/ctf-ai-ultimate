"""
CTFHunter - Reverse Engineering Module
======================================

Analyzes binary executables (ELF, PE, APK) for
reverse engineering challenges.
"""

import os
import re
import subprocess
import shutil
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


class ReverseModule:
    """
    Reverse engineering analysis module.
    
    Handles:
    - ELF binary analysis
    - PE (Windows) binary analysis
    - APK (Android) analysis
    - Security checks (checksec)
    - Disassembly
    - Symbol extraction
    - Library dependencies
    """
    
    def __init__(self):
        """Initialize the reverse engineering module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check available RE tools."""
        tools = ['file', 'strings', 'readelf', 'objdump', 'nm', 'ldd',
                 'checksec', 'ltrace', 'strace', 'gdb', 'r2', 'radare2',
                 'apktool', 'dex2jar', 'jadx', 'unzip']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str,
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a binary file.
        
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
        
        # Detect binary type
        binary_type = self._detect_binary_type(target)
        
        if binary_type == 'ELF':
            results.extend(self._analyze_elf(target, output_dir, extracted_dir, mode))
        elif binary_type == 'PE':
            results.extend(self._analyze_pe(target, output_dir, extracted_dir, mode))
        elif extension == '.apk' or binary_type == 'APK':
            results.extend(self._analyze_apk(target, output_dir, extracted_dir, mode))
        elif extension in ['.class', '.jar']:
            results.extend(self._analyze_java(target, output_dir, extracted_dir, mode))
        else:
            # Generic binary analysis
            results.extend(self._analyze_generic(target, output_dir, extracted_dir, mode))
        
        return results
    
    def _detect_binary_type(self, target: str) -> str:
        """Detect binary type using magic bytes."""
        try:
            with open(target, 'rb') as f:
                header = f.read(4)
            
            if header[:4] == b'\x7fELF':
                return 'ELF'
            elif header[:2] == b'MZ':
                return 'PE'
            elif header[:4] == b'PK\x03\x04':
                # Could be APK
                with open(target, 'rb') as f:
                    f.seek(30)
                    name_header = f.read(20)
                    if b'AndroidManifest' in name_header or b'classes.dex' in name_header:
                        return 'APK'
                return 'ZIP'
            elif header[:4] == b'\xca\xfe\xba\xbe':
                return 'JAVA_CLASS'
        except Exception:
            pass
        
        return 'UNKNOWN'
    
    def _analyze_elf(self, target: str, output_dir: str,
                     extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze ELF binary."""
        results = []
        
        # Run checksec
        results.append(self._run_checksec(target, output_dir))
        
        # Run readelf
        results.append(self._run_readelf(target, output_dir))
        
        # Run objdump for disassembly
        if mode in ['auto', 'deep']:
            results.append(self._run_objdump(target, output_dir))
        
        # Run nm for symbols
        results.append(self._run_nm(target, output_dir))
        
        # Run ldd for library dependencies
        results.append(self._run_ldd(target, output_dir))
        
        # Run strings
        results.append(self._run_strings(target, output_dir))
        
        # Check for packed binaries
        results.append(self._check_packing(target, output_dir))
        
        return results
    
    def _analyze_pe(self, target: str, output_dir: str,
                    extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze PE binary."""
        results = []
        
        # Run strings
        results.append(self._run_strings(target, output_dir))
        
        # File info
        results.append(self._run_file(target, output_dir))
        
        # Add tip for Windows analysis
        results.append(ToolResult(
            tool_name="pe_tip",
            command="manual",
            success=True,
            output="TIP: For detailed PE analysis, use:\n"
                   "- PEStudio (Windows)\n"
                   "- PE-bear\n"
                   "- DIE (Detect It Easy)\n"
                   "- Ghidra / IDA Pro for disassembly",
            error="",
            execution_time=0,
            flags_found=[]
        ))
        
        return results
    
    def _analyze_apk(self, target: str, output_dir: str,
                     extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze Android APK."""
        results = []
        
        # Extract APK (it's just a zip)
        results.append(self._extract_apk(target, extracted_dir))
        
        # Run apktool if available
        if self.available_tools.get('apktool'):
            results.append(self._run_apktool(target, extracted_dir))
        
        # Run jadx if available
        if self.available_tools.get('jadx'):
            results.append(self._run_jadx(target, extracted_dir))
        
        # Run strings
        results.append(self._run_strings(target, output_dir))
        
        return results
    
    def _analyze_java(self, target: str, output_dir: str,
                      extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze Java class/JAR files."""
        results = []
        
        extension = os.path.splitext(target)[1].lower()
        
        if extension == '.jar':
            # Extract JAR
            results.append(self._extract_jar(target, extracted_dir))
        
        # Run strings
        results.append(self._run_strings(target, output_dir))
        
        # Add tip
        results.append(ToolResult(
            tool_name="java_tip",
            command="manual",
            success=True,
            output="TIP: For Java decompilation, use:\n"
                   "- jadx (recommended)\n"
                   "- JD-GUI\n"
                   "- CFR decompiler\n"
                   "- Procyon",
            error="",
            execution_time=0,
            flags_found=[]
        ))
        
        return results
    
    def _analyze_generic(self, target: str, output_dir: str,
                         extracted_dir: str, mode: str) -> List[ToolResult]:
        """Generic binary analysis."""
        results = []
        
        results.append(self._run_file(target, output_dir))
        results.append(self._run_strings(target, output_dir))
        
        if mode in ['auto', 'deep']:
            results.append(self._run_xxd(target, output_dir))
        
        return results
    
    def _run_checksec(self, target: str, output_dir: str) -> ToolResult:
        """Run checksec for security features."""
        try:
            result = subprocess.run(
                ['checksec', '--file', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            
            with open(os.path.join(output_dir, "checksec_output.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="checksec",
                command=f"checksec --file {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="checksec",
                command=f"checksec --file {target}",
                success=False,
                output="",
                error="checksec not installed. Install with: apt install checksec",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="checksec",
                command=f"checksec --file {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_readelf(self, target: str, output_dir: str) -> ToolResult:
        """Run readelf for ELF header info."""
        try:
            # Get headers
            result = subprocess.run(
                ['readelf', '-a', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "readelf_output.txt"), 'w') as f:
                f.write(output)
            
            # Look for interesting sections
            interesting = []
            for line in output.split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['flag', 'secret', 'pass', 'key']):
                    interesting.append(line)
            
            summary = f"ELF Analysis Complete\n"
            summary += f"Interesting lines: {len(interesting)}\n"
            summary += '\n'.join(interesting[:20])
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="readelf",
                command=f"readelf -a {target}",
                success=result.returncode == 0,
                output=summary[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="readelf",
                command=f"readelf -a {target}",
                success=False,
                output="",
                error="readelf not installed. Install with: apt install binutils",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="readelf",
                command=f"readelf -a {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_objdump(self, target: str, output_dir: str) -> ToolResult:
        """Run objdump for disassembly."""
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout
            
            # Save full disassembly
            with open(os.path.join(output_dir, "objdump_disasm.txt"), 'w') as f:
                f.write(output)
            
            # Extract main function if present
            main_func = ""
            in_main = False
            for line in output.split('\n'):
                if '<main>' in line:
                    in_main = True
                    main_func = line + '\n'
                elif in_main:
                    if line.strip() and not line.startswith(' '):
                        break
                    main_func += line + '\n'
            
            summary = f"Disassembly saved to objdump_disasm.txt\n\n"
            if main_func:
                summary += f"Main function:\n{main_func[:2000]}"
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="objdump",
                command=f"objdump -d -M intel {target}",
                success=result.returncode == 0,
                output=summary[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="objdump",
                command=f"objdump -d {target}",
                success=False,
                output="",
                error="objdump not installed. Install with: apt install binutils",
                execution_time=0,
                flags_found=[]
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name="objdump",
                command=f"objdump -d {target}",
                success=False,
                output="",
                error="Disassembly timed out (binary too large)",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="objdump",
                command=f"objdump -d {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_nm(self, target: str, output_dir: str) -> ToolResult:
        """Run nm for symbol extraction."""
        try:
            result = subprocess.run(
                ['nm', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "nm_symbols.txt"), 'w') as f:
                f.write(output)
            
            # Look for interesting symbols
            interesting = []
            for line in output.split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['flag', 'secret', 'pass', 'key', 'win', 'correct']):
                    interesting.append(line)
            
            summary = f"Symbols extracted: {len(output.split(chr(10)))}\n"
            summary += f"Interesting symbols ({len(interesting)}):\n"
            summary += '\n'.join(interesting[:30])
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="nm",
                command=f"nm {target}",
                success=result.returncode == 0,
                output=summary[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="nm",
                command=f"nm {target}",
                success=False,
                output="",
                error="nm not installed. Install with: apt install binutils",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="nm",
                command=f"nm {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_ldd(self, target: str, output_dir: str) -> ToolResult:
        """Run ldd for library dependencies."""
        try:
            result = subprocess.run(
                ['ldd', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "ldd_output.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="ldd",
                command=f"ldd {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="ldd",
                command=f"ldd {target}",
                success=False,
                output="",
                error="ldd not installed",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="ldd",
                command=f"ldd {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _check_packing(self, target: str, output_dir: str) -> ToolResult:
        """Check if binary is packed."""
        indicators = []
        
        try:
            # Read sections with readelf
            result = subprocess.run(
                ['readelf', '-S', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check for UPX
            with open(target, 'rb') as f:
                content = f.read()
                if b'UPX!' in content:
                    indicators.append("UPX packed detected!")
                if b'UPX0' in content or b'UPX1' in content:
                    indicators.append("UPX sections found")
            
            # Check for suspicious section names
            sections = result.stdout.lower()
            if 'upx' in sections:
                indicators.append("UPX section names found")
            if '.packed' in sections:
                indicators.append("Packed section detected")
            
            output = "Packing Analysis:\n"
            if indicators:
                output += '\n'.join(indicators)
                output += "\n\nTry unpacking with: upx -d " + target
            else:
                output += "No obvious packing detected"
            
            return ToolResult(
                tool_name="pack_check",
                command="packing analysis",
                success=True,
                output=output,
                error="",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="pack_check",
                command="packing analysis",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_apk(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract APK as ZIP."""
        import zipfile
        
        apk_dir = os.path.join(extracted_dir, "apk_extracted")
        os.makedirs(apk_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(target, 'r') as zf:
                zf.extractall(apk_dir)
            
            # List important files
            important_files = []
            for root, dirs, files in os.walk(apk_dir):
                for f in files:
                    if f in ['AndroidManifest.xml', 'classes.dex'] or f.endswith('.xml'):
                        important_files.append(os.path.join(root, f))
            
            # Search for flags in extracted files
            flags = []
            for root, dirs, files in os.walk(apk_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            output = f"APK extracted to: {apk_dir}\n"
            output += f"Important files found: {len(important_files)}\n"
            output += '\n'.join(important_files[:20])
            
            return ToolResult(
                tool_name="apk_extract",
                command=f"unzip {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except Exception as e:
            return ToolResult(
                tool_name="apk_extract",
                command=f"unzip {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_apktool(self, target: str, extracted_dir: str) -> ToolResult:
        """Run apktool for APK decompilation."""
        apktool_dir = os.path.join(extracted_dir, "apktool_out")
        
        try:
            result = subprocess.run(
                ['apktool', 'd', '-f', '-o', apktool_dir, target],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Search for flags
            flags = []
            for root, dirs, files in os.walk(apktool_dir):
                for f in files:
                    if f.endswith(('.xml', '.smali', '.txt')):
                        filepath = os.path.join(root, f)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                                content = file.read()
                                flags.extend(self._extract_flags(content))
                        except Exception:
                            pass
            
            return ToolResult(
                tool_name="apktool",
                command=f"apktool d {target}",
                success=result.returncode == 0,
                output=f"Decompiled to: {apktool_dir}\n{result.stdout[:3000]}",
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="apktool",
                command=f"apktool d {target}",
                success=False,
                output="",
                error="apktool not installed. Install with: apt install apktool",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="apktool",
                command=f"apktool d {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_jadx(self, target: str, extracted_dir: str) -> ToolResult:
        """Run jadx for Java decompilation."""
        jadx_dir = os.path.join(extracted_dir, "jadx_out")
        
        try:
            result = subprocess.run(
                ['jadx', '-d', jadx_dir, target],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Search for flags in Java sources
            flags = []
            for root, dirs, files in os.walk(jadx_dir):
                for f in files:
                    if f.endswith('.java'):
                        filepath = os.path.join(root, f)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                                content = file.read()
                                flags.extend(self._extract_flags(content))
                        except Exception:
                            pass
            
            return ToolResult(
                tool_name="jadx",
                command=f"jadx -d {jadx_dir} {target}",
                success=result.returncode == 0,
                output=f"Decompiled Java sources to: {jadx_dir}",
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="jadx",
                command=f"jadx {target}",
                success=False,
                output="",
                error="jadx not installed. Install with: apt install jadx",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="jadx",
                command=f"jadx {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_jar(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract JAR file."""
        import zipfile
        
        jar_dir = os.path.join(extracted_dir, "jar_extracted")
        os.makedirs(jar_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(target, 'r') as zf:
                zf.extractall(jar_dir)
            
            # Search for flags
            flags = []
            class_files = []
            for root, dirs, files in os.walk(jar_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    if f.endswith('.class'):
                        class_files.append(f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            output = f"JAR extracted to: {jar_dir}\n"
            output += f"Class files: {len(class_files)}\n"
            
            return ToolResult(
                tool_name="jar_extract",
                command=f"unzip {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except Exception as e:
            return ToolResult(
                tool_name="jar_extract",
                command=f"unzip {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_file(self, target: str, output_dir: str) -> ToolResult:
        """Run file command."""
        try:
            result = subprocess.run(
                ['file', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return ToolResult(
                tool_name="file",
                command=f"file {target}",
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error="",
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
            
            output = result.stdout
            
            # Save full output
            with open(os.path.join(output_dir, "strings_output.txt"), 'w') as f:
                f.write(output)
            
            # Find interesting strings
            interesting = []
            for line in output.split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['flag', 'pass', 'secret', 'key', 'ctf', 'correct', 'wrong', 'win']):
                    interesting.append(line)
            
            summary = f"Total strings: {len(output.split(chr(10)))}\n"
            summary += f"Interesting ({len(interesting)}):\n"
            summary += '\n'.join(interesting[:50])
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="strings",
                command=f"strings -n 4 {target}",
                success=result.returncode == 0,
                output=summary[:5000],
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
            
            with open(os.path.join(output_dir, "hexdump.txt"), 'w') as f:
                f.write(result.stdout)
            
            lines = result.stdout.split('\n')
            summary = "First 20 lines:\n"
            summary += '\n'.join(lines[:20])
            summary += "\n\n... see hexdump.txt ...\n\n"
            summary += "Last 20 lines:\n"
            summary += '\n'.join(lines[-20:])
            
            return ToolResult(
                tool_name="xxd",
                command=f"xxd {target}",
                success=result.returncode == 0,
                output=summary[:5000],
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
