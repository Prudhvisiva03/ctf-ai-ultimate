"""
CTFHunter - Steganography Module
================================

Analyzes image and audio files for hidden data using
steganography detection tools.
"""

import os
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


class SteganographyModule:
    """
    Steganography analysis module.
    
    Analyzes images and audio files for hidden data using:
    - zsteg (PNG/BMP LSB analysis)
    - steghide (JPEG/WAV/AU steganography)
    - stegseek (steghide password cracking)
    - binwalk (embedded file detection)
    - foremost (file carving)
    - strings (printable string extraction)
    - exiftool (metadata extraction)
    """
    
    # Common steghide passwords to try
    COMMON_PASSWORDS = [
        "", "password", "123456", "admin", "secret", "flag",
        "ctf", "stego", "hidden", "pass", "test", "1234",
        "steganography", "letmein", "welcome", "qwerty"
    ]
    
    def __init__(self):
        """Initialize the steganography module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check which steganography tools are available."""
        tools = ['zsteg', 'steghide', 'stegseek', 'binwalk', 'foremost', 
                 'exiftool', 'strings', 'identify', 'pngcheck']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str, 
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a file for steganography.
        
        Args:
            target: Path to target file
            output_dir: Directory for output files
            extracted_dir: Directory for extracted files
            mode: Analysis mode ('auto', 'quick', 'deep')
            
        Returns:
            List of ToolResult objects
        """
        results = []
        extension = os.path.splitext(target)[1].lower()
        
        # Determine file type and run appropriate tools
        if extension in ['.png', '.bmp']:
            results.extend(self._analyze_png(target, output_dir, extracted_dir, mode))
        elif extension in ['.jpg', '.jpeg']:
            results.extend(self._analyze_jpeg(target, output_dir, extracted_dir, mode))
        elif extension in ['.gif']:
            results.extend(self._analyze_gif(target, output_dir, extracted_dir, mode))
        elif extension in ['.wav', '.mp3', '.flac', '.ogg', '.au']:
            results.extend(self._analyze_audio(target, output_dir, extracted_dir, mode))
        else:
            # Generic image/audio analysis
            results.extend(self._analyze_generic(target, output_dir, extracted_dir, mode))
        
        # Always run binwalk for embedded files
        results.append(self._run_binwalk(target, output_dir, extracted_dir))
        
        return results
    
    def _analyze_png(self, target: str, output_dir: str, 
                     extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze PNG/BMP images."""
        results = []
        
        # Run zsteg (LSB analysis)
        if self.available_tools.get('zsteg'):
            results.append(self._run_zsteg(target, output_dir))
        
        # Run pngcheck
        if self.available_tools.get('pngcheck'):
            results.append(self._run_pngcheck(target, output_dir))
        
        # Run exiftool
        if self.available_tools.get('exiftool'):
            results.append(self._run_exiftool(target, output_dir))
        
        # Run foremost for file carving
        if mode in ['auto', 'deep'] and self.available_tools.get('foremost'):
            results.append(self._run_foremost(target, extracted_dir))
        
        return results
    
    def _analyze_jpeg(self, target: str, output_dir: str,
                      extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze JPEG images."""
        results = []
        
        # Run exiftool
        if self.available_tools.get('exiftool'):
            results.append(self._run_exiftool(target, output_dir))
        
        # Run steghide extract (try common passwords)
        if self.available_tools.get('steghide'):
            results.append(self._run_steghide(target, output_dir, extracted_dir))
        
        # Run stegseek (steghide password cracker)
        if mode in ['auto', 'deep'] and self.available_tools.get('stegseek'):
            results.append(self._run_stegseek(target, output_dir, extracted_dir))
        
        # Run foremost
        if mode in ['auto', 'deep'] and self.available_tools.get('foremost'):
            results.append(self._run_foremost(target, extracted_dir))
        
        return results
    
    def _analyze_gif(self, target: str, output_dir: str,
                     extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze GIF images."""
        results = []
        
        # Run exiftool
        if self.available_tools.get('exiftool'):
            results.append(self._run_exiftool(target, output_dir))
        
        # Run identify (ImageMagick) for frame info
        if self.available_tools.get('identify'):
            results.append(self._run_identify(target, output_dir))
        
        # Extract frames using convert if available
        results.append(self._extract_gif_frames(target, extracted_dir))
        
        return results
    
    def _analyze_audio(self, target: str, output_dir: str,
                       extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze audio files."""
        results = []
        
        # Run exiftool
        if self.available_tools.get('exiftool'):
            results.append(self._run_exiftool(target, output_dir))
        
        # Run steghide for WAV/AU files
        extension = os.path.splitext(target)[1].lower()
        if extension in ['.wav', '.au'] and self.available_tools.get('steghide'):
            results.append(self._run_steghide(target, output_dir, extracted_dir))
        
        # Suggest manual spectrogram analysis
        results.append(ToolResult(
            tool_name="spectrogram_hint",
            command="manual",
            success=True,
            output="TIP: Try opening the audio file in Audacity or Sonic Visualiser\n"
                   "and check the spectrogram view for hidden messages.",
            error="",
            execution_time=0,
            flags_found=[]
        ))
        
        return results
    
    def _analyze_generic(self, target: str, output_dir: str,
                         extracted_dir: str, mode: str) -> List[ToolResult]:
        """Generic steganography analysis."""
        results = []
        
        if self.available_tools.get('exiftool'):
            results.append(self._run_exiftool(target, output_dir))
        
        if self.available_tools.get('foremost'):
            results.append(self._run_foremost(target, extracted_dir))
        
        return results
    
    def _run_zsteg(self, target: str, output_dir: str) -> ToolResult:
        """Run zsteg for LSB analysis on PNG/BMP."""
        try:
            result = subprocess.run(
                ['zsteg', '-a', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Save output
            output_file = os.path.join(output_dir, "zsteg_output.txt")
            with open(output_file, 'w') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n\nSTDERR:\n{result.stderr}")
            
            # Search for flags in output
            flags = self._extract_flags(result.stdout)
            
            return ToolResult(
                tool_name="zsteg",
                command=f"zsteg -a {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("zsteg", f"zsteg -a {target}")
        except FileNotFoundError:
            return self._not_found_result("zsteg")
        except Exception as e:
            return self._error_result("zsteg", str(e))
    
    def _run_steghide(self, target: str, output_dir: str, 
                      extracted_dir: str) -> ToolResult:
        """Run steghide to extract hidden data."""
        output_file = os.path.join(extracted_dir, "steghide_extracted")
        all_outputs = []
        extracted = False
        
        for password in self.COMMON_PASSWORDS:
            try:
                result = subprocess.run(
                    ['steghide', 'extract', '-sf', target, '-xf', output_file, '-p', password, '-f'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    all_outputs.append(f"SUCCESS with password: '{password}'")
                    all_outputs.append(result.stdout)
                    extracted = True
                    break
                    
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
        
        if not extracted:
            # Just get info
            try:
                result = subprocess.run(
                    ['steghide', 'info', target, '-p', ''],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                all_outputs.append("Could not extract with common passwords.")
                all_outputs.append("Steghide info:")
                all_outputs.append(result.stdout)
            except Exception:
                pass
        
        output = '\n'.join(all_outputs)
        
        # Save output
        with open(os.path.join(output_dir, "steghide_output.txt"), 'w') as f:
            f.write(output)
        
        flags = self._extract_flags(output)
        
        return ToolResult(
            tool_name="steghide",
            command=f"steghide extract -sf {target}",
            success=extracted,
            output=output[:5000],
            error="" if extracted else "Could not extract with common passwords",
            execution_time=0,
            flags_found=flags
        )
    
    def _run_stegseek(self, target: str, output_dir: str,
                      extracted_dir: str) -> ToolResult:
        """Run stegseek to crack steghide password."""
        output_file = os.path.join(extracted_dir, "stegseek_extracted")
        
        try:
            # Try with default rockyou wordlist
            result = subprocess.run(
                ['stegseek', target, '-xf', output_file],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout + "\n" + result.stderr
            
            # Save output
            with open(os.path.join(output_dir, "stegseek_output.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            # Also check extracted file for flags
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r', errors='ignore') as f:
                        content = f.read()
                    flags.extend(self._extract_flags(content))
                except Exception:
                    pass
            
            return ToolResult(
                tool_name="stegseek",
                command=f"stegseek {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("stegseek", f"stegseek {target}")
        except FileNotFoundError:
            return self._not_found_result("stegseek")
        except Exception as e:
            return self._error_result("stegseek", str(e))
    
    def _run_binwalk(self, target: str, output_dir: str,
                     extracted_dir: str) -> ToolResult:
        """Run binwalk to find and extract embedded files."""
        try:
            # First, analyze
            result = subprocess.run(
                ['binwalk', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            analysis_output = result.stdout
            
            # Then extract
            extract_result = subprocess.run(
                ['binwalk', '-e', '-C', extracted_dir, target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = f"=== ANALYSIS ===\n{analysis_output}\n\n=== EXTRACTION ===\n{extract_result.stdout}"
            
            # Save output
            with open(os.path.join(output_dir, "binwalk_output.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="binwalk",
                command=f"binwalk -e {target}",
                success=result.returncode == 0,
                output=output[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("binwalk", f"binwalk -e {target}")
        except FileNotFoundError:
            return self._not_found_result("binwalk")
        except Exception as e:
            return self._error_result("binwalk", str(e))
    
    def _run_foremost(self, target: str, extracted_dir: str) -> ToolResult:
        """Run foremost for file carving."""
        foremost_dir = os.path.join(extracted_dir, "foremost")
        os.makedirs(foremost_dir, exist_ok=True)
        
        try:
            result = subprocess.run(
                ['foremost', '-i', target, '-o', foremost_dir, '-T'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout
            
            # Read audit file if exists
            audit_files = []
            for root, dirs, files in os.walk(foremost_dir):
                for f in files:
                    if f == 'audit.txt':
                        audit_path = os.path.join(root, f)
                        try:
                            with open(audit_path, 'r') as af:
                                output += f"\n\nAudit:\n{af.read()}"
                        except Exception:
                            pass
                    else:
                        audit_files.append(os.path.join(root, f))
            
            if audit_files:
                output += f"\n\nExtracted {len(audit_files)} file(s)"
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="foremost",
                command=f"foremost -i {target}",
                success=result.returncode == 0 or len(audit_files) > 0,
                output=output[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("foremost", f"foremost -i {target}")
        except FileNotFoundError:
            return self._not_found_result("foremost")
        except Exception as e:
            return self._error_result("foremost", str(e))
    
    def _run_exiftool(self, target: str, output_dir: str) -> ToolResult:
        """Run exiftool for metadata extraction."""
        try:
            result = subprocess.run(
                ['exiftool', '-a', '-u', '-g1', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Save output
            with open(os.path.join(output_dir, "exiftool_output.txt"), 'w') as f:
                f.write(result.stdout)
            
            flags = self._extract_flags(result.stdout)
            
            return ToolResult(
                tool_name="exiftool",
                command=f"exiftool -a -u -g1 {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("exiftool", f"exiftool {target}")
        except FileNotFoundError:
            return self._not_found_result("exiftool")
        except Exception as e:
            return self._error_result("exiftool", str(e))
    
    def _run_pngcheck(self, target: str, output_dir: str) -> ToolResult:
        """Run pngcheck for PNG validation."""
        try:
            result = subprocess.run(
                ['pngcheck', '-cvt', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            
            with open(os.path.join(output_dir, "pngcheck_output.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="pngcheck",
                command=f"pngcheck -cvt {target}",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("pngcheck", f"pngcheck {target}")
        except FileNotFoundError:
            return self._not_found_result("pngcheck")
        except Exception as e:
            return self._error_result("pngcheck", str(e))
    
    def _run_identify(self, target: str, output_dir: str) -> ToolResult:
        """Run ImageMagick identify for image info."""
        try:
            result = subprocess.run(
                ['identify', '-verbose', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            with open(os.path.join(output_dir, "identify_output.txt"), 'w') as f:
                f.write(result.stdout)
            
            flags = self._extract_flags(result.stdout)
            
            return ToolResult(
                tool_name="identify",
                command=f"identify -verbose {target}",
                success=result.returncode == 0,
                output=result.stdout[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return self._timeout_result("identify", f"identify {target}")
        except FileNotFoundError:
            return self._not_found_result("identify")
        except Exception as e:
            return self._error_result("identify", str(e))
    
    def _extract_gif_frames(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract individual frames from GIF."""
        frames_dir = os.path.join(extracted_dir, "gif_frames")
        os.makedirs(frames_dir, exist_ok=True)
        
        try:
            result = subprocess.run(
                ['convert', target, os.path.join(frames_dir, "frame_%03d.png")],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Count extracted frames
            frames = [f for f in os.listdir(frames_dir) if f.endswith('.png')]
            output = f"Extracted {len(frames)} frame(s) to {frames_dir}"
            
            return ToolResult(
                tool_name="gif_extract",
                command=f"convert {target} frame_%03d.png",
                success=len(frames) > 0,
                output=output,
                error=result.stderr if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return self._not_found_result("convert (ImageMagick)")
        except Exception as e:
            return self._error_result("gif_extract", str(e))
    
    def _extract_flags(self, text: str) -> List[str]:
        """Extract flags from text using regex patterns."""
        import re
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
    
    def _timeout_result(self, tool_name: str, command: str) -> ToolResult:
        """Create a timeout result."""
        return ToolResult(
            tool_name=tool_name,
            command=command,
            success=False,
            output="",
            error="Command timed out",
            execution_time=0,
            flags_found=[]
        )
    
    def _not_found_result(self, tool_name: str) -> ToolResult:
        """Create a tool not found result."""
        return ToolResult(
            tool_name=tool_name,
            command="",
            success=False,
            output="",
            error=f"Tool '{tool_name}' not found. Install it with: apt install {tool_name}",
            execution_time=0,
            flags_found=[]
        )
    
    def _error_result(self, tool_name: str, error: str) -> ToolResult:
        """Create an error result."""
        return ToolResult(
            tool_name=tool_name,
            command="",
            success=False,
            output="",
            error=error,
            execution_time=0,
            flags_found=[]
        )
