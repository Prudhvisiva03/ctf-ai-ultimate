"""
CTFHunter - Network Analysis Module
===================================

Analyzes network captures (PCAP/PCAPNG) for
network forensics and CTF challenges.
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


class NetworkModule:
    """
    Network analysis module.
    
    Handles:
    - PCAP/PCAPNG analysis
    - Protocol statistics
    - Stream extraction
    - Credential hunting
    - File extraction from network traffic
    """
    
    def __init__(self):
        """Initialize the network module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check available network tools."""
        tools = ['tshark', 'tcpdump', 'strings', 'file', 'foremost',
                 'ngrep', 'tcpflow', 'scapy']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str,
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a network capture file.
        
        Args:
            target: Path to target file
            output_dir: Directory for output files
            extracted_dir: Directory for extracted files
            mode: Analysis mode
            
        Returns:
            List of ToolResult objects
        """
        results = []
        
        # Basic info
        results.append(self._run_capinfos(target, output_dir))
        
        # Protocol hierarchy
        results.append(self._run_protocol_stats(target, output_dir))
        
        # Find conversations
        results.append(self._run_conversations(target, output_dir))
        
        # Extract HTTP
        results.append(self._extract_http(target, output_dir, extracted_dir))
        
        # Extract DNS
        results.append(self._extract_dns(target, output_dir))
        
        # Look for credentials
        results.append(self._find_credentials(target, output_dir))
        
        # Extract files if deep mode
        if mode in ['auto', 'deep']:
            results.append(self._extract_files(target, extracted_dir))
        
        # Run strings
        results.append(self._run_strings(target, output_dir))
        
        # Search for flags
        results.append(self._search_flags_in_pcap(target, output_dir))
        
        return results
    
    def _run_capinfos(self, target: str, output_dir: str) -> ToolResult:
        """Get capture file information."""
        try:
            result = subprocess.run(
                ['tshark', '-r', target, '-z', 'io,stat,0'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Get basic info
            info_result = subprocess.run(
                ['tshark', '-r', target, '-c', '1', '-T', 'fields', '-e', 'frame.protocols'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = f"Capture Statistics:\n{result.stdout}\n"
            output += f"Protocols: {info_result.stdout}"
            
            with open(os.path.join(output_dir, "pcap_info.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="capinfos",
                command=f"tshark -r {target} -z io,stat,0",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="capinfos",
                command=f"tshark -r {target}",
                success=False,
                output="",
                error="tshark not installed. Install with: apt install tshark",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="capinfos",
                command=f"tshark -r {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_protocol_stats(self, target: str, output_dir: str) -> ToolResult:
        """Get protocol hierarchy statistics."""
        try:
            result = subprocess.run(
                ['tshark', '-r', target, '-q', '-z', 'io,phs'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "protocol_hierarchy.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="protocol_stats",
                command=f"tshark -r {target} -q -z io,phs",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="protocol_stats",
                command="tshark protocol stats",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_conversations(self, target: str, output_dir: str) -> ToolResult:
        """Extract IP conversations."""
        try:
            result = subprocess.run(
                ['tshark', '-r', target, '-q', '-z', 'conv,ip'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = "IP Conversations:\n" + result.stdout
            
            # Also get TCP conversations
            tcp_result = subprocess.run(
                ['tshark', '-r', target, '-q', '-z', 'conv,tcp'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output += "\n\nTCP Conversations:\n" + tcp_result.stdout
            
            with open(os.path.join(output_dir, "conversations.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="conversations",
                command=f"tshark -r {target} -q -z conv,ip",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="conversations",
                command="tshark conversations",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_http(self, target: str, output_dir: str,
                      extracted_dir: str) -> ToolResult:
        """Extract HTTP requests and responses."""
        try:
            # Extract HTTP requests
            requests_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'http.request',
                 '-T', 'fields', '-e', 'http.host', '-e', 'http.request.uri',
                 '-e', 'http.request.method', '-e', 'http.user_agent'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Extract HTTP responses with content
            response_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'http.response',
                 '-T', 'fields', '-e', 'http.response.code', '-e', 'http.content_type'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Extract POST data
            post_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'http.request.method==POST',
                 '-T', 'fields', '-e', 'http.file_data'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = "=== HTTP REQUESTS ===\n"
            output += requests_result.stdout
            output += "\n\n=== HTTP RESPONSES ===\n"
            output += response_result.stdout
            output += "\n\n=== POST DATA ===\n"
            output += post_result.stdout
            
            with open(os.path.join(output_dir, "http_traffic.txt"), 'w') as f:
                f.write(output)
            
            # Export HTTP objects
            http_export_dir = os.path.join(extracted_dir, "http_objects")
            os.makedirs(http_export_dir, exist_ok=True)
            
            subprocess.run(
                ['tshark', '-r', target, '--export-objects', f'http,{http_export_dir}'],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            # Count exported files
            exported = os.listdir(http_export_dir) if os.path.exists(http_export_dir) else []
            output += f"\n\n=== EXPORTED {len(exported)} HTTP OBJECT(S) ===\n"
            output += '\n'.join(exported[:30])
            
            flags = self._extract_flags(output)
            
            # Search exported files for flags
            for f in exported:
                filepath = os.path.join(http_export_dir, f)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        flags.extend(self._extract_flags(content))
                except Exception:
                    pass
            
            return ToolResult(
                tool_name="http_extract",
                command=f"tshark HTTP extraction",
                success=True,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="http_extract",
                command="tshark HTTP extraction",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_dns(self, target: str, output_dir: str) -> ToolResult:
        """Extract DNS queries and responses."""
        try:
            result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'dns',
                 '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.a',
                 '-e', 'dns.txt', '-e', 'dns.mx.mail_exchange'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = "DNS Queries and Responses:\n"
            output += result.stdout
            
            # Look for interesting DNS patterns (data exfiltration, etc.)
            interesting = []
            for line in result.stdout.split('\n'):
                if line and len(line) > 50:  # Long DNS names might be data exfil
                    interesting.append(line)
            
            if interesting:
                output += f"\n\nInteresting (long) DNS names ({len(interesting)}):\n"
                output += '\n'.join(interesting[:20])
            
            with open(os.path.join(output_dir, "dns_traffic.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="dns_extract",
                command=f"tshark DNS extraction",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="dns_extract",
                command="tshark DNS extraction",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _find_credentials(self, target: str, output_dir: str) -> ToolResult:
        """Search for credentials in traffic."""
        try:
            credentials = []
            
            # FTP credentials
            ftp_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'ftp.request.command==USER || ftp.request.command==PASS',
                 '-T', 'fields', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'],
                capture_output=True,
                text=True,
                timeout=60
            )
            if ftp_result.stdout.strip():
                credentials.append("=== FTP ===\n" + ftp_result.stdout)
            
            # HTTP Basic Auth
            auth_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'http.authorization',
                 '-T', 'fields', '-e', 'http.authorization'],
                capture_output=True,
                text=True,
                timeout=60
            )
            if auth_result.stdout.strip():
                credentials.append("=== HTTP Authorization ===\n" + auth_result.stdout)
            
            # Telnet
            telnet_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'telnet',
                 '-T', 'fields', '-e', 'telnet.data'],
                capture_output=True,
                text=True,
                timeout=60
            )
            if telnet_result.stdout.strip():
                credentials.append("=== Telnet Data ===\n" + telnet_result.stdout)
            
            # SMTP credentials
            smtp_result = subprocess.run(
                ['tshark', '-r', target, '-Y', 'smtp.req.command==AUTH',
                 '-T', 'fields', '-e', 'smtp.req.parameter'],
                capture_output=True,
                text=True,
                timeout=60
            )
            if smtp_result.stdout.strip():
                credentials.append("=== SMTP Auth ===\n" + smtp_result.stdout)
            
            output = '\n\n'.join(credentials) if credentials else "No clear-text credentials found"
            
            with open(os.path.join(output_dir, "credentials.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="credential_hunt",
                command="tshark credential extraction",
                success=len(credentials) > 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="credential_hunt",
                command="credential hunt",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _extract_files(self, target: str, extracted_dir: str) -> ToolResult:
        """Extract files from PCAP using various methods."""
        files_dir = os.path.join(extracted_dir, "pcap_files")
        os.makedirs(files_dir, exist_ok=True)
        
        extracted_count = 0
        
        try:
            # Export HTTP objects
            http_dir = os.path.join(files_dir, "http")
            os.makedirs(http_dir, exist_ok=True)
            subprocess.run(
                ['tshark', '-r', target, '--export-objects', f'http,{http_dir}'],
                capture_output=True,
                timeout=180
            )
            extracted_count += len(os.listdir(http_dir)) if os.path.exists(http_dir) else 0
            
            # Export SMB objects
            smb_dir = os.path.join(files_dir, "smb")
            os.makedirs(smb_dir, exist_ok=True)
            subprocess.run(
                ['tshark', '-r', target, '--export-objects', f'smb,{smb_dir}'],
                capture_output=True,
                timeout=180
            )
            extracted_count += len(os.listdir(smb_dir)) if os.path.exists(smb_dir) else 0
            
            # Export TFTP objects
            tftp_dir = os.path.join(files_dir, "tftp")
            os.makedirs(tftp_dir, exist_ok=True)
            subprocess.run(
                ['tshark', '-r', target, '--export-objects', f'tftp,{tftp_dir}'],
                capture_output=True,
                timeout=180
            )
            extracted_count += len(os.listdir(tftp_dir)) if os.path.exists(tftp_dir) else 0
            
            # Export IMF (email) objects
            imf_dir = os.path.join(files_dir, "email")
            os.makedirs(imf_dir, exist_ok=True)
            subprocess.run(
                ['tshark', '-r', target, '--export-objects', f'imf,{imf_dir}'],
                capture_output=True,
                timeout=180
            )
            extracted_count += len(os.listdir(imf_dir)) if os.path.exists(imf_dir) else 0
            
            # Search extracted files for flags
            flags = []
            for root, dirs, files in os.walk(files_dir):
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            flags.extend(self._extract_flags(content))
                    except Exception:
                        pass
            
            output = f"Extracted {extracted_count} file(s) to {files_dir}"
            
            return ToolResult(
                tool_name="file_extract",
                command="tshark --export-objects",
                success=extracted_count > 0,
                output=output,
                error="",
                execution_time=0,
                flags_found=list(set(flags))
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="file_extract",
                command="file extraction",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_strings(self, target: str, output_dir: str) -> ToolResult:
        """Run strings on PCAP."""
        try:
            result = subprocess.run(
                ['strings', '-n', '6', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "pcap_strings.txt"), 'w') as f:
                f.write(output)
            
            # Find interesting strings
            interesting = []
            for line in output.split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['flag', 'pass', 'secret', 'key', 'user', 'admin', 'login']):
                    interesting.append(line)
            
            summary = f"Total strings: {len(output.split(chr(10)))}\n"
            summary += f"Interesting ({len(interesting)}):\n"
            summary += '\n'.join(interesting[:50])
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="strings",
                command=f"strings -n 6 {target}",
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
    
    def _search_flags_in_pcap(self, target: str, output_dir: str) -> ToolResult:
        """Search for flag patterns directly in PCAP."""
        try:
            # Use tshark to search for common flag patterns in packet data
            patterns = ['flag{', 'FLAG{', 'ctf{', 'CTF{', 'HTB{', 'htb{', 'picoCTF{', 'THM{']
            
            all_matches = []
            
            for pattern in patterns:
                result = subprocess.run(
                    ['tshark', '-r', target, '-Y', f'frame contains "{pattern}"',
                     '-T', 'fields', '-e', 'data.text'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.stdout.strip():
                    all_matches.append(f"Pattern '{pattern}':\n{result.stdout}")
            
            output = '\n\n'.join(all_matches) if all_matches else "No flag patterns found in packets"
            
            with open(os.path.join(output_dir, "flag_search.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="flag_search",
                command="tshark flag pattern search",
                success=len(flags) > 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return self._tshark_not_found()
        except Exception as e:
            return ToolResult(
                tool_name="flag_search",
                command="flag search",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _tshark_not_found(self) -> ToolResult:
        """Return tshark not found error."""
        return ToolResult(
            tool_name="tshark",
            command="tshark",
            success=False,
            output="",
            error="tshark not installed. Install with: apt install tshark",
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
