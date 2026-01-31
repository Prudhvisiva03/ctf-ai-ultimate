#!/usr/bin/env python3
"""
Deep Network Analyzer - In-Depth PCAP/Network Analysis
Comprehensive packet inspection and data extraction
"""

import os
import re
import subprocess
import tempfile
import base64
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class DeepNetworkAnalyzer:
    """
    Comprehensive network analysis - examines every packet layer.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.flags_found = []
        self.credentials_found = []
        self.files_extracted = []
        
        self.flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'THM\{[^}]+\}'
        ]
    
    def analyze(self, filepath: str, output_dir: str = None) -> Dict:
        """Comprehensive PCAP analysis"""
        print(f"\n[DEEP NETWORK] Analyzing: {filepath}")
        print("=" * 60)
        
        results = {
            'file': filepath,
            'summary': {},
            'protocols': {},
            'conversations': [],
            'http_requests': [],
            'dns_queries': [],
            'ftp_data': [],
            'smtp_data': [],
            'credentials': [],
            'extracted_files': [],
            'suspicious': [],
            'raw_streams': [],
            'flags_found': []
        }
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return results
        
        if output_dir is None:
            output_dir = os.path.dirname(filepath)
        
        # 1. Basic PCAP info
        print("[*] Phase 1: PCAP summary...")
        results['summary'] = self._get_pcap_summary(filepath)
        
        # 2. Protocol hierarchy
        print("[*] Phase 2: Protocol analysis...")
        results['protocols'] = self._analyze_protocols(filepath)
        
        # 3. Conversation analysis
        print("[*] Phase 3: Conversation analysis...")
        results['conversations'] = self._analyze_conversations(filepath)
        
        # 4. HTTP analysis
        print("[*] Phase 4: HTTP traffic analysis...")
        results['http_requests'] = self._analyze_http(filepath)
        
        # 5. DNS analysis
        print("[*] Phase 5: DNS queries analysis...")
        results['dns_queries'] = self._analyze_dns(filepath)
        
        # 6. FTP analysis
        print("[*] Phase 6: FTP traffic analysis...")
        results['ftp_data'] = self._analyze_ftp(filepath)
        
        # 7. SMTP/Email analysis
        print("[*] Phase 7: Email traffic analysis...")
        results['smtp_data'] = self._analyze_smtp(filepath)
        
        # 8. Credential extraction
        print("[*] Phase 8: Credential hunting...")
        results['credentials'] = self._extract_credentials(filepath)
        
        # 9. File extraction
        print("[*] Phase 9: File extraction...")
        results['extracted_files'] = self._extract_files(filepath, output_dir)
        
        # 10. Raw stream analysis
        print("[*] Phase 10: TCP stream analysis...")
        results['raw_streams'] = self._analyze_tcp_streams(filepath)
        
        # 11. Suspicious activity detection
        print("[*] Phase 11: Suspicious activity detection...")
        results['suspicious'] = self._detect_suspicious(filepath)
        
        # 12. String search
        print("[*] Phase 12: Deep string search...")
        self._deep_string_search(filepath)
        
        results['credentials'] = self.credentials_found
        results['flags_found'] = self.flags_found
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] NETWORK ANALYSIS SUMMARY")
        print("=" * 60)
        
        if self.flags_found:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.flags_found)}")
            for flag in self.flags_found:
                print(f"    {flag}")
        
        if self.credentials_found:
            print(f"\n[CREDS] CREDENTIALS FOUND: {len(self.credentials_found)}")
            for cred in self.credentials_found[:5]:
                print(f"    {cred}")
        
        if results['extracted_files']:
            print(f"\n[FILES] EXTRACTED: {len(results['extracted_files'])}")
            for f in results['extracted_files'][:5]:
                print(f"    {f}")
        
        return results
    
    # ==================== PCAP SUMMARY ====================
    
    def _get_pcap_summary(self, filepath: str) -> Dict:
        """Get PCAP file summary"""
        summary = {}
        
        # Using capinfos
        try:
            result = subprocess.run(
                ['capinfos', filepath],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ':' in line:
                        key, value = line.split(':', 1)
                        summary[key.strip()] = value.strip()
                        
                print(f"    Packets: {summary.get('Number of packets', 'Unknown')}")
                print(f"    Duration: {summary.get('Capture duration', 'Unknown')}")
        except FileNotFoundError:
            pass
        
        # Using tshark for packet count
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-T', 'fields', '-e', 'frame.number'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                summary['packet_count'] = len(result.stdout.strip().splitlines())
        except FileNotFoundError:
            pass
        
        return summary
    
    # ==================== PROTOCOL ANALYSIS ====================
    
    def _analyze_protocols(self, filepath: str) -> Dict:
        """Analyze protocol hierarchy"""
        protocols = {}
        
        # Using tshark
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', 'io,phs'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                protocols['hierarchy'] = result.stdout
                
                # Count protocols
                for line in result.stdout.splitlines():
                    if 'frames' in line.lower():
                        parts = line.strip().split()
                        if parts:
                            protocols[parts[0]] = line.strip()
        except FileNotFoundError:
            pass
        
        return protocols
    
    # ==================== CONVERSATION ANALYSIS ====================
    
    def _analyze_conversations(self, filepath: str) -> List[Dict]:
        """Analyze network conversations"""
        conversations = []
        
        # TCP conversations
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', 'conv,tcp'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if '<->' in line:
                        conversations.append({
                            'protocol': 'TCP',
                            'details': line.strip()
                        })
        except FileNotFoundError:
            pass
        
        # UDP conversations
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', 'conv,udp'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if '<->' in line:
                        conversations.append({
                            'protocol': 'UDP',
                            'details': line.strip()
                        })
        except FileNotFoundError:
            pass
        
        print(f"    Conversations: {len(conversations)}")
        
        return conversations
    
    # ==================== HTTP ANALYSIS ====================
    
    def _analyze_http(self, filepath: str) -> List[Dict]:
        """Deep HTTP analysis"""
        http_data = []
        
        # Extract HTTP requests
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'http.request', '-T', 'fields',
                 '-e', 'ip.src', '-e', 'ip.dst', '-e', 'http.request.method',
                 '-e', 'http.host', '-e', 'http.request.uri', '-e', 'http.user_agent'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 5:
                            request = {
                                'src': parts[0],
                                'dst': parts[1],
                                'method': parts[2],
                                'host': parts[3],
                                'uri': parts[4],
                                'user_agent': parts[5] if len(parts) > 5 else ''
                            }
                            http_data.append(request)
                            
                            # Search for flags in URI
                            self._search_flags(parts[4])
                            
                            print(f"    [HTTP] {request['method']} {request['host']}{request['uri'][:50]}")
        except FileNotFoundError:
            pass
        
        # Extract HTTP responses
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'http.response', '-T', 'fields',
                 '-e', 'ip.src', '-e', 'http.response.code', '-e', 'http.content_type'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            http_data.append({
                                'type': 'response',
                                'src': parts[0],
                                'status': parts[1],
                                'content_type': parts[2] if len(parts) > 2 else ''
                            })
        except FileNotFoundError:
            pass
        
        # Extract cookies
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'http.cookie', '-T', 'fields',
                 '-e', 'http.cookie'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for cookie in result.stdout.strip().splitlines():
                    if cookie:
                        http_data.append({'type': 'cookie', 'value': cookie})
                        self._search_flags(cookie)
        except FileNotFoundError:
            pass
        
        # Extract Authorization headers
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'http.authorization', '-T', 'fields',
                 '-e', 'http.authorization'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for auth in result.stdout.strip().splitlines():
                    if auth:
                        http_data.append({'type': 'auth', 'value': auth})
                        
                        # Decode Basic auth
                        if auth.startswith('Basic '):
                            try:
                                decoded = base64.b64decode(auth[6:]).decode()
                                self.credentials_found.append(f"HTTP Basic: {decoded}")
                                print(f"    [CRED] HTTP Basic Auth: {decoded}")
                            except:
                                pass
        except FileNotFoundError:
            pass
        
        return http_data
    
    # ==================== DNS ANALYSIS ====================
    
    def _analyze_dns(self, filepath: str) -> List[Dict]:
        """Deep DNS analysis"""
        dns_data = []
        
        # Extract DNS queries
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'dns.qry.name', '-T', 'fields',
                 '-e', 'ip.src', '-e', 'dns.qry.name', '-e', 'dns.qry.type'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            query = {
                                'src': parts[0],
                                'name': parts[1],
                                'type': parts[2] if len(parts) > 2 else ''
                            }
                            dns_data.append(query)
                            
                            # Check for DNS tunneling (long subdomains)
                            if len(parts[1]) > 50:
                                print(f"    [DNS] Possible tunneling: {parts[1][:60]}...")
                                
                                # Try to decode base64/hex subdomain
                                subdomain = parts[1].split('.')[0]
                                self._try_decode_dns(subdomain)
                            
                            self._search_flags(parts[1])
        except FileNotFoundError:
            pass
        
        # DNS TXT records (often used for data exfiltration)
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'dns.txt', '-T', 'fields',
                 '-e', 'dns.txt'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for txt in result.stdout.strip().splitlines():
                    if txt:
                        dns_data.append({'type': 'TXT', 'value': txt})
                        print(f"    [DNS TXT] {txt[:60]}")
                        self._search_flags(txt)
                        
                        # Try to decode
                        self._try_decode_dns(txt)
        except FileNotFoundError:
            pass
        
        print(f"    DNS queries: {len(dns_data)}")
        
        return dns_data
    
    def _try_decode_dns(self, data: str):
        """Try to decode DNS tunneling data"""
        # Base64
        try:
            decoded = base64.b64decode(data.replace('-', '+').replace('_', '/')).decode()
            if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                print(f"    [DNS Decoded] Base64: {decoded[:60]}")
                self._search_flags(decoded)
        except:
            pass
        
        # Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
                decoded = bytes.fromhex(data).decode()
                if sum(c.isprintable() for c in decoded) > len(decoded) * 0.8:
                    print(f"    [DNS Decoded] Hex: {decoded[:60]}")
                    self._search_flags(decoded)
        except:
            pass
    
    # ==================== FTP ANALYSIS ====================
    
    def _analyze_ftp(self, filepath: str) -> List[Dict]:
        """Deep FTP analysis"""
        ftp_data = []
        
        # FTP commands
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'ftp.request.command', '-T', 'fields',
                 '-e', 'ip.src', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            cmd = {
                                'src': parts[0],
                                'command': parts[1],
                                'arg': parts[2] if len(parts) > 2 else ''
                            }
                            ftp_data.append(cmd)
                            
                            # Look for credentials
                            if cmd['command'] == 'USER':
                                print(f"    [FTP] Username: {cmd['arg']}")
                            elif cmd['command'] == 'PASS':
                                self.credentials_found.append(f"FTP Password: {cmd['arg']}")
                                print(f"    [FTP] Password: {cmd['arg']}")
                            
                            self._search_flags(cmd['arg'])
        except FileNotFoundError:
            pass
        
        # FTP responses
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'ftp.response', '-T', 'fields',
                 '-e', 'ftp.response.code', '-e', 'ftp.response.arg'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            ftp_data.append({
                                'type': 'response',
                                'code': parts[0],
                                'message': parts[1]
                            })
                            self._search_flags(parts[1])
        except FileNotFoundError:
            pass
        
        return ftp_data
    
    # ==================== SMTP ANALYSIS ====================
    
    def _analyze_smtp(self, filepath: str) -> List[Dict]:
        """Deep SMTP/Email analysis"""
        smtp_data = []
        
        # SMTP commands
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'smtp.req.command', '-T', 'fields',
                 '-e', 'smtp.req.command', '-e', 'smtp.req.parameter'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 1:
                            cmd = parts[0]
                            param = parts[1] if len(parts) > 1 else ''
                            smtp_data.append({'command': cmd, 'param': param})
                            
                            if cmd in ['MAIL', 'RCPT']:
                                print(f"    [SMTP] {cmd}: {param}")
                            elif cmd == 'AUTH':
                                print(f"    [SMTP AUTH] {param}")
                            
                            self._search_flags(param)
        except FileNotFoundError:
            pass
        
        # Email content
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'smtp.data.fragment', '-T', 'fields',
                 '-e', 'smtp.data.fragment'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                email_content = result.stdout.strip()
                if email_content:
                    smtp_data.append({'type': 'content', 'data': email_content[:1000]})
                    self._search_flags(email_content)
        except FileNotFoundError:
            pass
        
        # IMF (Internet Message Format)
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'imf', '-T', 'fields',
                 '-e', 'imf.subject', '-e', 'imf.from', '-e', 'imf.to'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if parts[0]:
                            print(f"    [EMAIL Subject] {parts[0]}")
                            self._search_flags(parts[0])
                        smtp_data.append({
                            'subject': parts[0] if parts else '',
                            'from': parts[1] if len(parts) > 1 else '',
                            'to': parts[2] if len(parts) > 2 else ''
                        })
        except FileNotFoundError:
            pass
        
        return smtp_data
    
    # ==================== CREDENTIAL EXTRACTION ====================
    
    def _extract_credentials(self, filepath: str) -> List[str]:
        """Extract credentials from various protocols"""
        
        # Telnet
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'telnet.data', '-T', 'fields',
                 '-e', 'telnet.data'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                telnet_data = result.stdout.strip()
                if telnet_data:
                    print(f"    [TELNET] Data found")
                    self._search_flags(telnet_data)
        except FileNotFoundError:
            pass
        
        # IMAP
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'imap.request', '-T', 'fields',
                 '-e', 'imap.request'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if 'LOGIN' in line.upper():
                        print(f"    [IMAP] Login attempt: {line}")
                        self.credentials_found.append(f"IMAP: {line}")
                    self._search_flags(line)
        except FileNotFoundError:
            pass
        
        # POP3
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'pop.request', '-T', 'fields',
                 '-e', 'pop.request.command', '-e', 'pop.request.parameter'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line:
                        parts = line.split('\t')
                        if parts[0] in ['USER', 'PASS']:
                            self.credentials_found.append(f"POP3 {parts[0]}: {parts[1] if len(parts) > 1 else ''}")
                            print(f"    [POP3] {parts[0]}: {parts[1] if len(parts) > 1 else ''}")
        except FileNotFoundError:
            pass
        
        return self.credentials_found
    
    # ==================== FILE EXTRACTION ====================
    
    def _extract_files(self, filepath: str, output_dir: str) -> List[str]:
        """Extract files from PCAP"""
        extracted = []
        
        extract_dir = os.path.join(output_dir, 'pcap_extracted')
        os.makedirs(extract_dir, exist_ok=True)
        
        # Extract HTTP objects
        try:
            http_dir = os.path.join(extract_dir, 'http')
            os.makedirs(http_dir, exist_ok=True)
            
            result = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'http,{http_dir}'],
                capture_output=True, text=True
            )
            
            # List extracted files
            if os.path.exists(http_dir):
                for f in os.listdir(http_dir):
                    full_path = os.path.join(http_dir, f)
                    extracted.append(full_path)
                    print(f"    [HTTP Export] {f}")
                    
                    # Search file content
                    try:
                        with open(full_path, 'rb') as file:
                            content = file.read()
                            self._search_flags(content.decode('latin-1', errors='ignore'))
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        # Extract IMF (email) objects
        try:
            imf_dir = os.path.join(extract_dir, 'imf')
            os.makedirs(imf_dir, exist_ok=True)
            
            result = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'imf,{imf_dir}'],
                capture_output=True, text=True
            )
            
            if os.path.exists(imf_dir):
                for f in os.listdir(imf_dir):
                    full_path = os.path.join(imf_dir, f)
                    extracted.append(full_path)
                    print(f"    [IMF Export] {f}")
        except FileNotFoundError:
            pass
        
        # Extract SMB objects
        try:
            smb_dir = os.path.join(extract_dir, 'smb')
            os.makedirs(smb_dir, exist_ok=True)
            
            result = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'smb,{smb_dir}'],
                capture_output=True, text=True
            )
            
            if os.path.exists(smb_dir):
                for f in os.listdir(smb_dir):
                    full_path = os.path.join(smb_dir, f)
                    extracted.append(full_path)
                    print(f"    [SMB Export] {f}")
        except FileNotFoundError:
            pass
        
        # Extract FTP-DATA
        try:
            ftp_dir = os.path.join(extract_dir, 'ftp')
            os.makedirs(ftp_dir, exist_ok=True)
            
            result = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'ftp-data,{ftp_dir}'],
                capture_output=True, text=True
            )
            
            if os.path.exists(ftp_dir):
                for f in os.listdir(ftp_dir):
                    full_path = os.path.join(ftp_dir, f)
                    extracted.append(full_path)
                    print(f"    [FTP Export] {f}")
        except FileNotFoundError:
            pass
        
        # Extract TFTP
        try:
            tftp_dir = os.path.join(extract_dir, 'tftp')
            os.makedirs(tftp_dir, exist_ok=True)
            
            result = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'tftp,{tftp_dir}'],
                capture_output=True, text=True
            )
            
            if os.path.exists(tftp_dir):
                for f in os.listdir(tftp_dir):
                    full_path = os.path.join(tftp_dir, f)
                    extracted.append(full_path)
                    print(f"    [TFTP Export] {f}")
        except FileNotFoundError:
            pass
        
        self.files_extracted = extracted
        return extracted
    
    # ==================== TCP STREAM ANALYSIS ====================
    
    def _analyze_tcp_streams(self, filepath: str) -> List[Dict]:
        """Analyze TCP streams"""
        streams = []
        
        # Get number of streams
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-T', 'fields', '-e', 'tcp.stream'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                stream_nums = set(result.stdout.strip().splitlines())
                stream_nums = [s for s in stream_nums if s]
                
                print(f"    TCP streams: {len(stream_nums)}")
                
                # Analyze first 20 streams
                for stream_num in list(stream_nums)[:20]:
                    try:
                        # Follow stream
                        result = subprocess.run(
                            ['tshark', '-r', filepath, '-q', '-z', f'follow,tcp,ascii,{stream_num}'],
                            capture_output=True, text=True
                        )
                        if result.returncode == 0:
                            stream_data = result.stdout
                            
                            # Search for flags
                            self._search_flags(stream_data)
                            
                            # Look for interesting content
                            if any(word in stream_data.lower() for word in 
                                   ['password', 'flag', 'secret', 'key', 'login', 'auth']):
                                streams.append({
                                    'stream': stream_num,
                                    'preview': stream_data[:500],
                                    'interesting': True
                                })
                                print(f"    [STREAM {stream_num}] Contains interesting keywords")
                            else:
                                streams.append({
                                    'stream': stream_num,
                                    'size': len(stream_data)
                                })
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        return streams
    
    # ==================== SUSPICIOUS ACTIVITY ====================
    
    def _detect_suspicious(self, filepath: str) -> List[str]:
        """Detect suspicious network activity"""
        suspicious = []
        
        # Port scan detection
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'tcp.flags.syn==1 && tcp.flags.ack==0',
                 '-T', 'fields', '-e', 'ip.src', '-e', 'tcp.dstport'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                syn_packets = result.stdout.strip().splitlines()
                if len(syn_packets) > 100:
                    suspicious.append(f"Possible port scan detected ({len(syn_packets)} SYN packets)")
                    print(f"    [!] Possible port scan ({len(syn_packets)} SYN packets)")
        except FileNotFoundError:
            pass
        
        # Unusual ports
        unusual_ports = [4444, 5555, 1337, 31337, 12345, 54321, 6666, 6667]
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-T', 'fields', '-e', 'tcp.dstport'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                ports = set(result.stdout.strip().splitlines())
                for port in ports:
                    try:
                        if int(port) in unusual_ports:
                            suspicious.append(f"Unusual port detected: {port}")
                            print(f"    [!] Unusual port: {port}")
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        # ICMP data exfiltration
        try:
            result = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'icmp.data', '-T', 'fields',
                 '-e', 'icmp.data'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                icmp_data = result.stdout.strip()
                if icmp_data:
                    suspicious.append("ICMP contains data (possible exfiltration)")
                    print("    [!] ICMP data found (possible exfiltration)")
                    
                    # Try to decode
                    for line in icmp_data.splitlines():
                        try:
                            decoded = bytes.fromhex(line.replace(':', '')).decode()
                            self._search_flags(decoded)
                        except:
                            pass
        except FileNotFoundError:
            pass
        
        return suspicious
    
    # ==================== DEEP STRING SEARCH ====================
    
    def _deep_string_search(self, filepath: str):
        """Deep string search in PCAP"""
        
        # Using strings on PCAP
        try:
            result = subprocess.run(
                ['strings', '-n', '6', filepath],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self._search_flags(result.stdout)
        except FileNotFoundError:
            pass
        
        # Search for base64 patterns
        try:
            result = subprocess.run(
                ['strings', '-n', '20', filepath],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', line.strip()):
                        try:
                            decoded = base64.b64decode(line.strip()).decode()
                            self._search_flags(decoded)
                        except:
                            pass
        except FileNotFoundError:
            pass
    
    # ==================== UTILITIES ====================
    
    def _search_flags(self, text: str):
        """Search for flags"""
        if not text:
            return
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if m not in self.flags_found:
                    self.flags_found.append(m)
                    print(f"    [FLAG] {m}")
