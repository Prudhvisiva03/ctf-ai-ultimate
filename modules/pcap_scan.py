"""
PCAP Network Analysis Module
Handles PCAP file analysis and packet inspection
"""

import subprocess
import os
import re
from pathlib import Path


class PCAPScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        
    def run_tshark_summary(self, filepath):
        """Get PCAP summary using tshark"""
        try:
            print("[*] Running tshark summary...")
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', 'io,phs'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                print("[+] PCAP Protocol Hierarchy:")
                print(proc.stdout[:1000])  # Show first 1000 chars
                return proc.stdout
            else:
                print("❌ tshark summary failed")
                return None
                
        except FileNotFoundError:
            print("⚠️  tshark not installed")
            return None
        except Exception as e:
            print(f"Error: {str(e)}")
            return None
    
    def run_tshark_conversations(self, filepath):
        """Get network conversations"""
        try:
            print("[*] Analyzing conversations...")
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', 'conv,tcp'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                return proc.stdout
            return None
                
        except Exception as e:
            return None
    
    def extract_http_objects(self, filepath):
        """Extract HTTP objects from PCAP"""
        try:
            output_dir = os.path.join(
                self.config.get('output_directory', 'output'),
                '_http_objects'
            )
            os.makedirs(output_dir, exist_ok=True)
            
            print(f"[*] Extracting HTTP objects to {output_dir}...")
            
            proc = subprocess.run(
                ['tshark', '-r', filepath, '--export-objects', f'http,{output_dir}'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Count extracted files
            if os.path.exists(output_dir):
                files = os.listdir(output_dir)
                if files:
                    print(f"🔥 Extracted {len(files)} HTTP object(s)")
                    for f in files[:10]:
                        print(f"    {f}")
                    return {
                        'count': len(files),
                        'directory': output_dir,
                        'files': files
                    }
                    
            print("❌ No HTTP objects found")
            return None
                
        except Exception as e:
            print(f"Error: {str(e)}")
            return None
    
    def analyze_tcp_streams(self, filepath):
        """Analyze TCP streams"""
        streams = []
        
        try:
            print("[*] Analyzing TCP streams...")
            
            # Get number of TCP streams
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-T', 'fields', '-e', 'tcp.stream'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                stream_nums = set(proc.stdout.strip().split('\n'))
                stream_nums = [s for s in stream_nums if s]
                
                print(f"[+] Found {len(stream_nums)} TCP stream(s)")
                
                # Extract first few streams
                for stream_num in list(stream_nums)[:5]:  # Limit to first 5
                    stream_data = self.follow_tcp_stream(filepath, stream_num)
                    if stream_data:
                        streams.append({
                            'stream_number': stream_num,
                            'data': stream_data
                        })
                        
                        # Search for flags in stream data
                        flags = self.search_flags(stream_data)
                        if flags:
                            print(f"✅ FLAG FOUND in TCP stream {stream_num}: {flags}")
                            
            return streams
                
        except Exception as e:
            print(f"Error: {str(e)}")
            return streams
    
    def follow_tcp_stream(self, filepath, stream_num):
        """Follow specific TCP stream"""
        try:
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-q', '-z', f'follow,tcp,ascii,{stream_num}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                return proc.stdout
            return None
                
        except Exception as e:
            return None
    
    def search_flags(self, content):
        """Search for flags in content"""
        flags = []
        
        for pattern in self.config.get('flag_patterns', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def extract_dns_queries(self, filepath):
        """Extract DNS queries"""
        try:
            print("[*] Extracting DNS queries...")
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'dns.qry.name'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                queries = proc.stdout.strip().split('\n')
                queries = list(set([q for q in queries if q]))
                
                if queries:
                    print(f"[+] Found {len(queries)} unique DNS query/queries")
                    for q in queries[:20]:
                        print(f"    {q}")
                    return queries
                    
        except Exception as e:
            pass
            
        return []
    
    def extract_credentials(self, filepath):
        """Search for potential credentials in plaintext protocols"""
        credentials = []
        
        try:
            print("[*] Searching for credentials...")
            
            # Search for HTTP Basic Auth
            proc = subprocess.run(
                ['tshark', '-r', filepath, '-Y', 'http.authorization', '-T', 'fields', '-e', 'http.authorization'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                creds = proc.stdout.strip().split('\n')
                credentials.extend([{'type': 'HTTP Auth', 'value': c} for c in creds if c])
                print(f"⚠️  Found {len(creds)} HTTP credential(s)")
                
        except Exception as e:
            pass
            
        return credentials
    
    def scan(self, filepath):
        """Perform comprehensive PCAP analysis"""
        print(f"\n[*] Starting PCAP analysis on: {filepath}")
        
        scan_results = {
            'filepath': filepath,
            'pcap_findings': []
        }
        
        # Get summary
        summary = self.run_tshark_summary(filepath)
        scan_results['summary'] = summary
        
        # Get conversations
        conversations = self.run_tshark_conversations(filepath)
        scan_results['conversations'] = conversations
        
        # Extract HTTP objects
        http_objects = self.extract_http_objects(filepath)
        if http_objects:
            scan_results['http_objects'] = http_objects
        
        # Analyze TCP streams
        tcp_streams = self.analyze_tcp_streams(filepath)
        scan_results['tcp_streams'] = tcp_streams
        
        # Extract DNS queries
        dns_queries = self.extract_dns_queries(filepath)
        if dns_queries:
            scan_results['dns_queries'] = dns_queries
        
        # Search for credentials
        credentials = self.extract_credentials(filepath)
        if credentials:
            scan_results['credentials'] = credentials
        
        return scan_results
