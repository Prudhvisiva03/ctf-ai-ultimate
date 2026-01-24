#!/usr/bin/env python3
"""
Network Intelligence Extractor
Extracts IPs, URLs, emails, credentials, and other network artifacts from files
"""

import re
import os
from collections import defaultdict

# Regex patterns for network artifacts
PATTERNS = {
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'ipv6': r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
    'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
    'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
    'credentials': r'(?:password|passwd|pwd|pass|user|username|login|api[_-]?key|secret|token)["\']?\s*[:=]\s*["\']?([^\s"\'<>]+)',
    'base64': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'hash_md5': r'\b[a-fA-F0-9]{32}\b',
    'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
    'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
    'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    'api_key': r'(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})',
}


def extract_from_text(text):
    """Extract all network artifacts from text"""
    results = defaultdict(set)
    
    for artifact_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if isinstance(matches[0], tuple):
                # For patterns with capture groups
                results[artifact_type].update([m for m in matches if m])
            else:
                results[artifact_type].update(matches)
    
    # Convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in results.items() if v}


def extract_from_file(filepath):
    """Extract network artifacts from a file"""
    try:
        # Try to read as text
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return extract_from_text(content)
    
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return {}


def analyze_pcap(filepath):
    """Special handling for PCAP files"""
    import subprocess
    
    results = {}
    
    try:
        # Extract HTTP traffic
        http_result = subprocess.run(
            ['tshark', '-r', filepath, '-Y', 'http', '-T', 'fields', '-e', 'http.host', '-e', 'http.request.uri'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if http_result.returncode == 0 and http_result.stdout:
            results['http_requests'] = http_result.stdout.strip().split('\n')
        
        # Extract DNS queries
        dns_result = subprocess.run(
            ['tshark', '-r', filepath, '-Y', 'dns', '-T', 'fields', '-e', 'dns.qry.name'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if dns_result.returncode == 0 and dns_result.stdout:
            results['dns_queries'] = list(set(dns_result.stdout.strip().split('\n')))
        
        # Extract all IPs
        ip_result = subprocess.run(
            ['tshark', '-r', filepath, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if ip_result.returncode == 0 and ip_result.stdout:
            ips = set()
            for line in ip_result.stdout.strip().split('\n'):
                ips.update(line.split('\t'))
            results['ip_addresses'] = sorted(list(ips))
    
    except Exception as e:
        print(f"[!] PCAP analysis error: {e}")
    
    return results


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python3 network_extractor.py <file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    print(f"[*] Extracting network intelligence from: {filepath}")
    print("")
    
    # Check if it's a PCAP
    if filepath.endswith(('.pcap', '.pcapng', '.cap')):
        print("[*] Detected PCAP file - using tshark analysis")
        results = analyze_pcap(filepath)
    else:
        results = extract_from_file(filepath)
    
    if not results:
        print("[-] No network artifacts found")
        sys.exit(0)
    
    print(f"[+] Found {len(results)} artifact type(s):")
    print("")
    
    for artifact_type, items in results.items():
        print(f"📡 {artifact_type.upper().replace('_', ' ')}:")
        for item in items[:20]:  # Limit to first 20
            print(f"   • {item}")
        if len(items) > 20:
            print(f"   ... and {len(items) - 20} more")
        print("")
    
    # Save to JSON
    output_file = "output/network_intelligence.json"
    os.makedirs("output", exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Full results saved to: {output_file}")
    
    # Highlight interesting findings
    if 'credentials' in results:
        print("")
        print("🔑 CREDENTIALS FOUND:")
        for cred in results['credentials']:
            print(f"   ⚠️  {cred}")
    
    if 'private_key' in results:
        print("")
        print("🔐 PRIVATE KEY DETECTED!")
    
    if 'api_key' in results:
        print("")
        print("🔑 API KEYS FOUND:")
        for key in results['api_key']:
            print(f"   ⚠️  {key}")
