"""
Web Challenge Scanning Module
Handles web reconnaissance and vulnerability scanning
"""

import subprocess
import os
import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class WebScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 CTFHunter/1.0'
        })
        
    def fetch_url(self, url):
        """Fetch URL content"""
        try:
            print(f"[*] Fetching {url}...")
            response = self.session.get(url, timeout=30, allow_redirects=True)
            
            print(f"[+] Status: {response.status_code}")
            print(f"[+] Content-Length: {len(response.content)} bytes")
            
            return response
            
        except Exception as e:
            print(f"❌ Failed to fetch URL: {str(e)}")
            return None
    
    def analyze_html(self, response):
        """Analyze HTML source for flags and hidden content"""
        results = {
            'flags': [],
            'comments': [],
            'hidden_inputs': [],
            'suspicious': []
        }
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Search entire source for flags
            print("[*] Searching HTML source for flags...")
            flags = self.search_flags(response.text)
            if flags:
                results['flags'] = flags
                for flag in flags:
                    print(f"✅ FLAG FOUND: {flag}")
            
            # Extract HTML comments
            print("[*] Extracting HTML comments...")
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            
            if not comments:
                # Alternative method
                comment_pattern = r'<!--(.*?)-->'
                comments = re.findall(comment_pattern, response.text, re.DOTALL)
            
            if comments:
                print(f"⚠️  Found {len(comments)} HTML comment(s)")
                results['comments'] = comments
                
                for comment in comments[:5]:
                    comment_str = str(comment).strip()
                    print(f"    {comment_str[:100]}")
                    
                    # Search comments for flags
                    comment_flags = self.search_flags(comment_str)
                    if comment_flags:
                        results['flags'].extend(comment_flags)
            
            # Find hidden input fields
            print("[*] Searching for hidden inputs...")
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            
            if hidden_inputs:
                print(f"⚠️  Found {len(hidden_inputs)} hidden input(s)")
                for inp in hidden_inputs:
                    hidden_data = {
                        'name': inp.get('name', ''),
                        'value': inp.get('value', '')
                    }
                    results['hidden_inputs'].append(hidden_data)
                    print(f"    {hidden_data}")
            
            # Search for suspicious attributes
            print("[*] Searching for suspicious content...")
            suspicious_attrs = ['data-flag', 'data-secret', 'data-key']
            
            for attr in suspicious_attrs:
                elements = soup.find_all(attrs={attr: True})
                if elements:
                    for elem in elements:
                        results['suspicious'].append({
                            'tag': elem.name,
                            'attribute': attr,
                            'value': elem.get(attr)
                        })
                        print(f"⚠️  Found suspicious attribute: {elem}")
            
        except Exception as e:
            print(f"Error analyzing HTML: {str(e)}")
            
        return results
    
    def analyze_javascript(self, response):
        """Extract and analyze JavaScript"""
        js_findings = []
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            
            print(f"[*] Found {len(scripts)} script tag(s)")
            
            for script in scripts:
                if script.string:
                    # Search for flags in JS
                    flags = self.search_flags(script.string)
                    if flags:
                        print(f"✅ FLAG FOUND IN JAVASCRIPT: {flags}")
                        js_findings.extend(flags)
            
        except Exception as e:
            print(f"Error analyzing JavaScript: {str(e)}")
            
        return js_findings
    
    def check_headers(self, response):
        """Analyze HTTP headers"""
        print("[*] Analyzing HTTP headers...")
        
        headers = dict(response.headers)
        
        # Display interesting headers
        interesting = ['Server', 'X-Powered-By', 'X-Flag', 'X-Secret']
        for header in interesting:
            if header in headers:
                print(f"    {header}: {headers[header]}")
        
        # Search headers for flags
        header_str = str(headers)
        flags = self.search_flags(header_str)
        
        if flags:
            print(f"✅ FLAG FOUND IN HEADERS: {flags}")
            
        return {
            'headers': headers,
            'flags': flags
        }
    
    def check_robots_txt(self, base_url):
        """Check robots.txt"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            print(f"[*] Checking {robots_url}...")
            
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                print(f"[+] robots.txt found!")
                print(response.text[:500])
                
                # Search for flags
                flags = self.search_flags(response.text)
                
                return {
                    'found': True,
                    'content': response.text,
                    'flags': flags
                }
            else:
                print("❌ robots.txt not found")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return {'found': False}
    
    def check_sitemap(self, base_url):
        """Check sitemap.xml"""
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            print(f"[*] Checking {sitemap_url}...")
            
            response = self.session.get(sitemap_url, timeout=10)
            
            if response.status_code == 200:
                print(f"[+] sitemap.xml found!")
                return {
                    'found': True,
                    'content': response.text[:1000]
                }
            else:
                print("❌ sitemap.xml not found")
                
        except Exception as e:
            pass
            
        return {'found': False}
    
    def probe_common_paths(self, base_url):
        """Probe common hidden paths"""
        print("[*] Probing common paths...")
        
        paths = self.config.get('web_paths', [
            '/admin', '/.git', '/backup', '/flag.txt', 
            '/secret', '/login', '/config'
        ])
        
        found_paths = []
        
        for path in paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    print(f"✅ Found: {url} [{response.status_code}]")
                    found_paths.append({
                        'path': path,
                        'url': url,
                        'status': response.status_code
                    })
                    
                    # If it's flag.txt or similar, check content
                    if 'flag' in path.lower() and response.status_code == 200:
                        flags = self.search_flags(response.text)
                        if flags:
                            print(f"🔥 FLAG FOUND AT {url}: {flags}")
                            
            except Exception as e:
                pass
        
        return found_paths
    
    def run_dirsearch(self, url):
        """Run dirsearch if available"""
        try:
            print("[*] Running dirsearch...")
            
            wordlist = self.config.get('wordlists', {}).get('dirb_common')
            
            if not wordlist or not os.path.exists(wordlist):
                print("⚠️  Wordlist not found, skipping dirsearch")
                return None
            
            output_dir = self.config.get('output_directory', 'output')
            output_file = os.path.join(output_dir, 'dirsearch.txt')
            
            proc = subprocess.run(
                ['dirsearch', '-u', url, '-w', wordlist, '-o', output_file],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if proc.returncode == 0:
                print(f"[+] Dirsearch completed, results saved to {output_file}")
                return output_file
                
        except FileNotFoundError:
            print("⚠️  dirsearch not installed")
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def search_flags(self, content):
        """Search for flags in content"""
        flags = []
        
        for pattern in self.config.get('flag_patterns', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def scan(self, url):
        """Perform comprehensive web reconnaissance"""
        print(f"\n[*] Starting web scan on: {url}")
        
        scan_results = {
            'url': url,
            'web_findings': []
        }
        
        # Fetch main page
        response = self.fetch_url(url)
        
        if not response:
            return scan_results
        
        # Save HTML source
        output_dir = self.config.get('output_directory', 'output')
        os.makedirs(output_dir, exist_ok=True)
        
        html_file = os.path.join(output_dir, 'page_source.html')
        with open(html_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(response.text)
        print(f"[+] Saved HTML source to {html_file}")
        
        # Analyze HTML
        html_results = self.analyze_html(response)
        scan_results['html_analysis'] = html_results
        
        if html_results.get('flags'):
            scan_results['flags'] = html_results['flags']
        
        # Analyze JavaScript
        js_flags = self.analyze_javascript(response)
        if js_flags:
            if 'flags' not in scan_results:
                scan_results['flags'] = []
            scan_results['flags'].extend(js_flags)
        
        # Check headers
        header_results = self.check_headers(response)
        scan_results['headers'] = header_results
        
        if header_results.get('flags'):
            if 'flags' not in scan_results:
                scan_results['flags'] = []
            scan_results['flags'].extend(header_results['flags'])
        
        # Get base URL
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check robots.txt
        robots = self.check_robots_txt(base_url)
        scan_results['robots_txt'] = robots
        
        if robots.get('flags'):
            if 'flags' not in scan_results:
                scan_results['flags'] = []
            scan_results['flags'].extend(robots['flags'])
        
        # Check sitemap
        sitemap = self.check_sitemap(base_url)
        scan_results['sitemap'] = sitemap
        
        # Probe common paths
        found_paths = self.probe_common_paths(base_url)
        scan_results['found_paths'] = found_paths
        
        return scan_results
