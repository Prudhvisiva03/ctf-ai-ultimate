"""
CTFHunter - Web Analysis Module
===============================

Analyzes web-related CTF challenges including
reconnaissance and common vulnerabilities.
"""

import os
import re
import subprocess
import shutil
import urllib.parse
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


class WebModule:
    """
    Web security analysis module.
    
    Handles:
    - URL analysis
    - robots.txt / sitemap.xml
    - HTML source analysis
    - JavaScript analysis
    - Cookie/header inspection
    - Common web vulnerabilities
    """
    
    def __init__(self):
        """Initialize the web module."""
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> dict:
        """Check available web tools."""
        tools = ['curl', 'wget', 'nikto', 'dirb', 'gobuster',
                 'whatweb', 'wfuzz', 'sqlmap']
        return {tool: shutil.which(tool) is not None for tool in tools}
    
    def analyze(self, target: str, output_dir: str,
                extracted_dir: str, mode: str = "auto") -> List[ToolResult]:
        """
        Analyze a web target or HTML file.
        
        Args:
            target: URL or path to HTML file
            output_dir: Directory for output files
            extracted_dir: Directory for extracted files
            mode: Analysis mode
            
        Returns:
            List of ToolResult objects
        """
        results = []
        
        # Check if target is URL or file
        if target.startswith(('http://', 'https://')):
            results.extend(self._analyze_url(target, output_dir, extracted_dir, mode))
        else:
            results.extend(self._analyze_html_file(target, output_dir, extracted_dir))
        
        return results
    
    def _analyze_url(self, url: str, output_dir: str,
                     extracted_dir: str, mode: str) -> List[ToolResult]:
        """Analyze a URL target."""
        results = []
        
        # Fetch and analyze main page
        results.append(self._fetch_page(url, output_dir))
        
        # Check robots.txt
        results.append(self._check_robots(url, output_dir))
        
        # Check sitemap.xml
        results.append(self._check_sitemap(url, output_dir))
        
        # Check common files
        results.append(self._check_common_files(url, output_dir))
        
        # Run whatweb if available
        if self.available_tools.get('whatweb'):
            results.append(self._run_whatweb(url, output_dir))
        
        # Deep mode - run directory brute force
        if mode == 'deep':
            if self.available_tools.get('gobuster'):
                results.append(self._run_gobuster(url, output_dir))
            elif self.available_tools.get('dirb'):
                results.append(self._run_dirb(url, output_dir))
        
        return results
    
    def _analyze_html_file(self, target: str, output_dir: str,
                           extracted_dir: str) -> List[ToolResult]:
        """Analyze an HTML file."""
        results = []
        
        try:
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Search for flags
            flags = self._extract_flags(content)
            
            # Search for interesting patterns
            results.append(self._analyze_html_content(content, output_dir))
            
            # Extract and analyze JavaScript
            results.append(self._extract_javascript(content, output_dir))
            
            # Extract comments
            results.append(self._extract_comments(content, output_dir))
            
            # Extract links
            results.append(self._extract_links(content, output_dir))
            
            # Check for encoded data
            results.append(self._find_encoded_data(content, output_dir))
            
        except Exception as e:
            results.append(ToolResult(
                tool_name="html_analyze",
                command=f"analyze {target}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            ))
        
        return results
    
    def _fetch_page(self, url: str, output_dir: str) -> ToolResult:
        """Fetch and analyze a web page."""
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '-i', '-k', url],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            # Save full response
            with open(os.path.join(output_dir, "page_response.txt"), 'w') as f:
                f.write(output)
            
            # Parse headers
            headers = []
            body = ""
            if '\r\n\r\n' in output:
                parts = output.split('\r\n\r\n', 1)
                headers = parts[0].split('\r\n')
                body = parts[1] if len(parts) > 1 else ""
            elif '\n\n' in output:
                parts = output.split('\n\n', 1)
                headers = parts[0].split('\n')
                body = parts[1] if len(parts) > 1 else ""
            
            # Look for interesting headers
            interesting_headers = []
            for header in headers:
                header_lower = header.lower()
                if any(kw in header_lower for kw in ['flag', 'secret', 'x-', 'set-cookie', 'server']):
                    interesting_headers.append(header)
            
            summary = f"URL: {url}\n"
            summary += f"\nInteresting Headers:\n"
            summary += '\n'.join(interesting_headers[:20])
            summary += f"\n\nBody Length: {len(body)} bytes"
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="curl",
                command=f"curl -s -L -i {url}",
                success=result.returncode == 0,
                output=summary[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name="curl",
                command=f"curl {url}",
                success=False,
                output="",
                error="Request timed out",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="curl",
                command=f"curl {url}",
                success=False,
                output="",
                error="curl not installed",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="curl",
                command=f"curl {url}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _check_robots(self, url: str, output_dir: str) -> ToolResult:
        """Check robots.txt."""
        parsed = urllib.parse.urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-k', robots_url],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            output = result.stdout
            
            if "User-agent" in output or "Disallow" in output or "Allow" in output:
                with open(os.path.join(output_dir, "robots.txt"), 'w') as f:
                    f.write(output)
                
                # Extract disallowed paths
                disallowed = re.findall(r'Disallow:\s*(.+)', output)
                
                summary = f"robots.txt found!\n\n{output}\n\n"
                summary += f"Disallowed paths ({len(disallowed)}):\n"
                summary += '\n'.join(disallowed[:20])
                
                flags = self._extract_flags(output)
                
                return ToolResult(
                    tool_name="robots_txt",
                    command=f"curl {robots_url}",
                    success=True,
                    output=summary[:5000],
                    error="",
                    execution_time=0,
                    flags_found=flags
                )
            else:
                return ToolResult(
                    tool_name="robots_txt",
                    command=f"curl {robots_url}",
                    success=False,
                    output="No robots.txt found or empty",
                    error="",
                    execution_time=0,
                    flags_found=[]
                )
        except Exception as e:
            return ToolResult(
                tool_name="robots_txt",
                command=f"curl {robots_url}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _check_sitemap(self, url: str, output_dir: str) -> ToolResult:
        """Check sitemap.xml."""
        parsed = urllib.parse.urlparse(url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-k', sitemap_url],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            output = result.stdout
            
            if '<?xml' in output or '<urlset' in output or '<sitemapindex' in output:
                with open(os.path.join(output_dir, "sitemap.xml"), 'w') as f:
                    f.write(output)
                
                # Extract URLs
                urls = re.findall(r'<loc>([^<]+)</loc>', output)
                
                summary = f"sitemap.xml found!\n\n"
                summary += f"URLs found ({len(urls)}):\n"
                summary += '\n'.join(urls[:30])
                
                flags = self._extract_flags(output)
                
                return ToolResult(
                    tool_name="sitemap_xml",
                    command=f"curl {sitemap_url}",
                    success=True,
                    output=summary[:5000],
                    error="",
                    execution_time=0,
                    flags_found=flags
                )
            else:
                return ToolResult(
                    tool_name="sitemap_xml",
                    command=f"curl {sitemap_url}",
                    success=False,
                    output="No sitemap.xml found",
                    error="",
                    execution_time=0,
                    flags_found=[]
                )
        except Exception as e:
            return ToolResult(
                tool_name="sitemap_xml",
                command=f"curl {sitemap_url}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _check_common_files(self, url: str, output_dir: str) -> ToolResult:
        """Check for common sensitive files."""
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        common_paths = [
            '/.git/config',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/admin/',
            '/backup/',
            '/.htaccess',
            '/flag.txt',
            '/secret.txt',
            '/.DS_Store',
            '/debug/',
            '/test/',
            '/api/',
            '/swagger/',
            '/.well-known/',
            '/crossdomain.xml',
            '/security.txt',
            '/.svn/entries',
        ]
        
        found = []
        flags = []
        
        for path in common_paths:
            try:
                check_url = base_url + path
                result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-k', check_url],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                status = result.stdout.strip()
                if status in ['200', '301', '302', '403']:
                    found.append(f"{path} - HTTP {status}")
                    
                    # If 200, fetch content and check for flags
                    if status == '200':
                        content_result = subprocess.run(
                            ['curl', '-s', '-k', check_url],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        flags.extend(self._extract_flags(content_result.stdout))
                        
            except Exception:
                pass
        
        output = f"Common Files Check:\n\n"
        if found:
            output += f"Found {len(found)} interesting path(s):\n"
            output += '\n'.join(found)
        else:
            output += "No common sensitive files found"
        
        with open(os.path.join(output_dir, "common_files.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="common_files",
            command="common file check",
            success=len(found) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _run_whatweb(self, url: str, output_dir: str) -> ToolResult:
        """Run whatweb for technology detection."""
        try:
            result = subprocess.run(
                ['whatweb', '-v', url],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout + result.stderr
            
            with open(os.path.join(output_dir, "whatweb_output.txt"), 'w') as f:
                f.write(output)
            
            flags = self._extract_flags(output)
            
            return ToolResult(
                tool_name="whatweb",
                command=f"whatweb -v {url}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=flags
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="whatweb",
                command=f"whatweb {url}",
                success=False,
                output="",
                error="whatweb not installed. Install with: apt install whatweb",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="whatweb",
                command=f"whatweb {url}",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_gobuster(self, url: str, output_dir: str) -> ToolResult:
        """Run gobuster for directory brute-forcing."""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        
        if not os.path.exists(wordlist):
            return ToolResult(
                tool_name="gobuster",
                command="gobuster",
                success=False,
                output="",
                error="No wordlist found. Install with: apt install wordlists",
                execution_time=0,
                flags_found=[]
            )
        
        try:
            result = subprocess.run(
                ['gobuster', 'dir', '-u', url, '-w', wordlist, '-q', '-t', '10'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "gobuster_output.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="gobuster",
                command=f"gobuster dir -u {url} -w {wordlist}",
                success=result.returncode == 0,
                output=output[:5000],
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=0,
                flags_found=[]
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name="gobuster",
                command="gobuster",
                success=False,
                output="",
                error="Scan timed out",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="gobuster",
                command="gobuster",
                success=False,
                output="",
                error="gobuster not installed. Install with: apt install gobuster",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="gobuster",
                command="gobuster",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _run_dirb(self, url: str, output_dir: str) -> ToolResult:
        """Run dirb for directory brute-forcing."""
        try:
            result = subprocess.run(
                ['dirb', url, '-S', '-r'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout
            
            with open(os.path.join(output_dir, "dirb_output.txt"), 'w') as f:
                f.write(output)
            
            return ToolResult(
                tool_name="dirb",
                command=f"dirb {url}",
                success=result.returncode == 0,
                output=output[:5000],
                error="",
                execution_time=0,
                flags_found=[]
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name="dirb",
                command="dirb",
                success=False,
                output="",
                error="Scan timed out",
                execution_time=0,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name="dirb",
                command="dirb",
                success=False,
                output="",
                error="dirb not installed. Install with: apt install dirb",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name="dirb",
                command="dirb",
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _analyze_html_content(self, content: str, output_dir: str) -> ToolResult:
        """Analyze HTML content for interesting data."""
        findings = []
        flags = self._extract_flags(content)
        
        # Find hidden inputs
        hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', content, re.IGNORECASE)
        if hidden_inputs:
            findings.append(f"Hidden inputs ({len(hidden_inputs)}):")
            findings.extend(hidden_inputs[:10])
        
        # Find data attributes
        data_attrs = re.findall(r'data-[a-z-]+=["\'][^"\']+["\']', content, re.IGNORECASE)
        if data_attrs:
            findings.append(f"\nData attributes ({len(data_attrs)}):")
            findings.extend(data_attrs[:10])
        
        # Find meta tags
        meta_tags = re.findall(r'<meta[^>]+>', content, re.IGNORECASE)
        interesting_meta = [m for m in meta_tags if any(kw in m.lower() for kw in ['flag', 'secret', 'author', 'description'])]
        if interesting_meta:
            findings.append(f"\nInteresting meta tags:")
            findings.extend(interesting_meta[:10])
        
        output = '\n'.join(findings) if findings else "No interesting HTML patterns found"
        
        with open(os.path.join(output_dir, "html_analysis.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="html_analyze",
            command="HTML content analysis",
            success=len(findings) > 0 or len(flags) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=flags
        )
    
    def _extract_javascript(self, content: str, output_dir: str) -> ToolResult:
        """Extract and analyze JavaScript."""
        # Extract inline scripts
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
        
        # Extract script sources
        script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        output = f"Inline scripts: {len(scripts)}\n"
        output += f"External scripts: {len(script_srcs)}\n\n"
        
        if script_srcs:
            output += "External script URLs:\n"
            output += '\n'.join(script_srcs[:20])
            output += "\n\n"
        
        # Analyze inline scripts
        flags = []
        interesting = []
        
        for i, script in enumerate(scripts[:10]):
            script_flags = self._extract_flags(script)
            flags.extend(script_flags)
            
            # Look for interesting patterns
            if any(kw in script.lower() for kw in ['flag', 'password', 'secret', 'key', 'api', 'token']):
                interesting.append(f"Script {i+1}:\n{script[:500]}...")
        
        if interesting:
            output += "Interesting scripts:\n"
            output += '\n\n'.join(interesting)
        
        with open(os.path.join(output_dir, "javascript_analysis.txt"), 'w') as f:
            f.write(output)
            for i, script in enumerate(scripts):
                f.write(f"\n\n=== Script {i+1} ===\n")
                f.write(script)
        
        return ToolResult(
            tool_name="js_analyze",
            command="JavaScript analysis",
            success=len(scripts) > 0 or len(script_srcs) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _extract_comments(self, content: str, output_dir: str) -> ToolResult:
        """Extract HTML comments."""
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        
        output = f"Found {len(comments)} HTML comment(s):\n\n"
        
        flags = []
        for i, comment in enumerate(comments):
            output += f"[{i+1}] {comment.strip()[:200]}\n"
            flags.extend(self._extract_flags(comment))
        
        with open(os.path.join(output_dir, "html_comments.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="comments_extract",
            command="HTML comment extraction",
            success=len(comments) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _extract_links(self, content: str, output_dir: str) -> ToolResult:
        """Extract links from HTML."""
        # href links
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        # src links
        srcs = re.findall(r'src=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        # action links
        actions = re.findall(r'action=["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        output = f"Links found:\n"
        output += f"  href: {len(hrefs)}\n"
        output += f"  src: {len(srcs)}\n"
        output += f"  action: {len(actions)}\n\n"
        
        all_links = list(set(hrefs + srcs + actions))
        output += "All unique links:\n"
        output += '\n'.join(all_links[:50])
        
        with open(os.path.join(output_dir, "links.txt"), 'w') as f:
            f.write(output)
        
        # Check for interesting links
        flags = []
        for link in all_links:
            flags.extend(self._extract_flags(link))
        
        return ToolResult(
            tool_name="links_extract",
            command="Link extraction",
            success=len(all_links) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
        )
    
    def _find_encoded_data(self, content: str, output_dir: str) -> ToolResult:
        """Find encoded data in content."""
        import base64
        
        findings = []
        flags = []
        
        # Find base64 strings
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        b64_matches = b64_pattern.findall(content)
        
        for match in b64_matches[:20]:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 3:
                    # Check if readable
                    if sum(1 for c in decoded if c.isprintable()) / len(decoded) > 0.7:
                        findings.append(f"Base64: {match[:30]}... -> {decoded[:100]}")
                        flags.extend(self._extract_flags(decoded))
            except Exception:
                pass
        
        output = "Encoded Data Analysis:\n\n"
        if findings:
            output += '\n'.join(findings)
        else:
            output += "No obvious encoded data found"
        
        with open(os.path.join(output_dir, "encoded_data.txt"), 'w') as f:
            f.write(output)
        
        return ToolResult(
            tool_name="encoded_data",
            command="Encoded data analysis",
            success=len(findings) > 0,
            output=output[:5000],
            error="",
            execution_time=0,
            flags_found=list(set(flags))
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
