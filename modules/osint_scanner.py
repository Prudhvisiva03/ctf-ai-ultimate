#!/usr/bin/env python3
"""
OSINT & Geolocation Scanner - For Digital Cyberhunt CTF
Supports: GPS extraction, image geolocation, metadata analysis, coordinate decoding,
          Online OSINT tools, Username lookup, IP/Domain analysis, Social media OSINT
Author: Prudhvi (CTFHunter)
Version: 3.0.0
"""

import re
import os
import subprocess
import json
import math
import hashlib
import base64
import urllib.parse
from typing import Dict, List, Optional, Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class OnlineOSINT:
    """Online OSINT tools and API integrations"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.api_keys = {
            'shodan': self.config.get('shodan_api_key', ''),
            'virustotal': self.config.get('virustotal_api_key', ''),
            'hunter': self.config.get('hunter_api_key', ''),
            'whoisxml': self.config.get('whoisxml_api_key', ''),
            'what3words': self.config.get('what3words_api_key', ''),
            'ipinfo': self.config.get('ipinfo_api_key', ''),
        }
        self.timeout = 15
        self.results = []
    
    def check_username(self, username: str) -> Dict:
        """Check username across multiple platforms"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests module not installed'}
        
        platforms = {
            'github': f'https://api.github.com/users/{username}',
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://www.instagram.com/{username}/',
            'reddit': f'https://www.reddit.com/user/{username}/about.json',
            'linkedin': f'https://www.linkedin.com/in/{username}',
            'tiktok': f'https://www.tiktok.com/@{username}',
            'pinterest': f'https://www.pinterest.com/{username}/',
            'medium': f'https://medium.com/@{username}',
            'dev.to': f'https://dev.to/{username}',
            'hackerrank': f'https://www.hackerrank.com/{username}',
            'gitlab': f'https://gitlab.com/{username}',
            'keybase': f'https://keybase.io/{username}',
            'pastebin': f'https://pastebin.com/u/{username}',
            'soundcloud': f'https://soundcloud.com/{username}',
            'spotify': f'https://open.spotify.com/user/{username}',
            'twitch': f'https://www.twitch.tv/{username}',
            'youtube': f'https://www.youtube.com/@{username}',
            'facebook': f'https://www.facebook.com/{username}',
            'telegram': f'https://t.me/{username}',
        }
        
        found = []
        not_found = []
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for platform, url in platforms.items():
            try:
                resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200:
                    # Additional checks for some platforms
                    if platform == 'reddit':
                        try:
                            data = resp.json()
                            if 'data' in data:
                                found.append({'platform': platform, 'url': url, 'status': 'FOUND'})
                            else:
                                not_found.append(platform)
                        except:
                            not_found.append(platform)
                    elif platform == 'github':
                        found.append({'platform': platform, 'url': url, 'status': 'FOUND', 'data': resp.json()})
                    else:
                        found.append({'platform': platform, 'url': url, 'status': 'FOUND'})
                else:
                    not_found.append(platform)
            except:
                not_found.append(platform)
        
        return {
            'username': username,
            'found': found,
            'not_found': not_found,
            'total_found': len(found)
        }
    
    def reverse_image_search_urls(self, image_path: str) -> Dict:
        """Generate reverse image search URLs for manual checking"""
        urls = {}
        
        if os.path.exists(image_path):
            # For local files, provide instructions
            urls['instructions'] = "Upload image to these services:"
            urls['google'] = "https://images.google.com/ (click camera icon)"
            urls['tineye'] = "https://tineye.com/"
            urls['yandex'] = "https://yandex.com/images/"
            urls['bing'] = "https://www.bing.com/visualsearch"
            urls['baidu'] = "https://image.baidu.com/"
            urls['pimeyes'] = "https://pimeyes.com/ (face search)"
            urls['facecheck'] = "https://facecheck.id/ (face search)"
        
        return urls
    
    def ip_lookup(self, ip: str) -> Dict:
        """Lookup IP address information"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests module not installed'}
        
        results = {'ip': ip, 'sources': {}}
        
        # IPInfo.io
        try:
            url = f'https://ipinfo.io/{ip}/json'
            if self.api_keys.get('ipinfo'):
                url += f"?token={self.api_keys['ipinfo']}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                results['sources']['ipinfo'] = resp.json()
        except:
            pass
        
        # IP-API.com (free)
        try:
            resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=self.timeout)
            if resp.status_code == 200:
                results['sources']['ip-api'] = resp.json()
        except:
            pass
        
        # AbuseIPDB lookup (basic)
        try:
            resp = requests.get(f'https://api.abuseipdb.com/api/v2/check', 
                              params={'ipAddress': ip},
                              headers={'Key': self.api_keys.get('abuseipdb', ''), 'Accept': 'application/json'},
                              timeout=self.timeout)
            if resp.status_code == 200:
                results['sources']['abuseipdb'] = resp.json()
        except:
            pass
        
        # Shodan (if API key available)
        if self.api_keys.get('shodan'):
            try:
                resp = requests.get(f'https://api.shodan.io/shodan/host/{ip}',
                                  params={'key': self.api_keys['shodan']},
                                  timeout=self.timeout)
                if resp.status_code == 200:
                    results['sources']['shodan'] = resp.json()
            except:
                pass
        
        return results
    
    def domain_lookup(self, domain: str) -> Dict:
        """Lookup domain information"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests module not installed'}
        
        results = {'domain': domain, 'sources': {}}
        
        # DNS lookup URLs
        results['manual_checks'] = {
            'whois': f'https://who.is/whois/{domain}',
            'dnsdumpster': 'https://dnsdumpster.com/',
            'securitytrails': f'https://securitytrails.com/domain/{domain}',
            'crt.sh': f'https://crt.sh/?q={domain}',
            'virustotal': f'https://www.virustotal.com/gui/domain/{domain}',
            'urlscan': f'https://urlscan.io/search/#domain:{domain}',
            'wayback': f'https://web.archive.org/web/*/{domain}',
            'builtwith': f'https://builtwith.com/{domain}',
        }
        
        # VirusTotal (if API key)
        if self.api_keys.get('virustotal'):
            try:
                resp = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}',
                                  headers={'x-apikey': self.api_keys['virustotal']},
                                  timeout=self.timeout)
                if resp.status_code == 200:
                    results['sources']['virustotal'] = resp.json()
            except:
                pass
        
        return results
    
    def email_lookup(self, email: str) -> Dict:
        """Lookup email address information"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests module not installed'}
        
        results = {'email': email, 'sources': {}}
        
        # Check if email appears in breaches (HaveIBeenPwned concept)
        results['manual_checks'] = {
            'haveibeenpwned': f'https://haveibeenpwned.com/account/{email}',
            'dehashed': 'https://dehashed.com/',
            'hunter': f'https://hunter.io/email-verifier/{email}',
            'emailrep': f'https://emailrep.io/{email}',
        }
        
        # Hunter.io verification (if API key)
        if self.api_keys.get('hunter'):
            try:
                resp = requests.get('https://api.hunter.io/v2/email-verifier',
                                  params={'email': email, 'api_key': self.api_keys['hunter']},
                                  timeout=self.timeout)
                if resp.status_code == 200:
                    results['sources']['hunter'] = resp.json()
            except:
                pass
        
        # Gravatar check
        try:
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            gravatar_url = f'https://www.gravatar.com/avatar/{email_hash}?d=404'
            resp = requests.head(gravatar_url, timeout=self.timeout)
            results['gravatar'] = {
                'has_gravatar': resp.status_code == 200,
                'url': f'https://www.gravatar.com/avatar/{email_hash}'
            }
        except:
            pass
        
        return results
    
    def phone_lookup(self, phone: str) -> Dict:
        """Generate phone number lookup URLs"""
        # Clean phone number
        clean_phone = re.sub(r'[^\d+]', '', phone)
        
        results = {
            'phone': phone,
            'cleaned': clean_phone,
            'manual_checks': {
                'truecaller': 'https://www.truecaller.com/',
                'numverify': 'https://numverify.com/',
                'phonevalidator': 'https://www.phonevalidator.com/',
                'whitepages': f'https://www.whitepages.com/phone/{clean_phone}',
                'sync.me': 'https://sync.me/',
            }
        }
        
        return results
    
    def what3words_lookup(self, words: str) -> Dict:
        """Convert What3Words to coordinates"""
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests module not installed'}
        
        results = {'words': words}
        
        # Manual check URL
        results['manual_url'] = f'https://what3words.com/{words}'
        
        # API lookup if key available
        if self.api_keys.get('what3words'):
            try:
                resp = requests.get('https://api.what3words.com/v3/convert-to-coordinates',
                                  params={'words': words, 'key': self.api_keys['what3words']},
                                  timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'coordinates' in data:
                        results['coordinates'] = data['coordinates']
                        results['google_maps'] = f"https://maps.google.com/?q={data['coordinates']['lat']},{data['coordinates']['lng']}"
            except:
                pass
        
        return results
    
    def social_media_osint(self, handle: str) -> Dict:
        """Comprehensive social media OSINT"""
        results = {
            'handle': handle,
            'platforms': {},
            'tools': {
                'sherlock': f'sherlock {handle}',
                'socialscan': f'socialscan -u {handle}',
                'maigret': f'maigret {handle}',
            },
            'manual_searches': {
                'namechk': f'https://namechk.com/',
                'knowem': f'https://knowem.com/checkusernames.php?u={handle}',
                'namecheckr': f'https://www.namecheckr.com/',
                'usersearch': f'https://usersearch.org/results_normal.php?URL_username={handle}',
                'socialsearcher': f'https://www.social-searcher.com/search-users/?q={handle}',
            }
        }
        
        # Check platforms
        username_check = self.check_username(handle)
        results['platforms'] = username_check
        
        return results
    
    def get_osint_resources(self) -> Dict:
        """Return comprehensive OSINT resources and tools"""
        return {
            'search_engines': {
                'google_dorks': 'https://www.google.com/advanced_search',
                'duckduckgo': 'https://duckduckgo.com/',
                'shodan': 'https://www.shodan.io/',
                'censys': 'https://search.censys.io/',
                'zoomeye': 'https://www.zoomeye.org/',
                'greynoise': 'https://viz.greynoise.io/',
            },
            'image_osint': {
                'google_images': 'https://images.google.com/',
                'tineye': 'https://tineye.com/',
                'yandex_images': 'https://yandex.com/images/',
                'pimeyes': 'https://pimeyes.com/',
                'facecheck': 'https://facecheck.id/',
                'exif_viewer': 'http://exif.regex.info/exif.cgi',
            },
            'social_media': {
                'sherlock': 'pip install sherlock-project',
                'socialscan': 'pip install socialscan',
                'maigret': 'pip install maigret',
                'twint': 'Twitter scraping tool',
                'instaloader': 'pip install instaloader',
            },
            'domain_email': {
                'hunter.io': 'https://hunter.io/',
                'phonebook.cz': 'https://phonebook.cz/',
                'emailrep': 'https://emailrep.io/',
                'clearbit': 'https://clearbit.com/',
            },
            'geolocation': {
                'what3words': 'https://what3words.com/',
                'plus_codes': 'https://plus.codes/',
                'geohash': 'http://geohash.org/',
                'geospy': 'https://geospy.ai/',
                'picarta': 'https://picarta.ai/',
            },
            'breach_data': {
                'haveibeenpwned': 'https://haveibeenpwned.com/',
                'dehashed': 'https://dehashed.com/',
                'leakcheck': 'https://leakcheck.io/',
            },
            'osint_frameworks': {
                'osintframework': 'https://osintframework.com/',
                'intelx': 'https://intelx.io/',
                'maltego': 'https://www.maltego.com/',
                'spiderfoot': 'https://www.spiderfoot.net/',
            }
        }


class OSINTScanner:
    """OSINT and Geolocation analysis for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'coordinates': [],
            'locations': [],
            'metadata': {},
            'social_media': [],
            'domains': [],
            'emails': [],
            'ips': [],
            'phones': [],
            'usernames': [],
            'online_osint': {},
            'findings': []
        }
        self.online_osint = OnlineOSINT(config)
    
    def scan(self, target: str, online: bool = True) -> Dict:
        """Main scan method - analyzes file for OSINT data
        
        Args:
            target: File path or text to analyze
            online: Whether to use online OSINT tools (default: True)
        """
        if os.path.exists(target):
            # File-based analysis
            self.extract_gps_from_image(target)
            self.extract_metadata(target)
            self.analyze_strings_for_osint(target)
            self.decode_coordinates_from_file(target)
            
            # Online analysis if enabled
            if online and REQUESTS_AVAILABLE:
                self._run_online_osint_for_file(target)
        else:
            # Text-based analysis (could be username, email, IP, etc.)
            self._analyze_text_input(target, online)
        
        return self.results
    
    def _analyze_text_input(self, text: str, online: bool = True) -> None:
        """Analyze text input for OSINT (email, username, IP, domain, etc.)"""
        
        # Check if it's an email
        if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', text):
            self.results['emails'].append(text)
            if online and REQUESTS_AVAILABLE:
                email_info = self.online_osint.email_lookup(text)
                self.results['online_osint']['email'] = email_info
                self.results['findings'].append(f"📧 Email analyzed: {text}")
        
        # Check if it's an IP address
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text):
            self.results['ips'].append(text)
            if online and REQUESTS_AVAILABLE:
                ip_info = self.online_osint.ip_lookup(text)
                self.results['online_osint']['ip'] = ip_info
                self.results['findings'].append(f"🌐 IP analyzed: {text}")
        
        # Check if it's a domain
        elif re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', text):
            self.results['domains'].append(text)
            if online and REQUESTS_AVAILABLE:
                domain_info = self.online_osint.domain_lookup(text)
                self.results['online_osint']['domain'] = domain_info
                self.results['findings'].append(f"🔗 Domain analyzed: {text}")
        
        # Check if it's a phone number
        elif re.match(r'^[\d\s\-\+\(\)]{7,}$', text):
            self.results['phones'].append(text)
            phone_info = self.online_osint.phone_lookup(text)
            self.results['online_osint']['phone'] = phone_info
            self.results['findings'].append(f"📱 Phone analyzed: {text}")
        
        # Check if it's a What3Words address
        elif re.match(r'^[a-z]+\.[a-z]+\.[a-z]+$', text.lower()):
            if online and REQUESTS_AVAILABLE:
                w3w_info = self.online_osint.what3words_lookup(text)
                self.results['online_osint']['what3words'] = w3w_info
                self.results['findings'].append(f"🗺️ What3Words analyzed: {text}")
        
        # Treat as username
        else:
            self.results['usernames'].append(text)
            if online and REQUESTS_AVAILABLE:
                username_info = self.online_osint.social_media_osint(text)
                self.results['online_osint']['username'] = username_info
                self.results['findings'].append(f"👤 Username analyzed: {text}")
    
    def _run_online_osint_for_file(self, filepath: str) -> None:
        """Run online OSINT analysis on extracted data from file"""
        
        # Generate reverse image search URLs
        if filepath.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
            self.results['online_osint']['reverse_image'] = self.online_osint.reverse_image_search_urls(filepath)
            self.results['findings'].append("🖼️ Reverse image search URLs generated")
        
        # Lookup extracted emails
        for email in self.results.get('emails', [])[:5]:
            email_info = self.online_osint.email_lookup(email)
            self.results['online_osint'][f'email_{email}'] = email_info
        
        # Lookup extracted social media handles
        for sm in self.results.get('social_media', [])[:5]:
            handle = sm.get('handle', '')
            if handle:
                sm_info = self.online_osint.check_username(handle)
                self.results['online_osint'][f'username_{handle}'] = sm_info
        
        # Lookup extracted What3Words
        for finding in self.results.get('findings', []):
            if 'What3Words' in finding:
                match = re.search(r'([a-z]+\.[a-z]+\.[a-z]+)', finding)
                if match:
                    w3w_info = self.online_osint.what3words_lookup(match.group(1))
                    self.results['online_osint']['what3words'] = w3w_info
    
    def lookup_username(self, username: str) -> Dict:
        """Lookup a username across multiple platforms"""
        return self.online_osint.check_username(username)
    
    def lookup_email(self, email: str) -> Dict:
        """Lookup an email address"""
        return self.online_osint.email_lookup(email)
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup an IP address"""
        return self.online_osint.ip_lookup(ip)
    
    def lookup_domain(self, domain: str) -> Dict:
        """Lookup a domain"""
        return self.online_osint.domain_lookup(domain)
    
    def lookup_phone(self, phone: str) -> Dict:
        """Lookup a phone number"""
        return self.online_osint.phone_lookup(phone)
    
    def get_reverse_image_urls(self, image_path: str) -> Dict:
        """Get reverse image search URLs"""
        return self.online_osint.reverse_image_search_urls(image_path)
    
    def get_osint_resources(self) -> Dict:
        """Get comprehensive OSINT tools and resources"""
        return self.online_osint.get_osint_resources()
    
    def extract_gps_from_image(self, filepath: str) -> Dict:
        """Extract GPS coordinates from image EXIF data"""
        try:
            # Use exiftool for GPS extraction
            result = subprocess.run(
                ['exiftool', '-gps*', '-c', '%.6f', '-json', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                if data and len(data) > 0:
                    gps_data = data[0]
                    
                    # Look for GPS coordinates
                    lat = gps_data.get('GPSLatitude', '')
                    lon = gps_data.get('GPSLongitude', '')
                    
                    if lat and lon:
                        # Parse coordinates
                        lat_val = self._parse_gps_coordinate(str(lat))
                        lon_val = self._parse_gps_coordinate(str(lon))
                        
                        if lat_val and lon_val:
                            coord_info = {
                                'latitude': lat_val,
                                'longitude': lon_val,
                                'raw_lat': lat,
                                'raw_lon': lon,
                                'google_maps': f'https://maps.google.com/?q={lat_val},{lon_val}',
                                'source': 'EXIF GPS'
                            }
                            self.results['coordinates'].append(coord_info)
                            self.results['findings'].append(
                                f"🌍 GPS Found: {lat_val}, {lon_val} | Maps: {coord_info['google_maps']}"
                            )
                            return coord_info
        except Exception as e:
            pass
        
        return {}
    
    def _parse_gps_coordinate(self, coord_str: str) -> Optional[float]:
        """Parse GPS coordinate from various formats"""
        try:
            # Already a float
            if re.match(r'^-?\d+\.\d+$', coord_str.strip()):
                return float(coord_str)
            
            # DMS format: 40 deg 26' 46.56" N
            dms_pattern = r'(\d+)\s*(?:deg|°)\s*(\d+)\'\s*([\d.]+)"\s*([NSEW])?'
            match = re.search(dms_pattern, coord_str, re.IGNORECASE)
            if match:
                d, m, s, direction = match.groups()
                decimal = float(d) + float(m)/60 + float(s)/3600
                if direction and direction.upper() in ['S', 'W']:
                    decimal = -decimal
                return round(decimal, 6)
            
            # Decimal degrees with direction: 40.446 N
            dd_pattern = r'(-?\d+\.?\d*)\s*([NSEW])?'
            match = re.search(dd_pattern, coord_str, re.IGNORECASE)
            if match:
                value, direction = match.groups()
                decimal = float(value)
                if direction and direction.upper() in ['S', 'W']:
                    decimal = -decimal
                return round(decimal, 6)
                
        except:
            pass
        return None
    
    def extract_metadata(self, filepath: str) -> Dict:
        """Extract all metadata for OSINT analysis"""
        try:
            result = subprocess.run(
                ['exiftool', '-json', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                if data and len(data) > 0:
                    metadata = data[0]
                    
                    # Look for interesting OSINT fields
                    osint_fields = [
                        'Author', 'Creator', 'Artist', 'Copyright',
                        'Software', 'Camera', 'Make', 'Model',
                        'DateTimeOriginal', 'CreateDate', 'ModifyDate',
                        'Comment', 'UserComment', 'ImageDescription',
                        'OwnerName', 'SerialNumber', 'LensModel'
                    ]
                    
                    for field in osint_fields:
                        if field in metadata and metadata[field]:
                            self.results['metadata'][field] = metadata[field]
                    
                    # Check for hidden comments that might contain flags
                    for key, value in metadata.items():
                        if isinstance(value, str):
                            # Check for flag patterns
                            flag_patterns = [
                                r'digitalcyberhunt\{[^}]+\}',
                                r'DCH\{[^}]+\}',
                                r'flag\{[^}]+\}',
                                r'FLAG\{[^}]+\}',
                                r'CTF\{[^}]+\}'
                            ]
                            for pattern in flag_patterns:
                                matches = re.findall(pattern, value, re.IGNORECASE)
                                if matches:
                                    for m in matches:
                                        self.results['findings'].append(f"🚩 FLAG in {key}: {m}")
                    
                    return metadata
        except Exception as e:
            pass
        
        return {}
    
    def analyze_strings_for_osint(self, filepath: str) -> List[str]:
        """Extract strings and look for OSINT data"""
        try:
            result = subprocess.run(
                ['strings', '-n', '8', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                strings = result.stdout
                
                # Look for coordinates in strings
                coord_patterns = [
                    # Decimal degrees: 40.7128, -74.0060
                    r'(-?\d{1,3}\.\d{4,})[,\s]+(-?\d{1,3}\.\d{4,})',
                    # DMS: 40°26'46"N 74°0'21"W
                    r'(\d{1,3})°(\d{1,2})\'(\d{1,2}(?:\.\d+)?)"?([NS])\s*(\d{1,3})°(\d{1,2})\'(\d{1,2}(?:\.\d+)?)"?([EW])',
                    # Google Maps URL
                    r'maps\.google\.com/?\?q=(-?\d+\.?\d*),(-?\d+\.?\d*)',
                    # What3Words
                    r'what3words\.com/([a-z]+\.[a-z]+\.[a-z]+)',
                ]
                
                for pattern in coord_patterns:
                    matches = re.findall(pattern, strings, re.IGNORECASE)
                    for match in matches:
                        self.results['findings'].append(f"📍 Coordinate pattern found: {match}")
                
                # Look for social media handles
                social_patterns = {
                    'twitter': r'@([A-Za-z0-9_]{1,15})',
                    'instagram': r'instagram\.com/([A-Za-z0-9_.]+)',
                    'github': r'github\.com/([A-Za-z0-9-]+)',
                    'linkedin': r'linkedin\.com/in/([A-Za-z0-9-]+)',
                }
                
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, strings, re.IGNORECASE)
                    for m in matches:
                        if len(m) > 2 and m not in ['com', 'org', 'net']:
                            self.results['social_media'].append({
                                'platform': platform,
                                'handle': m
                            })
                
                # Look for email addresses
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', strings)
                if emails:
                    self.results['findings'].extend([f"📧 Email: {e}" for e in set(emails)])
                
                # Look for phone numbers
                phones = re.findall(r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', strings)
                if phones:
                    self.results['findings'].extend([f"📱 Phone: {p}" for p in set(phones)])
                
        except Exception as e:
            pass
        
        return self.results['findings']
    
    def decode_coordinates_from_file(self, filepath: str) -> List[Dict]:
        """Try to decode various coordinate formats from file content"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Try to decode as text
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = str(content)
            
            # What3Words detection
            w3w_pattern = r'([a-z]+\.[a-z]+\.[a-z]+)'
            w3w_matches = re.findall(w3w_pattern, text.lower())
            for match in w3w_matches:
                if len(match.split('.')) == 3:
                    words = match.split('.')
                    if all(len(w) >= 3 for w in words):
                        self.results['findings'].append(
                            f"🗺️ Possible What3Words: {match} (check: what3words.com/{match})"
                        )
            
            # Plus codes (Open Location Code)
            pluscode_pattern = r'[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,}'
            pluscode_matches = re.findall(pluscode_pattern, text.upper())
            for match in pluscode_matches:
                self.results['findings'].append(f"📌 Plus Code found: {match}")
            
            # Geohash
            geohash_pattern = r'\b[0-9bcdefghjkmnpqrstuvwxyz]{5,12}\b'
            # Only flag likely geohashes
            geohash_candidates = re.findall(geohash_pattern, text.lower())
            for gh in geohash_candidates[:5]:  # Limit to avoid false positives
                if self._is_likely_geohash(gh):
                    self.results['findings'].append(f"🔢 Possible Geohash: {gh}")
            
        except Exception as e:
            pass
        
        return self.results['coordinates']
    
    def _is_likely_geohash(self, s: str) -> bool:
        """Check if string is likely a geohash"""
        # Geohash characters
        valid_chars = set('0123456789bcdefghjkmnpqrstuvwxyz')
        if not all(c in valid_chars for c in s.lower()):
            return False
        # Reasonable length
        if len(s) < 5 or len(s) > 12:
            return False
        # Not a common word
        common_words = ['hello', 'world', 'password', 'secret', 'hidden']
        if s.lower() in common_words:
            return False
        return True
    
    def get_summary(self) -> str:
        """Get a formatted summary of OSINT findings"""
        summary = []
        summary.append("\n" + "="*60)
        summary.append("🔍 OSINT ANALYSIS RESULTS (Online + Offline)")
        summary.append("="*60)
        
        if self.results['coordinates']:
            summary.append("\n📍 GPS COORDINATES:")
            for coord in self.results['coordinates']:
                summary.append(f"   Lat: {coord['latitude']}, Lon: {coord['longitude']}")
                summary.append(f"   📱 {coord['google_maps']}")
        
        if self.results['metadata']:
            summary.append("\n📋 METADATA:")
            for key, value in self.results['metadata'].items():
                summary.append(f"   {key}: {value}")
        
        if self.results['social_media']:
            summary.append("\n👤 SOCIAL MEDIA:")
            for sm in self.results['social_media']:
                summary.append(f"   {sm['platform']}: {sm['handle']}")
        
        if self.results.get('emails'):
            summary.append("\n📧 EMAILS:")
            for email in self.results['emails']:
                summary.append(f"   {email}")
        
        if self.results.get('ips'):
            summary.append("\n🌐 IP ADDRESSES:")
            for ip in self.results['ips']:
                summary.append(f"   {ip}")
        
        if self.results.get('domains'):
            summary.append("\n🔗 DOMAINS:")
            for domain in self.results['domains']:
                summary.append(f"   {domain}")
        
        if self.results.get('usernames'):
            summary.append("\n👤 USERNAMES:")
            for username in self.results['usernames']:
                summary.append(f"   {username}")
        
        # Online OSINT results
        if self.results.get('online_osint'):
            summary.append("\n🌍 ONLINE OSINT RESULTS:")
            online = self.results['online_osint']
            
            if 'reverse_image' in online:
                summary.append("\n   🖼️ REVERSE IMAGE SEARCH:")
                for service, url in online['reverse_image'].items():
                    summary.append(f"      {service}: {url}")
            
            if 'username' in online:
                username_data = online['username']
                if 'platforms' in username_data and 'found' in username_data.get('platforms', {}):
                    found = username_data['platforms']['found']
                    summary.append(f"\n   👤 USERNAME FOUND ON {len(found)} PLATFORMS:")
                    for p in found[:10]:
                        summary.append(f"      ✓ {p['platform']}: {p['url']}")
            
            if 'ip' in online:
                ip_data = online['ip']
                if 'sources' in ip_data:
                    summary.append("\n   🌐 IP INTELLIGENCE:")
                    for source, data in ip_data['sources'].items():
                        if isinstance(data, dict):
                            city = data.get('city', data.get('regionName', 'Unknown'))
                            country = data.get('country', data.get('countryCode', ''))
                            summary.append(f"      {source}: {city}, {country}")
            
            if 'email' in online:
                email_data = online['email']
                if email_data.get('gravatar', {}).get('has_gravatar'):
                    summary.append(f"\n   📧 EMAIL HAS GRAVATAR: {email_data['gravatar']['url']}")
                if 'manual_checks' in email_data:
                    summary.append("   📧 MANUAL EMAIL CHECKS:")
                    for service, url in email_data['manual_checks'].items():
                        summary.append(f"      {service}: {url}")
            
            if 'domain' in online:
                domain_data = online['domain']
                if 'manual_checks' in domain_data:
                    summary.append("\n   🔗 DOMAIN INTELLIGENCE:")
                    for service, url in list(domain_data['manual_checks'].items())[:5]:
                        summary.append(f"      {service}: {url}")
            
            if 'what3words' in online:
                w3w = online['what3words']
                summary.append(f"\n   🗺️ WHAT3WORDS: {w3w.get('manual_url', '')}")
                if 'coordinates' in w3w:
                    summary.append(f"      Coordinates: {w3w['coordinates']}")
                    summary.append(f"      Google Maps: {w3w.get('google_maps', '')}")
        
        if self.results['findings']:
            summary.append("\n🎯 FINDINGS:")
            for finding in self.results['findings']:
                summary.append(f"   {finding}")
        
        if not any([self.results['coordinates'], self.results['metadata'], 
                   self.results['social_media'], self.results['findings'],
                   self.results.get('online_osint')]):
            summary.append("\n   No OSINT data found.")
        
        # Add OSINT resources hint
        summary.append("\n" + "-"*60)
        summary.append("💡 TIP: Use scanner.get_osint_resources() for more OSINT tools")
        summary.append("="*60 + "\n")
        return "\n".join(summary)


def main():
    """CLI interface for OSINT scanner"""
    import sys
    
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║           🔍 OSINT Scanner v3.0 - CTFHunter                  ║
╠══════════════════════════════════════════════════════════════╣
║  Usage: python osint_scanner.py <command> <target>           ║
╠══════════════════════════════════════════════════════════════╣
║  Commands:                                                   ║
║    scan <file>        - Full OSINT scan on file              ║
║    username <name>    - Check username across platforms      ║
║    email <email>      - Lookup email address                 ║
║    ip <address>       - IP address intelligence              ║
║    domain <domain>    - Domain reconnaissance                ║
║    phone <number>     - Phone number lookup                  ║
║    w3w <words>        - What3Words to coordinates            ║
║    image <file>       - Reverse image search URLs            ║
║    resources          - Show OSINT tools & resources         ║
╠══════════════════════════════════════════════════════════════╣
║  Examples:                                                   ║
║    python osint_scanner.py scan image.jpg                    ║
║    python osint_scanner.py username john_doe                 ║
║    python osint_scanner.py email test@example.com            ║
║    python osint_scanner.py ip 8.8.8.8                        ║
║    python osint_scanner.py domain example.com                ║
║    python osint_scanner.py w3w filled.count.soap             ║
╚══════════════════════════════════════════════════════════════╝
        """)
        sys.exit(1)
    
    scanner = OSINTScanner()
    command = sys.argv[1].lower()
    
    if command == 'scan' and len(sys.argv) > 2:
        results = scanner.scan(sys.argv[2])
        print(scanner.get_summary())
    
    elif command == 'username' and len(sys.argv) > 2:
        print(f"\n🔍 Checking username: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.lookup_username(sys.argv[2])
        if 'found' in results:
            print(f"\n✅ Found on {len(results['found'])} platforms:\n")
            for p in results['found']:
                print(f"  ✓ {p['platform']}: {p['url']}")
            print(f"\n❌ Not found on: {', '.join(results['not_found'][:10])}...")
    
    elif command == 'email' and len(sys.argv) > 2:
        print(f"\n📧 Looking up email: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.lookup_email(sys.argv[2])
        print(json.dumps(results, indent=2))
    
    elif command == 'ip' and len(sys.argv) > 2:
        print(f"\n🌐 Looking up IP: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.lookup_ip(sys.argv[2])
        for source, data in results.get('sources', {}).items():
            print(f"\n[{source}]")
            if isinstance(data, dict):
                for k, v in list(data.items())[:10]:
                    print(f"  {k}: {v}")
    
    elif command == 'domain' and len(sys.argv) > 2:
        print(f"\n🔗 Looking up domain: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.lookup_domain(sys.argv[2])
        print("\nManual check URLs:")
        for service, url in results.get('manual_checks', {}).items():
            print(f"  {service}: {url}")
    
    elif command == 'phone' and len(sys.argv) > 2:
        print(f"\n📱 Looking up phone: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.lookup_phone(sys.argv[2])
        print(json.dumps(results, indent=2))
    
    elif command == 'w3w' and len(sys.argv) > 2:
        print(f"\n🗺️ Looking up What3Words: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.online_osint.what3words_lookup(sys.argv[2])
        print(f"URL: {results.get('manual_url', '')}")
        if 'coordinates' in results:
            print(f"Coordinates: {results['coordinates']}")
            print(f"Google Maps: {results.get('google_maps', '')}")
    
    elif command == 'image' and len(sys.argv) > 2:
        print(f"\n🖼️ Reverse image search URLs for: {sys.argv[2]}")
        print("-" * 50)
        results = scanner.get_reverse_image_urls(sys.argv[2])
        for service, url in results.items():
            print(f"  {service}: {url}")
    
    elif command == 'resources':
        print("\n📚 OSINT TOOLS & RESOURCES")
        print("=" * 60)
        resources = scanner.get_osint_resources()
        for category, tools in resources.items():
            print(f"\n🔹 {category.upper().replace('_', ' ')}:")
            for name, url in tools.items():
                print(f"   {name}: {url}")
    
    else:
        # Try auto-detect
        target = sys.argv[1] if len(sys.argv) > 1 else ''
        if target:
            print(f"\n🔍 Auto-analyzing: {target}")
            results = scanner.scan(target)
            print(scanner.get_summary())


if __name__ == "__main__":
    main()
