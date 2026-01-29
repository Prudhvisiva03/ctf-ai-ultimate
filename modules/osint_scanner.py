#!/usr/bin/env python3
"""
OSINT & Geolocation Scanner - For Digital Cyberhunt CTF
Supports: GPS extraction, image geolocation, metadata analysis, coordinate decoding
Author: Prudhvi (CTFHunter)
Version: 2.1.0
"""

import re
import os
import subprocess
import json
import math
from typing import Dict, List, Optional, Any


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
            'findings': []
        }
    
    def scan(self, target: str) -> Dict:
        """Main scan method - analyzes file for OSINT data"""
        if not os.path.exists(target):
            return {'error': f'File not found: {target}'}
        
        # Run all OSINT extractions
        self.extract_gps_from_image(target)
        self.extract_metadata(target)
        self.analyze_strings_for_osint(target)
        self.decode_coordinates_from_file(target)
        
        return self.results
    
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
        summary.append("\n" + "="*50)
        summary.append("🔍 OSINT ANALYSIS RESULTS")
        summary.append("="*50)
        
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
        
        if self.results['findings']:
            summary.append("\n🎯 FINDINGS:")
            for finding in self.results['findings']:
                summary.append(f"   {finding}")
        
        if not any([self.results['coordinates'], self.results['metadata'], 
                   self.results['social_media'], self.results['findings']]):
            summary.append("\n   No OSINT data found.")
        
        summary.append("="*50 + "\n")
        return "\n".join(summary)


def main():
    """CLI interface for OSINT scanner"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python osint_scanner.py <file>")
        print("\nOSINT Scanner - Extract geolocation & metadata for CTF")
        sys.exit(1)
    
    scanner = OSINTScanner()
    results = scanner.scan(sys.argv[1])
    print(scanner.get_summary())


if __name__ == "__main__":
    main()
