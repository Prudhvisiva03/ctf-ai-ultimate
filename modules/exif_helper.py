#!/usr/bin/env python3
"""
EXIF Helper - Extract and decode Base64 from EXIF metadata
"""

import re
import base64
import subprocess
import os

def extract_base64_from_exif(filepath):
    """
    Extract potential Base64 strings from EXIF metadata
    Returns list of (field_name, decoded_value) tuples
    """
    results = []
    
    try:
        # Run exiftool to get all metadata
        result = subprocess.run(
            ['exiftool', filepath],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return results
        
        # Look for Base64-like strings in the output
        # Base64 pattern: alphanumeric + / + = padding
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        for line in result.stdout.split('\n'):
            if ':' not in line:
                continue
                
            field, value = line.split(':', 1)
            field = field.strip()
            value = value.strip()
            
            # Check if value looks like Base64
            matches = re.findall(base64_pattern, value)
            for match in matches:
                try:
                    # Try to decode
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    
                    # Only keep if it decodes to printable ASCII
                    if decoded and all(c.isprintable() or c in '\n\r\t' for c in decoded):
                        results.append({
                            'field': field,
                            'encoded': match,
                            'decoded': decoded,
                            'hint': f"Found Base64 in {field}: {decoded}"
                        })
                        
                        # Try double-decode if it still looks like Base64
                        if re.match(base64_pattern, decoded):
                            try:
                                double_decoded = base64.b64decode(decoded).decode('utf-8', errors='ignore')
                                if double_decoded and all(c.isprintable() or c in '\n\r\t' for c in double_decoded):
                                    results.append({
                                        'field': field,
                                        'encoded': decoded,
                                        'decoded': double_decoded,
                                        'hint': f"Found double-encoded Base64 in {field}: {double_decoded}"
                                    })
                            except:
                                pass
                                
                except Exception:
                    continue
    
    except Exception as e:
        print(f"[!] Error extracting EXIF: {e}")
    
    return results


def try_steghide_with_passwords(filepath, passwords, output_dir="output"):
    """
    Try steghide extraction with a list of passwords
    Returns (success, extracted_file, password_used)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    for password in passwords:
        try:
            # Try extraction
            result = subprocess.run(
                ['steghide', 'extract', '-sf', filepath, '-p', password, '-f'],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=output_dir
            )
            
            # Check if successful
            if result.returncode == 0 or 'wrote extracted data' in result.stderr.lower():
                # Find what was extracted
                for line in result.stderr.split('\n'):
                    if 'wrote extracted data to' in line.lower():
                        extracted = line.split('"')[1] if '"' in line else None
                        return True, extracted, password
                        
                return True, None, password
                
        except Exception as e:
            continue
    
    return False, None, None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 exif_helper.py <image_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    print(f"[*] Analyzing EXIF metadata: {filepath}")
    results = extract_base64_from_exif(filepath)
    
    if results:
        print(f"[+] Found {len(results)} Base64 strings in EXIF:")
        passwords = []
        for r in results:
            print(f"    {r['hint']}")
            passwords.append(r['decoded'])
        
        print(f"\n[*] Trying steghide with {len(passwords)} passwords...")
        success, extracted, password = try_steghide_with_passwords(filepath, passwords)
        
        if success:
            print(f"[+] SUCCESS! Extracted with password: {password}")
            if extracted:
                print(f"[+] Extracted file: {extracted}")
        else:
            print(f"[-] No successful extraction")
            print(f"[!] HINT: Try these passwords manually:")
            for pwd in passwords:
                print(f"    steghide extract -sf {filepath} -p '{pwd}'")
    else:
        print("[-] No Base64 strings found in EXIF")
