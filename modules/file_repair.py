#!/usr/bin/env python3
"""
File Repair Module - Detect and fix corrupted file headers
Common in CTF challenges where file magic bytes are modified
"""

import os
import shutil

# Common file signatures (magic bytes)
FILE_SIGNATURES = {
    'PNG': {
        'signature': b'\x89PNG\r\n\x1a\n',
        'offset': 0,
        'extension': '.png'
    },
    'JPEG': {
        'signature': b'\xff\xd8\xff',
        'offset': 0,
        'extension': '.jpg'
    },
    'GIF87a': {
        'signature': b'GIF87a',
        'offset': 0,
        'extension': '.gif'
    },
    'GIF89a': {
        'signature': b'GIF89a',
        'offset': 0,
        'extension': '.gif'
    },
    'PDF': {
        'signature': b'%PDF',
        'offset': 0,
        'extension': '.pdf'
    },
    'ZIP': {
        'signature': b'PK\x03\x04',
        'offset': 0,
        'extension': '.zip'
    },
    'RAR': {
        'signature': b'Rar!\x1a\x07',
        'offset': 0,
        'extension': '.rar'
    },
    'BMP': {
        'signature': b'BM',
        'offset': 0,
        'extension': '.bmp'
    },
    'ELF': {
        'signature': b'\x7fELF',
        'offset': 0,
        'extension': ''
    },
    'PE': {
        'signature': b'MZ',
        'offset': 0,
        'extension': '.exe'
    }
}


def analyze_file_header(filepath):
    """
    Analyze file header and detect corruption
    Returns: (is_corrupted, detected_type, suggestions)
    """
    with open(filepath, 'rb') as f:
        header = f.read(512)  # Read first 512 bytes
    
    results = {
        'is_corrupted': False,
        'detected_type': None,
        'current_header': header[:16].hex(),
        'suggestions': []
    }
    
    # Check if header matches any known signature
    for file_type, info in FILE_SIGNATURES.items():
        sig = info['signature']
        offset = info['offset']
        
        if header[offset:offset+len(sig)] == sig:
            results['detected_type'] = file_type
            results['is_corrupted'] = False
            return results
    
    # Header doesn't match - likely corrupted
    results['is_corrupted'] = True
    
    # Try to detect what it might be based on partial matches or content
    # Check for partial PNG signature
    if b'PNG' in header[:20]:
        results['suggestions'].append({
            'type': 'PNG',
            'confidence': 'high',
            'reason': 'Found PNG marker in header',
            'fix': 'Replace first 8 bytes with: 89 50 4E 47 0D 0A 1A 0A'
        })
    
    # Check for JPEG markers
    if b'\xff\xd8' in header[:10] or b'JFIF' in header[:20] or b'Exif' in header[:20]:
        results['suggestions'].append({
            'type': 'JPEG',
            'confidence': 'high',
            'reason': 'Found JPEG markers in header',
            'fix': 'Replace first 3 bytes with: FF D8 FF'
        })
    
    # Check for GIF
    if b'GIF' in header[:10]:
        results['suggestions'].append({
            'type': 'GIF',
            'confidence': 'high',
            'reason': 'Found GIF marker',
            'fix': 'Replace first 6 bytes with: 47 49 46 38 39 61 (GIF89a)'
        })
    
    # Check for PDF
    if b'PDF' in header[:20] or b'%PDF' in header[:20]:
        results['suggestions'].append({
            'type': 'PDF',
            'confidence': 'high',
            'reason': 'Found PDF marker',
            'fix': 'Replace first 4 bytes with: 25 50 44 46 (%PDF)'
        })
    
    # Check for ZIP (PK header)
    if b'PK' in header[:10]:
        results['suggestions'].append({
            'type': 'ZIP',
            'confidence': 'high',
            'reason': 'Found PK marker',
            'fix': 'Replace first 4 bytes with: 50 4B 03 04'
        })
    
    return results


def repair_file(filepath, file_type, output_dir='output'):
    """
    Attempt to repair file by fixing the header
    Returns: (success, repaired_filepath)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    if file_type not in FILE_SIGNATURES:
        return False, None
    
    sig_info = FILE_SIGNATURES[file_type]
    correct_signature = sig_info['signature']
    offset = sig_info['offset']
    extension = sig_info['extension']
    
    # Read original file
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Replace header
    repaired_data = correct_signature + data[offset + len(correct_signature):]
    
    # Save repaired file
    base_name = os.path.basename(filepath)
    repaired_name = f"{base_name}_repaired{extension}"
    repaired_path = os.path.join(output_dir, repaired_name)
    
    with open(repaired_path, 'wb') as f:
        f.write(repaired_data)
    
    return True, repaired_path


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 file_repair.py <file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    print(f"[*] Analyzing file header: {filepath}")
    print("")
    
    results = analyze_file_header(filepath)
    
    print(f"[+] Current header: {results['current_header']}")
    print("")
    
    if not results['is_corrupted']:
        print(f"[+] File appears valid: {results['detected_type']}")
    else:
        print("[!] File header appears CORRUPTED")
        print("")
        
        if results['suggestions']:
            print(f"[+] Found {len(results['suggestions'])} possible file type(s):")
            print("")
            
            for i, suggestion in enumerate(results['suggestions'], 1):
                print(f"{i}. {suggestion['type']} (confidence: {suggestion['confidence']})")
                print(f"   Reason: {suggestion['reason']}")
                print(f"   Fix: {suggestion['fix']}")
                print("")
            
            # Auto-repair the most likely type
            best_suggestion = results['suggestions'][0]
            print(f"[*] Attempting auto-repair as {best_suggestion['type']}...")
            
            success, repaired_path = repair_file(filepath, best_suggestion['type'])
            
            if success:
                print(f"[+] ✅ Repaired file saved to: {repaired_path}")
                print(f"[!] HINT: Open the repaired file to find the flag!")
            else:
                print(f"[-] Auto-repair failed")
        else:
            print("[-] Could not determine file type")
            print("[!] HINT: Try manually inspecting with 'xxd' or hex editor")
