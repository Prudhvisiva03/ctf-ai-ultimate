#!/usr/bin/env python3
"""
Crypto Analyzer - Auto-detect and decode common encodings
Supports: Base64, Base32, Hex, ROT13, Caesar, URL encoding, and more
"""

import re
import base64
import binascii
import urllib.parse
from collections import Counter


def detect_encoding(text):
    """Detect what encoding the text might be"""
    encodings = []
    
    # Base64 detection
    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text.strip()) and len(text) % 4 == 0:
        encodings.append('base64')
    
    # Base32 detection
    if re.match(r'^[A-Z2-7]+=*$', text.strip().upper()) and len(text) % 8 == 0:
        encodings.append('base32')
    
    # Hex detection
    if re.match(r'^[0-9a-fA-F\s]+$', text.strip()):
        encodings.append('hex')
    
    # URL encoding detection
    if '%' in text and re.search(r'%[0-9a-fA-F]{2}', text):
        encodings.append('url')
    
    # Binary detection
    if re.match(r'^[01\s]+$', text.strip()):
        encodings.append('binary')
    
    # ROT13/Caesar (high frequency of shifted letters)
    if text.isalpha():
        encodings.append('rot13_or_caesar')
    
    # Morse code detection
    if re.match(r'^[\.\-\s/]+$', text.strip()):
        encodings.append('morse')
    
    return encodings


def try_base64(text):
    """Try to decode Base64"""
    try:
        decoded = base64.b64decode(text.strip())
        # Check if result is printable
        if all(c < 128 for c in decoded):
            return decoded.decode('utf-8', errors='ignore')
    except:
        pass
    return None


def try_base32(text):
    """Try to decode Base32"""
    try:
        decoded = base64.b32decode(text.strip().upper())
        if all(c < 128 for c in decoded):
            return decoded.decode('utf-8', errors='ignore')
    except:
        pass
    return None


def try_hex(text):
    """Try to decode Hex"""
    try:
        # Remove spaces and newlines
        clean = text.replace(' ', '').replace('\n', '').replace('\r', '')
        decoded = bytes.fromhex(clean)
        if all(c < 128 for c in decoded):
            return decoded.decode('utf-8', errors='ignore')
    except:
        pass
    return None


def try_url(text):
    """Try to decode URL encoding"""
    try:
        return urllib.parse.unquote(text)
    except:
        pass
    return None


def try_binary(text):
    """Try to decode binary"""
    try:
        # Remove spaces
        clean = text.replace(' ', '').replace('\n', '').replace('\r', '')
        # Split into 8-bit chunks
        chars = [clean[i:i+8] for i in range(0, len(clean), 8)]
        decoded = ''.join([chr(int(c, 2)) for c in chars if len(c) == 8])
        return decoded
    except:
        pass
    return None


def try_rot13(text):
    """Try ROT13"""
    import codecs
    return codecs.decode(text, 'rot_13')


def try_caesar(text, shift=None):
    """Try Caesar cipher with all shifts or specific shift"""
    results = []
    
    shifts_to_try = [shift] if shift else range(1, 26)
    
    for s in shifts_to_try:
        decoded = ''
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                decoded += chr((ord(char) - base + s) % 26 + base)
            else:
                decoded += char
        
        # Check if result looks like English
        if shift is None and looks_like_english(decoded):
            results.append((s, decoded))
        elif shift is not None:
            return decoded
    
    return results


def looks_like_english(text):
    """Simple heuristic to check if text looks like English"""
    common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'flag', 'ctf']
    text_lower = text.lower()
    matches = sum(1 for word in common_words if word in text_lower)
    return matches >= 2


def try_morse(text):
    """Try to decode Morse code"""
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9'
    }
    
    try:
        # Split by spaces or slashes
        words = text.split(' / ') if ' / ' in text else [text]
        decoded_words = []
        
        for word in words:
            letters = word.split()
            decoded = ''.join([morse_dict.get(letter, '?') for letter in letters])
            decoded_words.append(decoded)
        
        return ' '.join(decoded_words)
    except:
        pass
    return None


def analyze_crypto(text):
    """Analyze and try to decode text"""
    results = {
        'original': text[:100] + '...' if len(text) > 100 else text,
        'detected_encodings': [],
        'decoded_results': []
    }
    
    # Detect possible encodings
    encodings = detect_encoding(text)
    results['detected_encodings'] = encodings
    
    # Try each encoding
    if 'base64' in encodings:
        decoded = try_base64(text)
        if decoded:
            results['decoded_results'].append({
                'method': 'Base64',
                'result': decoded,
                'success': True
            })
    
    if 'base32' in encodings:
        decoded = try_base32(text)
        if decoded:
            results['decoded_results'].append({
                'method': 'Base32',
                'result': decoded,
                'success': True
            })
    
    if 'hex' in encodings:
        decoded = try_hex(text)
        if decoded:
            results['decoded_results'].append({
                'method': 'Hexadecimal',
                'result': decoded,
                'success': True
            })
    
    if 'url' in encodings:
        decoded = try_url(text)
        if decoded and decoded != text:
            results['decoded_results'].append({
                'method': 'URL Encoding',
                'result': decoded,
                'success': True
            })
    
    if 'binary' in encodings:
        decoded = try_binary(text)
        if decoded:
            results['decoded_results'].append({
                'method': 'Binary',
                'result': decoded,
                'success': True
            })
    
    if 'rot13_or_caesar' in encodings:
        # Try ROT13
        decoded = try_rot13(text)
        results['decoded_results'].append({
            'method': 'ROT13',
            'result': decoded,
            'success': True
        })
        
        # Try Caesar with all shifts
        caesar_results = try_caesar(text)
        if caesar_results:
            for shift, decoded in caesar_results[:3]:  # Top 3 results
                results['decoded_results'].append({
                    'method': f'Caesar (shift {shift})',
                    'result': decoded,
                    'success': True
                })
    
    if 'morse' in encodings:
        decoded = try_morse(text)
        if decoded:
            results['decoded_results'].append({
                'method': 'Morse Code',
                'result': decoded,
                'success': True
            })
    
    return results


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python3 crypto_analyzer.py <text_or_file>")
        print("Example: python3 crypto_analyzer.py 'cGljb0NURntoZWxsb30='")
        sys.exit(1)
    
    input_text = sys.argv[1]
    
    # Check if it's a file
    import os
    if os.path.isfile(input_text):
        with open(input_text, 'r', encoding='utf-8', errors='ignore') as f:
            input_text = f.read()
    
    print(f"[*] Analyzing crypto/encoding...")
    print("")
    
    results = analyze_crypto(input_text)
    
    if results['detected_encodings']:
        print(f"[+] Detected encoding(s): {', '.join(results['detected_encodings'])}")
        print("")
    
    if results['decoded_results']:
        print(f"[+] Successfully decoded {len(results['decoded_results'])} variant(s):")
        print("")
        
        for i, result in enumerate(results['decoded_results'], 1):
            print(f"{i}. {result['method']}:")
            print(f"   {result['result']}")
            print("")
    else:
        print("[-] Could not decode - might be encrypted or unknown encoding")
        print("[!] HINT: Try CyberChef or dcode.fr for advanced decoding")
    
    # Save results
    os.makedirs("output", exist_ok=True)
    with open("output/crypto_analysis.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print("[+] Full analysis saved to: output/crypto_analysis.json")
