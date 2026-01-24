
import re

def strings(path):
    with open(path, 'rb') as f:
        data = f.read()
    
    # ASCII strings > 6 chars
    # Include space, tab, newline
    chars = b'[ -~\t\r\n]{6,}'
    matches = re.findall(chars, data)
    
    print(f"Found {len(matches)} strings.")
    for m in matches:
        s = m.decode()
        if 'pico' in s.lower() or 'flag' in s.lower() or 'ctf' in s.lower():
            print(f"FOUND: {s}")

if __name__ == '__main__':
    strings("decoded_image.png")
