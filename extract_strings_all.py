
from PIL import Image
import re

def check_strings(data, name):
    try:
        text = data.decode('latin-1')
        matches = re.findall(r'[a-zA-Z0-9_{}]{10,}', text)
        for m in matches:
            if 'pico' in m or 'flag' in m or 'CTF' in m:
                print(f"[{name}] FOUND: {m}")
            if '{' in m and '}' in m:
                print(f"[{name}] POTENTIAL: {m}")
    except: pass

def extract(path):
    img = Image.open(path)
    pixels = img.load()
    w, h = img.size
    
    # buffers
    # RGB, R, G, B
    modes = [('RGB', [0,1,2]), ('R', [0]), ('G', [1]), ('B', [2])]
    
    for name, chans in modes:
        print(f"Scanning {name}...")
        data = bytearray()
        curr = 0
        bits = 0
        for y in range(h):
            for x in range(w):
                p = pixels[x, y]
                vals = [p[i] for i in chans]
                for v in vals:
                    curr = (curr << 1) | (v & 1)
                    bits += 1
                    if bits == 8:
                        data.append(curr)
                        curr = 0
                        bits = 0
            if len(data) > 200000: break # Check first 200k bytes
        
        check_strings(data, name)

if __name__ == '__main__':
    extract("decoded_image.png")
