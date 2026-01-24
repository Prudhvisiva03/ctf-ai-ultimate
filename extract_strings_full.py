
from PIL import Image
import re

def check(data, name):
    try:
        # Latin-1 to keep bytes
        text = data.decode('latin-1')
        matches = re.findall(r'picoCTF\{[^}]+\}', text)
        if matches:
            print(f"!!! FOUND FLAG in {name}: {matches[0]}")
            return True
        matches_flag = re.findall(r'flag\{[^}]+\}', text)
        if matches_flag:
            print(f"!!! FOUND FLAG in {name}: {matches_flag[0]}")
            return True
    except: pass
    return False

def extract(path):
    img = Image.open(path)
    pixels = img.load()
    w, h = img.size
    print(f"Scanning full {w}x{h} ({img.mode})...")
    
    # Modes
    # RGB, BGR, R, G, B
    tasks = [
        ('RGB', [0,1,2]),
        ('BGR', [2,1,0]),
        ('R', [0]),
        ('G', [1]),
        ('B', [2])
    ]
    
    for name, chans in tasks:
        data = bytearray()
        curr = 0
        bits = 0
        
        # Iterate all pixels
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
        
        if check(data, name):
            print("Done.")
            return

    print("Nothing found in full scan.")

if __name__ == '__main__':
    extract("decoded_image.png")
