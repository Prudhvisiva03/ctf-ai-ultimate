
from PIL import Image
import re

def extract(path):
    img = Image.open(path)
    print("Info:", img.info)
    
    pixels = img.load()
    w, h = img.size
    
    # Extract RGB LSB
    data = bytearray()
    curr = 0
    bits = 0
    
    LIMIT = 1000000 # 1MB is enough to find flag usually
    
    print("Extracting RGB LSB strings...")
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            for v in [r, g, b]:
                curr = (curr << 1) | (v & 1)
                bits += 1
                if bits == 8:
                    data.append(curr)
                    curr = 0
                    bits = 0
            if len(data) > LIMIT: break
        if len(data) > LIMIT: break
    
    # Strings
    try:
        # Decode ignoring errors
        text = data.decode('latin-1') # Ensure 1-to-1 mapping roughly
        # Find printable
        # Regex for long strings
        matches = re.findall(r'[a-zA-Z0-9_{}]{10,}', text)
        for m in matches:
            if 'pico' in m or 'flag' in m or 'CTF' in m:
                print(f"FOUND: {m}")
            # Also print if it looks flag-like
            if '{' in m and '}' in m:
                print(f"POTENTIAL: {m}")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    extract("decoded_image.png")
