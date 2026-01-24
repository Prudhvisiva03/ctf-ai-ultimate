
from PIL import Image
import re

def check_str(data, name):
    try:
        # UTF-16
        t = data.decode('utf-16', 'ignore')
        if 'pico' in t.lower() or 'flag' in t.lower(): print(f"[{name} UTF16] FOUND FLAG")
    except: pass
    try:
        # UTF-8
        t = data.decode('utf-8', 'ignore')
        if 'pico' in t.lower() or 'flag' in t.lower(): print(f"[{name} UTF8] FOUND FLAG: {t[t.lower().find('pico'):t.lower().find('pico')+40]}")
    except: pass

def run():
    img = Image.open("decoded_image.png")
    pixels = img.load()
    w, h = img.size
    
    # Modes
    modes = [('RGB_0', [0,1,2], 0), ('RGB_1', [0,1,2], 1), ('RGB_2', [0,1,2], 2)]
    
    for name, chans, bit in modes:
        print(f"Checking {name}...")
        data = bytearray()
        data_inv = bytearray()
        
        curr = 0; curr_inv = 0
        bits = 0
        
        for y in range(h):
            for x in range(w):
                p = pixels[x, y] # RGB
                vals = [p[i] for i in chans]
                for v in vals:
                    b = (v >> bit) & 1
                    curr = (curr << 1) | b
                    curr_inv = (curr_inv << 1) | (1 - b)
                    bits += 1
                    if bits == 8:
                        data.append(curr)
                        data_inv.append(curr_inv)
                        curr = 0; curr_inv = 0; bits = 0
        
        check_str(data, name)
        check_str(data_inv, name + "_INV")

if __name__ == '__main__':
    run()
