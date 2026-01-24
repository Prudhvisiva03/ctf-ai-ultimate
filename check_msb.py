
from PIL import Image

def check_data(data, name):
    # Check headers
    sigs = {b'PK': 'ZIP', b'7z': '7z', b'\x7fELF': 'ELF', b'\x89PNG': 'PNG', b'%PDF': 'PDF'}
    for s, t in sigs.items():
        if data.startswith(s): print(f"!!! FOUND {t} header in {name}")
    try:
        text = data.decode('utf-8', 'ignore')
        for kw in ['pico', 'flag', 'ctf']:
            idx = text.lower().find(kw)
            if idx != -1: print(f"!!! FOUND '{kw}' in {name}: {text[idx:idx+40]}")
    except: pass

def run():
    img = Image.open("decoded_image.png")
    pixels = img.load()
    w, h = img.size
    print(f"Checking MSB (Bit 7) for {w}x{h}...")
    
    # Modes: R, G, B, RGB
    # We extract bit 7.
    modes = [('R_7', [0]), ('G_7', [1]), ('B_7', [2]), ('RGB_7', [0,1,2])]
    
    for name, chans in modes:
        data = bytearray()
        curr = 0
        bits = 0
        for y in range(h):
            for x in range(w):
                p = pixels[x,y]
                vals = [p[i] for i in chans]
                for v in vals:
                    # Bit 7
                    curr = (curr << 1) | ((v >> 7) & 1)
                    bits += 1
                    if bits == 8:
                        data.append(curr)
                        curr = 0
                        bits = 0
        check_data(data, name)

if __name__ == '__main__':
    run()
