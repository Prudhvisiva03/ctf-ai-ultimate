
from PIL import Image

def check(data, name):
    sigs = {b'PK': 'ZIP', b'7z': '7z', b'\x7fELF': 'ELF', b'\x89PNG': 'PNG', b'%PDF': 'PDF'}
    for s, t in sigs.items():
        if data.startswith(s): print(f"!!! FOUND {t} in {name} !!!")
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
    print(f"Checking Little Endian LSB for {w}x{h}...")
    
    # Check RGB and BGR
    # LE: bits fill from LSB to MSB (0, 1, 2...7)
    modes = [('RGB_LE', [0,1,2]), ('BGR_LE', [2,1,0]), ('R_LE', [0]), ('G_LE', [1]), ('B_LE', [2])]
    
    for name, chans in modes:
        data = bytearray()
        curr = 0
        bits = 0
        for y in range(h):
            for x in range(w):
                p = pixels[x, y]
                vals = [p[i] for i in chans]
                for v in vals:
                    b = v & 1
                    # LE packing: bit goes to position 'bits'
                    curr |= (b << bits)
                    bits += 1
                    if bits == 8:
                        data.append(curr)
                        curr = 0
                        bits = 0
        check(data, name)

if __name__ == '__main__':
    run()
