
from PIL import Image

def check_data(data, name):
    # Check headers
    sigs = {
        b'PK': 'ZIP',
        b'7z': '7z',
        b'\x7fELF': 'ELF',
        b'\x89PNG': 'PNG',
        b'%PDF': 'PDF'
    }
    found_sig = False
    for s, n in sigs.items():
        if data.startswith(s):
            print(f"[FOUND] {n} header in {name}")
            found_sig = True
    
    # Check strings
    try:
        text = data.decode('utf-8', 'ignore')
        for pat in ['pico', 'flag', 'ctf']:
            idx = text.lower().find(pat)
            if idx != -1:
                print(f"[FOUND] Text '{pat}' in {name} at {idx}: {text[idx:idx+40]}")
    except: pass

def run():
    img = Image.open("decoded_image.png")
    pixels = img.load()
    w, h = img.size
    print(f"Image: {w}x{h} {img.mode}")
    
    # Modes to check
    # (Name, channels_order, bit)
    modes = [
        ("BGR_0", [2, 1, 0], 0),
        ("RGB_1", [0, 1, 2], 1),
        ("R_1", [0], 1),
        ("G_1", [1], 1),
        ("B_1", [2], 1),
        ("BGR_1", [2, 1, 0], 1),
        # Column major? (XY) - zsteg checks 'xy'
        # Just extracting column-wise for RGB_0
    ]
    
    for name, chans, bit in modes:
        print(f"Checking {name}...")
        data = bytearray()
        curr = 0
        bits = 0
        
        for y in range(h):
            for x in range(w):
                p = pixels[x, y]
                vals = [p[i] for i in chans]
                for v in vals:
                    curr = (curr << 1) | ((v >> bit) & 1)
                    bits += 1
                    if bits == 8:
                        data.append(curr)
                        curr = 0
                        bits = 0
        
        check_data(data, name)
        
    # Check Column Major RGB_0
    print("Checking RGB_0 XY (Column Major)...")
    data_xy = bytearray()
    curr = 0
    bits = 0
    for x in range(w):
        for y in range(h):
            p = pixels[x, y]
            vals = [p[0], p[1], p[2]]
            for v in vals:
                curr = (curr << 1) | (v & 1)
                bits += 1
                if bits == 8:
                    data_xy.append(curr)
                    curr = 0
                    bits = 0
    check_data(data_xy, "RGB_0_XY")

if __name__ == '__main__':
    run()
