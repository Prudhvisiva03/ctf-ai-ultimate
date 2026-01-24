
from PIL import Image

def check_sig(data, name):
    sig = data[:10]
    print(f"[{name}] Start: {sig.hex()} | {sig}")
    
    signatures = {
        b'PK': 'ZIP',
        b'%PDF': 'PDF',
        b'\x7fELF': 'ELF',
        b'\x89PNG': 'PNG',
        b'7z': '7z'
    }
    
    for s, t in signatures.items():
        if data.startswith(s):
            print(f"!!! FOUND {t} header in {name} !!!")

    # Check for flag text
    try:
        # Check first 5000 bytes for text patterns? Or whole file?
        # Text search is fast.
        s = data.decode('utf-8', 'ignore')
        for kw in ['pico', 'flag', 'ctf']:
            idx = s.lower().find(kw)
            if idx != -1:
                print(f"!!! FOUND '{kw}' in {name} context: {s[max(0, idx-20):idx+50]}")
    except: pass

def extract_all_lsb(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    w, h = img.size
    
    # Initialize buffers
    data_r = bytearray()
    data_g = bytearray()
    data_b = bytearray()
    data_rgb = bytearray()
    
    # State
    curr_r, bit_r = 0, 0
    curr_g, bit_g = 0, 0
    curr_b, bit_b = 0, 0
    
    curr_rgb, bit_rgb = 0, 0
    
    print("Extracting LSBs...")
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            
            # R
            curr_r = (curr_r << 1) | (r & 1)
            bit_r += 1
            if bit_r == 8:
                data_r.append(curr_r)
                curr_r, bit_r = 0, 0
                
            # G
            curr_g = (curr_g << 1) | (g & 1)
            bit_g += 1
            if bit_g == 8:
                data_g.append(curr_g)
                curr_g, bit_g = 0, 0
                
            # B
            curr_b = (curr_b << 1) | (b & 1)
            bit_b += 1
            if bit_b == 8:
                data_b.append(curr_b)
                curr_b, bit_b = 0, 0
                
            # RGB
            for v in [r, g, b]:
                curr_rgb = (curr_rgb << 1) | (v & 1)
                bit_rgb += 1
                if bit_rgb == 8:
                    data_rgb.append(curr_rgb)
                    curr_rgb, bit_rgb = 0, 0
                    
    print("Checking results...")
    check_sig(data_r, "Red LSB")
    check_sig(data_g, "Green LSB")
    check_sig(data_b, "Blue LSB")
    check_sig(data_rgb, "RGB LSB")

if __name__ == '__main__':
    extract_all_lsb("decoded_image.png")
