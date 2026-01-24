
from PIL import Image

def get_lsb_bytes(pixels, width, height, channels, bit=0):
    data = bytearray()
    curr = 0
    count = 0
    # Sample first 2000 pixels
    limit = 2000
    
    for y in range(height):
        for x in range(width):
            p = pixels[x,y]
            vals = [p[i] for i in channels]
            for v in vals:
                b = (v >> bit) & 1
                curr = (curr << 1) | b
                count += 1
                if count == 8:
                    data.append(curr)
                    curr = 0
                    count = 0
            if len(data) >= 100: return data
    return data

if __name__ == '__main__':
    img = Image.open("decoded_image.png")
    pixels = img.load()
    w, h = img.size
    print(f"Modes check for {img.mode}:")
    
    tasks = [
        ('RGB LSB', [0,1,2], 0),
        ('BGR LSB', [2,1,0], 0),
        ('RGBA LSB', [0,1,2,3], 0),
        ('ABGR LSB', [3,2,1,0], 0),
        ('R LSB', [0], 0),
        ('G LSB', [1], 0),
        ('B LSB', [2], 0),
        ('A LSB', [3], 0),
        ('RGB Bit 1', [0,1,2], 1),
    ]
    
    for name, chans, bit in tasks:
        if img.mode != 'RGBA' and (3 in chans): continue
        d = get_lsb_bytes(pixels, w, h, chans, bit)
        print(f"\n[{name}]: {d[:50]}")
        try:
            print(f"   ASCII: {d[:50].decode('utf-8', 'ignore')}")
        except: pass
