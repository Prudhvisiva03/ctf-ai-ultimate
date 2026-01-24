
from PIL import Image
import re

def extract_lsb(img):
    print(f"Scanning image: {img.mode} {img.size}")
    pixels = img.load()
    width, height = img.size

    channels = []
    if img.mode == 'RGB':
        channels = ['R', 'G', 'B']
    elif img.mode == 'RGBA':
        channels = ['R', 'G', 'B', 'A']
    else:
        print(f"Skipping mode {img.mode}")
        return

    # Prepare buffers for each channel and combined
    buffs = {c: "" for c in channels}
    buffs['RGB'] = ""
    buffs['RGBA'] = "" if 'A' in channels else None

    # Iterate pixels
    count = 0
    # Limit check to first 100000 bytes to avoid massive output if full, 
    # but usually flags are near start or it's a small message.
    # Flags can be anywhere though. Let's do a reasonable chunk.
    try:
        for y in range(height):
            for x in range(width):
                p = pixels[x, y]
                # p is tuple (r, g, b) or (r, g, b, a)
                
                curr_rgb = ""
                curr_rgba = ""
                
                for i, c in enumerate(channels):
                    val = p[i]
                    bit = str(val & 1)
                    buffs[c] += bit
                    
                    if c in ['R', 'G', 'B']:
                        curr_rgb += bit
                    curr_rgba += bit
                
                buffs['RGB'] += curr_rgb
                if buffs['RGBA'] is not None:
                    buffs['RGBA'] += curr_rgba
                
                count += 1
                # Check every 1000 pixels? No, do it after collection.
                # Just limiting to avoid memory error if huge
                if count > 500000: # 500k pixels is fair amount of data
                    break
            if count > 500000:
                break
    except Exception as e:
        print(f"Error processing pixels: {e}")

    # Process buffers
    print("Converting bits to bytes...")
    for key, bits in buffs.items():
        if bits is None: continue
        
        # Bits to bytes
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i:i+8]
            if len(chunk) < 8: break
            byte_array.append(int(chunk, 2))
        
        # Check for strings
        try:
            # Try utf-8
            decoded = byte_array.decode('utf-8', errors='ignore')
            # Look for flag
            patterns = [r'picoCTF\{.*?\}', r'flag\{.*?\}', r'CTF\{.*?\}']
            
            for pat in patterns:
                matches = re.findall(pat, decoded)
                for m in matches:
                    print(f"[FOUND] Flag in {key} channel(s): {m}")
                    
            # Also grep for 'pico' case insensitive
            if 'pico' in decoded.lower():
                idx = decoded.lower().find('pico')
                print(f"[INFO] 'pico' seen in {key} around: {decoded[idx:idx+50]}")
                
        except Exception as e:
            print(f"Error checking {key}: {e}")

if __name__ == '__main__':
    img = Image.open("decoded_image.png")
    extract_lsb(img)
