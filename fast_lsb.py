
import sys
from PIL import Image
import re

def brute_lsb(image_path):
    print(f"Opening {image_path}...")
    img = Image.open(image_path)
    print(f"Size: {img.size} Mode: {img.mode}")
    
    pixels = img.load()
    width, height = img.size
    
    # Define channels
    modes = []
    if img.mode == 'RGB':
        modes = [('R', 0), ('G', 1), ('B', 2), ('RGB', [0,1,2])]
    elif img.mode == 'RGBA':
        modes = [('R', 0), ('G', 1), ('B', 2), ('A', 3), ('RGB', [0,1,2]), ('RGBA', [0,1,2,3])]
    
    # We will process in chunks of rows to save memory and show progress
    CHUNK_HEIGHT = 500
    
    for mode_name, channel_idx in modes:
        print(f"\nChecking mode: {mode_name}")
        
        # We'll use a bytearray for efficiency
        current_bits = 0
        bit_count = 0
        extracted_bytes = bytearray()
        
        # Stop if we find something
        found = False
        
        for y_start in range(0, height, CHUNK_HEIGHT):
            y_end = min(y_start + CHUNK_HEIGHT, height)
            
            for y in range(y_start, y_end):
                for x in range(width):
                    p = pixels[x, y]
                    
                    if isinstance(channel_idx, int):
                         # Single channel
                        vals = [p[channel_idx]]
                    else:
                        # Multi channel
                        vals = [p[i] for i in channel_idx]
                    
                    for val in vals:
                        bit = val & 1
                        current_bits = (current_bits << 1) | bit
                        bit_count += 1
                        
                        if bit_count == 8:
                            extracted_bytes.append(current_bits)
                            current_bits = 0
                            bit_count = 0
            
            # Check content so far periodically (every chunk)
            # We look for 'pico' or 'flag'
            try:
                # Decode last 1000 bytes or so to check boundaries?
                # Actually checking the whole thing is safer but slow if huge.
                # Let's check the *newly added* section + overlap
                check_len = (CHUNK_HEIGHT * width * len(vals if isinstance(channel_idx, list) else [1])) // 8
                start_check = max(0, len(extracted_bytes) - check_len - 100)
                
                recent_data = extracted_bytes[start_check:]
                
                # Check binary patterns directly to avoid decode errors halting us
                if b'pico' in recent_data or b'flag' in recent_data or b'CTF' in recent_data:
                    # Try to decode and print context
                    try:
                        text = recent_data.decode('utf-8', errors='ignore')
                        match = re.search(r'(picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\})', text)
                        if match:
                            print(f"\n!!! FOUND FLAG in {mode_name}: {match.group(1)}")
                            return
                        else:
                            # Print context
                            idx = text.lower().find('pico')
                            if idx == -1: idx = text.lower().find('flag')
                            if idx != -1:
                                print(f"Possible match in {mode_name}: ...{text[idx:idx+50]}...")
                    except:
                        pass
            except Exception as e:
                pass
                
        print(f"Finished {mode_name}, extracted {len(extracted_bytes)} bytes.")

if __name__ == '__main__':
    brute_lsb("decoded_image.png")
