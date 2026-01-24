
from PIL import Image
import magic

def save_and_check(data, name):
    fname = f"{name}.bin"
    with open(fname, 'wb') as f:
        f.write(data)
    
    m = magic.from_file(fname)
    print(f"[{name}] Magic: {m}")
    
    # Check for flag text blindly too
    try:
        s = data.decode('utf-8', 'ignore')
        if 'pico' in s.lower() or 'flag' in s.lower() or 'ctf' in s.lower():
            print(f"[{name}] STRINGS FOUND 'pico'/'flag'/'ctf'")
            # print snippet
            idx = s.lower().find('pico')
            if idx == -1: idx = s.lower().find('flag')
            if idx == -1: idx = s.lower().find('ctf')
            print(f"Context: {s[max(0, idx-20):idx+50]}")
    except: pass

def extract_all_lsb(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    w, h = img.size
    
    # buffers
    # R, G, B, RGB
    buffs = {
        'r': (0, bytearray(), 0), 
        'g': (1, bytearray(), 0), 
        'b': (2, bytearray(), 0), 
        'rgb': (None, bytearray(), 0)
    }
    # rgb tuples: (channel_index, bytearray, current_byte_val, bit_count)
    # Actually need state: (bytearray, curr_val, bit_count)
    
    # Initialize states
    state_r = {'data': bytearray(), 'curr': 0, 'bits': 0}
    state_g = {'data': bytearray(), 'curr': 0, 'bits': 0}
    state_b = {'data': bytearray(), 'curr': 0, 'bits': 0}
    state_rgb = {'data': bytearray(), 'curr': 0, 'bits': 0}
    
    print("Extracting...")
    count = 0 
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y] # Assuming RGB
            
            # R
            state_r['curr'] = (state_r['curr'] << 1) | (r & 1)
            state_r['bits'] += 1
            if state_r['bits'] == 8:
                state_r['data'].append(state_r['curr'])
                state_r['curr'] = 0
                state_r['bits'] = 0
            
            # G
            state_g['curr'] = (state_g['curr'] << 1) | (g & 1)
            state_g['bits'] += 1
            if state_g['bits'] == 8:
                state_g['data'].append(state_g['curr'])
                state_g['curr'] = 0
                state_g['bits'] = 0
                
            # B
            state_b['curr'] = (state_b['curr'] << 1) | (b & 1)
            state_b['bits'] += 1
            if state_b['bits'] == 8:
                state_b['data'].append(state_b['curr'])
                state_b['curr'] = 0
                state_b['bits'] = 0
            
            # RGB
            for v in [r, g, b]:
                state_rgb['curr'] = (state_rgb['curr'] << 1) | (v & 1)
                state_rgb['bits'] += 1
                if state_rgb['bits'] == 8:
                    state_rgb['data'].append(state_rgb['curr'])
                    state_rgb['curr'] = 0
                    state_rgb['bits'] = 0
        
        count += 1
        # Check periodically? No, just run. 10M pixels is fast in C, slow in Python.
        # But should be < 1 min.
    
    print("Saving...")
    save_and_check(state_r['data'], "lsb_r")
    save_and_check(state_g['data'], "lsb_g")
    save_and_check(state_b['data'], "lsb_b")
    save_and_check(state_rgb['data'], "lsb_rgb")

if __name__ == '__main__':
    extract_all_lsb("decoded_image.png")
