
import struct
import os

def parse_record(data, offset):
    if offset + 1024 > len(data): return None
    record = data[offset:offset+1024]
    if record[:4] != b'FILE': return None
    
    try:
        attr_offset = struct.unpack('<H', record[20:22])[0]
        pos = attr_offset
        
        filename = "Unknown"
        resident_data = None
        
        while pos < 1024 - 8:
            attr_type = struct.unpack('<I', record[pos:pos+4])[0]
            if attr_type == 0xffffffff: break
            attr_len = struct.unpack('<I', record[pos+4:pos+8])[0]
            if attr_len <= 0: break
            
            if attr_type == 0x30: # $FILE_NAME
                content_offset = struct.unpack('<H', record[pos+20:22])[0]
                name_len = record[pos+content_offset+64]
                name = record[pos+content_offset+66:pos+content_offset+66+name_len*2].decode('utf-16le', errors='ignore')
                filename = name
            
            if attr_type == 0x80: # $DATA
                non_resident = record[pos+8]
                if non_resident == 0:
                    ss_len = struct.unpack('<I', record[pos+16:pos+20])[0]
                    ss_offset = struct.unpack('<H', record[pos+20:22])[0]
                    resident_data = record[pos+ss_offset:pos+ss_offset+ss_len]
            
            pos += attr_len
        return filename, resident_data
    except:
        return None

def scan_mft(filepath, mft_offset):
    with open(filepath, 'rb') as f:
        f.seek(mft_offset)
        # Read 10MB of MFT
        mft_data = f.read(10 * 1024 * 1024)
        
        for i in range(0, len(mft_data), 1024):
            res = parse_record(mft_data, i)
            if res:
                fname, data = res
                if data and len(data) > 20:
                    # Print any resident data that looks interesting
                    if any(c in data for c in [b'pico', b'flag', b'CTF', b'Thunder']):
                        print(f"[{fname}] : {data}")
                    elif b'{' in data and b'}' in data:
                        print(f"[{fname}] (Potential Flag structure): {data}")

if __name__ == '__main__':
    target = "c:\\Users\\Prudhvi\\Downloads\\Archive_Chall\\Chall.001"
    scan_mft(target, 69902336)
