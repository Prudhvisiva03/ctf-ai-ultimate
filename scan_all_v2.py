
import struct
import re

def parse_record(record):
    if record[:4] != b'FILE': return
    
    try:
        attr_offset = struct.unpack('<H', record[20:22])[0]
        pos = attr_offset
        
        filename = "Unknown"
        # First pass: find filename
        while pos < 1024 - 8:
            attr_type = struct.unpack('<I', record[pos:pos+4])[0]
            if attr_type == 0xffffffff: break
            attr_len = struct.unpack('<I', record[pos+4:pos+8])[0]
            if attr_len == 0: break
            
            if attr_type == 0x30: # $FILE_NAME
                content_offset = struct.unpack('<H', record[pos+20:22])[0]
                name_len = record[pos+content_offset+64]
                name = record[pos+content_offset+66:pos+content_offset+66+name_len*2].decode('utf-16le', errors='ignore')
                filename = name
            pos += attr_len
            
        # Second pass: find resident data
        pos = attr_offset
        while pos < 1024 - 8:
            attr_type = struct.unpack('<I', record[pos:pos+4])[0]
            if attr_type == 0xffffffff: break
            attr_len = struct.unpack('<I', record[pos+4:pos+8])[0]
            if attr_len == 0: break
            
            if attr_type == 0x80: # $DATA
                non_resident = record[pos+8]
                if non_resident == 0:
                    ss_len = struct.unpack('<I', record[pos+16:pos+20])[0]
                    content_offset = struct.unpack('<H', record[pos+20:22])[0]
                    content = record[pos+content_offset:pos+content_offset+ss_len]
                    if len(content) > 5:
                        print(f"File: {filename} | Resident Data: {content}")
                        if b'pico' in content or b'CTF' in content or b'flag' in content:
                           print(f"🚩 FLAG FOUND: {content}")
            pos += attr_len
    except:
        pass

def scan_all(filepath):
    print(f"Scanning {filepath} for MFT records...")
    with open(filepath, 'rb') as f:
        content = f.read()
        for m in re.finditer(b'FILE', content):
            parse_record(content[m.start():m.start()+1024])

if __name__ == '__main__':
    target = "c:\\Users\\Prudhvi\\Downloads\\Archive_Chall\\Chall.001"
    scan_all(target)
