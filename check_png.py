
import struct

def check_png_structure(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    # PNG Signature
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        print("Not a valid PNG file.")
        return

    print(f"Total size: {len(data)}")

    offset = 8
    while offset < len(data):
        try:
            length = struct.unpack('>I', data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8]
            print(f"Chunk: {chunk_type.decode()} at {offset}, length: {length}")
            
            # Move to next chunk: length field (4) + type (4) + data (length) + CRC (4)
            offset += 4 + 4 + length + 4
            
            if chunk_type == b'IEND':
                print("Found IEND chunk.")
                if offset < len(data):
                    print(f"WARNING: {len(data) - offset} bytes of appended data found after IEND!")
                    appended = data[offset:]
                    try:
                        print("Appended data (string):")
                        print(appended.decode('utf-8'))
                    except:
                        print("Appended data (hex):")
                        print(appended[:100].hex())
                else:
                    print("No appended data detected.")
                break
        except Exception as e:
            print(f"Error parsing chunks: {e}")
            break

if __name__ == '__main__':
    check_png_structure("decoded_image.png")
