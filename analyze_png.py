import sys
from PIL import Image
from PIL.ExifTags import TAGS

def analyze_image(path):
    try:
        img = Image.open(path)
        print(f"Format: {img.format}")
        print(f"Size: {img.size}")
        print(f"Mode: {img.mode}")
        
        print("\nMetadata:")
        for k, v in img.info.items():
            print(f"{k}: {v}")

        if hasattr(img, '_getexif') and img._getexif():
            print("\nEXIF Data:")
            exif = img._getexif()
            for tag_id in exif:
                tag = TAGS.get(tag_id, tag_id)
                data = exif.get(tag_id)
                print(f"{tag}: {data}")

        # Check for LSB
        print("\nChecking LSBs...")
        pixels = list(img.getdata())
        
        # Simple LSB extraction (RGB)
        binary_str = ""
        for p in pixels:
             # Handle different modes
            if isinstance(p, int): # Grayscale or Palette
                binary_str += str(p & 1)
            else:
                for val in p:
                    binary_str += str(val & 1)
        
        # Convert binary string to bytes
        bytes_list = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                bytes_list.append(int(byte, 2))
        
        decoded_bytes = bytes(bytes_list)
        
        # Look for flag in decoded bytes
        import re
        flag_pattern = b"flag\{[^}]+\}|picoCTF\{[^}]+\}"
        matches = re.findall(flag_pattern, decoded_bytes)
        if matches:
            print("\nFOUND FLAG via LSB:")
            for m in matches:
                print(m.decode(errors='ignore'))
        
        # Also try simply printing the first 200 chars of decoded bytes to see if it makes sense
        print("\nFirst 100 decoded bytes from LSB:")
        print(decoded_bytes[:100])

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    analyze_image("decoded_image.png")
