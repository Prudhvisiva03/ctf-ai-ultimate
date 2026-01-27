
import re

def search_text(filepath):
    print(f"Scanning {filepath} for flag patterns...")
    # This regex looks for anything that might be a flag, even with garbage around it
    # It searches for 'picoCTF', 'CTF', or 'flag' followed by '{' and then '}'
    # It allows for some non-printable characters in between if they are single bytes
    # But usually flags are clean.
    patterns = [
        rb'picoCTF\{[a-zA-Z0-9_!@#$%^&*()+-]+\}',
        rb'CTF\{[a-zA-Z0-9_!@#$%^&*()+-]+\}',
        rb'flag\{[a-zA-Z0-9_!@#$%^&*()+-]+\}'
    ]
    
    with open(filepath, 'rb') as f:
        data = f.read() # 200MB is okay for memory
        
        for p in patterns:
            matches = re.findall(p, data, re.IGNORECASE)
            for m in matches:
                print(f"FOUND: {m.decode('utf-8', errors='ignore')}")

if __name__ == '__main__':
    target = "c:\\Users\\Prudhvi\\Downloads\\Archive_Chall\\Chall.001"
    search_text(target)
