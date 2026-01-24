
def check_file(path):
    with open(path, 'r') as f:
        data = f.read()
    
    print(f"File size: {len(data)}")
    
    if 'pico' in data:
        print("FOUND 'pico' in file!")
        idx = data.find('pico')
        print(data[max(0, idx-20):idx+50])
    
    if 'flag' in data:
        print("FOUND 'flag' in file!")
        idx = data.find('flag')
        print(data[max(0, idx-20):idx+50])

if __name__ == '__main__':
    check_file(r"c:\Users\Prudhvi\Downloads\logs.txt")
