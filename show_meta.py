
from PIL import Image

def show_meta(path):
    img = Image.open(path)
    print("Info keys:")
    for k, v in img.info.items():
        print(f"{k}: {v}")
    
    print("Text chunks:")
    if 'text' in img.info:
        print(img.info['text'])

if __name__ == '__main__':
    show_meta("decoded_image.png")
