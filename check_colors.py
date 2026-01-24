
from PIL import Image

def analyze_colors(path):
    img = Image.open(path)
    print("Getting colors...")
    # maxcolors to something large just in case
    colors = img.getcolors(maxcolors=1000000)
    
    if colors:
        print(f"Total unique colors: {len(colors)}")
        # Sort by count (fewest first - interesting stuff)
        colors.sort(key=lambda x: x[0])
        
        print("\nLeast common colors:")
        for c in colors[:20]:
            print(f"Count: {c[0]} Color: {c[1]}")
            
        print("\nMost common colors:")
        for c in colors[-10:]:
            print(f"Count: {c[0]} Color: {c[1]}")
    else:
        print("Too many colors (> 1,000,000)")

if __name__ == '__main__':
    analyze_colors("decoded_image.png")
