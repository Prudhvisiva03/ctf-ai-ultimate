# Walkthrough: Basic PNG Steganography

**Difficulty:** Beginner  
**Tools Used:** `zsteg`, `exiftool`, `strings`

## The Scenario
You are given a file named `challenge.png`. It looks like a normal image of a cat, but you suspect there's a hidden message (flag) inside.

## Step 1: Automated Analysis with CTF-AI
Run the tool on the image:

```bash
ctf-ai --solve challenge.png
```

## Step 2: What CTF-AI Does Behind the Scenes

### 1. File Type Detection
First, the tool verifies it's actually a PNG:
```bash
file challenge.png
# Output: challenge.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced
```

### 2. Leasts Significant Bit (LSB) Analysis
The tool automatically runs `zsteg`, which checks for hidden data in the bits of the image pixels.
```bash
zsteg -a challenge.png
```

**Result:**
```text
imagedata           .. text: "This is just random data..."
b1,r,lsb,xy         .. text: "flag{z5t3g_is_aw3s0m3}"
b2,g,msb,xy         .. file: OpenPGP Data
```

CTF-AI detects the pattern `flag{...}` in the output.

### 3. Metadata Check
If `zsteg` failed, it would check metadata using `exiftool`:
```bash
exiftool challenge.png
```
Sometimes flags are hidden in `Comment`, `Artist`, or `Description` fields.

### 4. Strings Check
Finally, it checks for printable strings appended to the end of the file:
```bash
strings challenge.png | tail -n 10
```

## Step 3: The Result
CTF-AI presents the findings:

```text
🎉 SUCCESS! Found 1 flag(s):
   1. flag{z5t3g_is_aw3s0m3}
```

## Manual Replication
To practice, try calculating this manually one day! But for now, CTF-AI saves you the trouble of remembering all the `zsteg` arguments.

## Key Takeaways
- **LSB Steganography** is very common in CTF challenges.
- **zsteg** is the best tool for PNGs.
- Always check metadata first!
