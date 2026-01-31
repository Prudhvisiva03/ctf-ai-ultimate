# CTFHunter Examples

This directory contains example files for testing CTFHunter.

## Test Files

You can create test files to verify CTFHunter installation:

### 1. Text File with Flag
```bash
echo "The secret flag{test_flag_12345} is hidden here" > test.txt
ctfhunter --target test.txt --mode auto
```

### 2. Test with Base64 Encoded Flag
```bash
echo "VGhlIGZsYWcgaXMgZmxhZ3tiYXNlNjRfZGVjb2RlZH0=" > encoded.txt
ctfhunter --target encoded.txt --mode auto
```

### 3. Test Binary File
```bash
echo -e "\x89PNG\r\n\x1a\nflag{hidden_in_binary}" > fake.png
ctfhunter --target fake.png --mode auto
```

## Sample Challenges

Download sample CTF challenges from:
- https://picoctf.org/
- https://ctftime.org/
- https://hackthebox.com/
- https://tryhackme.com/

## Usage Tips

1. **Always start with auto mode**:
   ```bash
   ctfhunter --target challenge_file --mode auto
   ```

2. **Use deep mode for complex challenges**:
   ```bash
   ctfhunter --target challenge_file --mode deep
   ```

3. **Check extracted files manually**:
   ```bash
   ls -la output/<challenge_name>/extracted/
   ```

4. **Review all output files**:
   ```bash
   cat output/<challenge_name>/report.txt
   ```
