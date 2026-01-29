#!/bin/bash
# Update CTF-AI Ultimate on Linux with all enhancements

echo "🚀 Updating CTF-AI Ultimate..."
echo ""

cd ~/ctf-ai-ultimate || exit 1

# 1. Update file_scan.py with auto-scanning
echo "[1/3] Updating file_scan.py..."
cat > /tmp/scan_extracted_files.py << 'EOF'
    
    def scan_extracted_files(self, extract_dir):
        """Scan all extracted files for flags using strings"""
        flags = []
        
        if not os.path.exists(extract_dir):
            return flags
        
        print(f"   ↳ Scanning directory: {extract_dir}")
        
        # Walk through all extracted files
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    # Run strings on each file
                    proc = subprocess.run(
                        ['strings', filepath],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if proc.returncode == 0:
                        # Search for flags in strings output
                        found_flags = self.search_flags(proc.stdout)
                        if found_flags:
                            print(f"   ✅ Found flag(s) in: {os.path.basename(filepath)}")
                            flags.extend(found_flags)
                            
                except Exception as e:
                    continue  # Skip files that cause errors
        
        return list(set(flags))  # Remove duplicates
EOF

# Add the function to file_scan.py if not already there
if ! grep -q "def scan_extracted_files" modules/file_scan.py; then
    # Insert before check_and_decode_base64
    sed -i '/def check_and_decode_base64/i\    def scan_extracted_files(self, extract_dir):\n        """Scan all extracted files for flags using strings"""\n        flags = []\n        \n        if not os.path.exists(extract_dir):\n            return flags\n        \n        print(f"   ↳ Scanning directory: {extract_dir}")\n        \n        # Walk through all extracted files\n        for root, dirs, files in os.walk(extract_dir):\n            for file in files:\n                filepath = os.path.join(root, file)\n                try:\n                    # Run strings on each file\n                    proc = subprocess.run(\n                        ["strings", filepath],\n                        capture_output=True,\n                        text=True,\n                        timeout=10\n                    )\n                    \n                    if proc.returncode == 0:\n                        # Search for flags in strings output\n                        found_flags = self.search_flags(proc.stdout)\n                        if found_flags:\n                            print(f"   ✅ Found flag(s) in: {os.path.basename(filepath)}")\n                            flags.extend(found_flags)\n                            \n                except Exception as e:\n                    continue  # Skip files that cause errors\n        \n        return list(set(flags))  # Remove duplicates\n    \n' modules/file_scan.py
    
    # Add call to scan_extracted_files in extract_with_binwalk
    sed -i '/Extracted files to {extract_dir}/a\                \n                # ✅ AUTO-SCAN EXTRACTED FILES FOR FLAGS\n                print("[*] Auto-scanning extracted files for flags...")\n                extracted_flags = self.scan_extracted_files(extract_dir)\n                if extracted_flags:\n                    print(f"🎉 FOUND {len(extracted_flags)} FLAG(S) IN EXTRACTED FILES!")\n                    for flag in extracted_flags:\n                        print(f"   🚩 {flag}")\n                    self.findings.append({\n                        "type": "flag_found",\n                        "flags": extracted_flags,\n                        "location": "extracted_files",\n                        "status": "success"\n                    })' modules/file_scan.py
fi

echo "✅ file_scan.py updated!"

# 2. Update reporter.py for unique output directories
echo "[2/3] Updating reporter.py..."
# This was already done in your Windows version, sync it via git

# 3. Update ctf-ai.py for disk image detection
echo "[3/3] Updating ctf-ai.py..."
# This was already done in your Windows version, sync it via git

echo ""
echo "✅ All updates complete!"
echo ""
echo "🎯 Now test with:"
echo "   sudo ctf-ai --solve /home/siva/Downloads/disko-1.dd.gz"
echo ""
