"""
Steganography Scanning Module
Handles image steganography detection and extraction
"""

import subprocess
import os
from pathlib import Path


class StegoScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        
    def run_zsteg(self, filepath):
        """Run zsteg for PNG images"""
        results = []
        try:
            print("[*] Running zsteg scan...")
            proc = subprocess.run(
                ['zsteg', '-a', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.returncode == 0:
                results = proc.stdout.split('\n')
                
                # Filter meaningful results
                meaningful = [r for r in results if r.strip() and not r.startswith('b')]
                
                if meaningful:
                    print(f"✅ Zsteg found {len(meaningful)} potential hidden data")
                    for r in meaningful[:10]:  # Show first 10
                        print(f"    {r}")
                else:
                    print("❌ No hidden data found with zsteg")
                    
        except FileNotFoundError:
            print("⚠️  zsteg not installed")
            results.append("zsteg not available")
        except Exception as e:
            results.append(f"Error: {str(e)}")
            
        return results
    
    def run_stegseek(self, filepath):
        """Run stegseek for steghide-compatible images"""
        results = {}
        try:
            output_dir = self.config.get('output_directory', 'output')
            output_file = os.path.join(output_dir, 'stegseek_output.txt')
            
            print("[*] Running stegseek (passwordless)...")
            
            # Try passwordless extraction first
            proc = subprocess.run(
                ['steghide', 'extract', '-sf', filepath, '-p', '', '-xf', output_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                print(f"✅ Extracted hidden data to {output_file}")
                results['extracted'] = True
                results['output_file'] = output_file
                
                # Read extracted content
                if os.path.exists(output_file):
                    with open(output_file, 'r', errors='ignore') as f:
                        content = f.read()
                        results['content'] = content
                        print(f"[+] Extracted content preview:\n{content[:200]}")
            else:
                print("❌ No passwordless steghide data found")
                results['extracted'] = False
                
                # Try with rockyou.txt if available
                rockyou_path = self.config.get('wordlists', {}).get('rockyou')
                if rockyou_path and os.path.exists(rockyou_path):
                    print("[*] Attempting brute force with rockyou.txt...")
                    results['bruteforce'] = self.brute_force_stegseek(filepath, rockyou_path)
                    
        except FileNotFoundError:
            print("⚠️  steghide not installed")
            results['error'] = "steghide not available"
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def brute_force_stegseek(self, filepath, wordlist):
        """Brute force steghide with wordlist"""
        try:
            output_dir = self.config.get('output_directory', 'output')
            
            # Use stegseek if available (faster than steghide)
            proc = subprocess.run(
                ['stegseek', filepath, wordlist, '-xf', os.path.join(output_dir, 'cracked.txt')],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if proc.returncode == 0:
                print(f"🔥 Successfully cracked steghide password!")
                return {
                    'success': True,
                    'output': proc.stdout
                }
            else:
                print("❌ Brute force failed")
                return {
                    'success': False,
                    'output': proc.stderr
                }
                
        except FileNotFoundError:
            print("⚠️  stegseek not installed, trying steghide brute force...")
            return {'error': 'stegseek not available'}
        except Exception as e:
            return {'error': str(e)}
    
    def run_steghide_info(self, filepath):
        """Get steghide info"""
        try:
            proc = subprocess.run(
                ['steghide', 'info', filepath],
                capture_output=True,
                text=True,
                timeout=10,
                input='\n'  # Send empty password
            )
            
            return proc.stdout
            
        except Exception as e:
            return str(e)
    
    def scan(self, filepath):
        """Perform steganography scan"""
        print(f"\n[*] Starting steganography scan on: {filepath}")
        
        scan_results = {
            'filepath': filepath,
            'stego_findings': []
        }
        
        # Detect file extension
        ext = Path(filepath).suffix.lower()
        
        # Run appropriate tools based on file type
        if ext in ['.png', '.bmp']:
            print("[+] Detected PNG/BMP - running zsteg")
            zsteg_results = self.run_zsteg(filepath)
            scan_results['zsteg'] = zsteg_results
            
        if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.wav', '.au']:
            print("[+] Attempting steghide extraction")
            
            # Get steghide info
            info = self.run_steghide_info(filepath)
            scan_results['steghide_info'] = info
            
            # Try extraction
            stegseek_results = self.run_stegseek(filepath)
            scan_results['steghide'] = stegseek_results
        
        return scan_results
