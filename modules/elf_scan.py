"""
ELF Binary Analysis Module
Performs basic reverse engineering reconnaissance
"""

import subprocess
import os
import re
from pathlib import Path


class ELFScanner:
    def __init__(self, config):
        self.config = config
        self.findings = []
        
    def run_file(self, filepath):
        """Get basic file information"""
        try:
            proc = subprocess.run(
                ['file', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if proc.returncode == 0:
                print(f"[+] File type: {proc.stdout.strip()}")
                return proc.stdout.strip()
                
        except Exception as e:
            return str(e)
            
        return None
    
    def run_checksec(self, filepath):
        """Run checksec to analyze binary protections"""
        try:
            print("[*] Running checksec...")
            proc = subprocess.run(
                ['checksec', '--file=' + filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                print(proc.stdout)
                return proc.stdout
            else:
                # Try alternative format
                proc = subprocess.run(
                    ['checksec', filepath],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if proc.returncode == 0:
                    print(proc.stdout)
                    return proc.stdout
                    
        except FileNotFoundError:
            print("⚠️  checksec not installed")
            # Fallback to manual checking
            return self.manual_checksec(filepath)
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def manual_checksec(self, filepath):
        """Manual security check using readelf"""
        results = []
        
        try:
            # Check for NX
            proc = subprocess.run(
                ['readelf', '-l', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if 'GNU_STACK' in proc.stdout:
                if 'RWE' in proc.stdout:
                    results.append("NX: Disabled (Stack is executable)")
                else:
                    results.append("NX: Enabled")
                    
            # Check for PIE
            proc = subprocess.run(
                ['readelf', '-h', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if 'DYN' in proc.stdout:
                results.append("PIE: Enabled")
            else:
                results.append("PIE: Disabled")
                
            return '\n'.join(results)
            
        except Exception as e:
            return f"Manual checksec failed: {str(e)}"
    
    def run_strings(self, filepath):
        """Extract strings and search for flags and interesting content"""
        try:
            print("[*] Extracting strings...")
            proc = subprocess.run(
                ['strings', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                strings_output = proc.stdout.split('\n')
                
                # Search for flags
                flags = self.search_flags(proc.stdout)
                if flags:
                    for flag in flags:
                        print(f"✅ FLAG FOUND: {flag}")
                
                # Search for interesting strings
                interesting = []
                keywords = ['flag', 'password', 'key', 'secret', 'admin', 'user']
                
                for s in strings_output:
                    s_lower = s.lower()
                    if any(kw in s_lower for kw in keywords):
                        interesting.append(s)
                
                if interesting:
                    print(f"⚠️  Found {len(interesting)} interesting string(s):")
                    for s in interesting[:20]:
                        print(f"    {s}")
                
                return {
                    'all_strings': strings_output,
                    'flags': flags,
                    'interesting': interesting
                }
                
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def search_flags(self, content):
        """Search for flags in content"""
        flags = []
        
        for pattern in self.config.get('flag_patterns', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def run_ldd(self, filepath):
        """Run ldd to show shared library dependencies"""
        try:
            print("[*] Checking shared libraries...")
            proc = subprocess.run(
                ['ldd', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if proc.returncode == 0:
                print(proc.stdout)
                return proc.stdout
                
        except FileNotFoundError:
            print("⚠️  ldd not available")
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return None
    
    def detect_dangerous_functions(self, filepath):
        """Detect potentially dangerous functions"""
        dangerous_funcs = [
            'system', 'exec', 'popen', 'strcpy', 'strcat', 
            'gets', 'sprintf', 'scanf', 'printf'
        ]
        
        try:
            print("[*] Searching for dangerous functions...")
            proc = subprocess.run(
                ['nm', '-D', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            found_funcs = []
            
            if proc.returncode == 0:
                for func in dangerous_funcs:
                    if func in proc.stdout:
                        found_funcs.append(func)
                        
                if found_funcs:
                    print(f"⚠️  Found dangerous functions: {', '.join(found_funcs)}")
                    return found_funcs
                else:
                    print("✅ No dangerous functions detected")
                    
        except Exception as e:
            print(f"Error: {str(e)}")
            
        return found_funcs
    
    def get_entry_point(self, filepath):
        """Get binary entry point"""
        try:
            proc = subprocess.run(
                ['readelf', '-h', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.split('\n'):
                    if 'Entry point' in line:
                        return line.strip()
                        
        except Exception as e:
            pass
            
        return None
    
    def scan(self, filepath):
        """Perform comprehensive ELF binary analysis"""
        print(f"\n[*] Starting ELF binary analysis on: {filepath}")
        
        scan_results = {
            'filepath': filepath,
            'binary_analysis': []
        }
        
        # Get file type
        file_type = self.run_file(filepath)
        scan_results['file_type'] = file_type
        
        # Run checksec
        checksec = self.run_checksec(filepath)
        scan_results['checksec'] = checksec
        
        # Extract strings
        strings_results = self.run_strings(filepath)
        if strings_results:
            scan_results['strings'] = strings_results
            if strings_results.get('flags'):
                scan_results['flags'] = strings_results['flags']
        
        # Run ldd
        ldd_output = self.run_ldd(filepath)
        scan_results['dependencies'] = ldd_output
        
        # Detect dangerous functions
        dangerous = self.detect_dangerous_functions(filepath)
        scan_results['dangerous_functions'] = dangerous
        
        # Get entry point
        entry = self.get_entry_point(filepath)
        scan_results['entry_point'] = entry
        
        # Provide next steps
        print("\n[*] Recommended next steps:")
        print("    1. Use 'ltrace ./binary' to trace library calls")
        print("    2. Use 'strace ./binary' to trace system calls")
        print("    3. Use 'gdb ./binary' for dynamic analysis")
        print("    4. Use 'radare2 ./binary' or 'ghidra' for deep reverse engineering")
        
        if dangerous:
            print(f"    5. Focus on dangerous functions: {', '.join(dangerous)}")
        
        return scan_results
