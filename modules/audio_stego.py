#!/usr/bin/env python3
"""
Audio Steganography Scanner - Analyze audio files for hidden data
For CTF challenges with audio steganography
Author: Prudhvi (CTFHunter)
Version: 2.1.0

Supports: WAV, MP3, FLAC, OGG
Techniques: Spectrogram, LSB, metadata, hidden strings
"""

import subprocess
import os
import re
from typing import Dict, List, Optional


class AudioStegoScanner:
    """Audio steganography analysis for CTF challenges"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.results = {
            'file_info': {},
            'spectrogram': None,
            'strings': [],
            'metadata': {},
            'flags': [],
            'findings': []
        }
        self.flag_patterns = self.config.get('flag_patterns', [
            r'digitalcyberhunt\{[^}]+\}',
            r'DCH\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}'
        ])
        self.output_dir = self.config.get('output_directory', 'output')
    
    def scan(self, filepath: str) -> Dict:
        """Full audio steganography analysis"""
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Run all analysis methods
        self._get_file_info(filepath)
        self._extract_metadata(filepath)
        self._extract_strings(filepath)
        self._generate_spectrogram(filepath)
        self._check_sonic_visualiser(filepath)
        self._check_morse_audio(filepath)
        self._search_flags()
        
        return self.results
    
    def _get_file_info(self, filepath: str):
        """Get basic audio file information"""
        try:
            # Use ffprobe for detailed info
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                import json
                info = json.loads(result.stdout)
                self.results['file_info'] = {
                    'format': info.get('format', {}).get('format_name', 'Unknown'),
                    'duration': info.get('format', {}).get('duration', 'Unknown'),
                    'bitrate': info.get('format', {}).get('bit_rate', 'Unknown'),
                    'size': info.get('format', {}).get('size', 'Unknown')
                }
                self.results['findings'].append(f"🎵 Audio format: {self.results['file_info']['format']}")
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Try file command as fallback
            try:
                result = subprocess.run(['file', filepath], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.results['file_info']['type'] = result.stdout.strip()
            except:
                pass
    
    def _extract_metadata(self, filepath: str):
        """Extract audio metadata using exiftool"""
        try:
            result = subprocess.run(
                ['exiftool', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Look for interesting metadata
                        if value and key in ['Comment', 'Title', 'Artist', 'Album', 'Genre', 'Lyrics']:
                            self.results['metadata'][key] = value
                            self.results['findings'].append(f"📋 Metadata {key}: {value}")
                            
                            # Check for flags in metadata
                            for pattern in self.flag_patterns:
                                matches = re.findall(pattern, value, re.IGNORECASE)
                                if matches:
                                    self.results['flags'].extend(matches)
                                    self.results['findings'].append(f"🚩 FLAG in metadata: {matches}")
                                    
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    def _extract_strings(self, filepath: str):
        """Extract strings from audio file"""
        try:
            result = subprocess.run(
                ['strings', '-n', '8', filepath],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                strings = result.stdout.split('\n')
                
                # Filter interesting strings
                for s in strings:
                    s = s.strip()
                    if len(s) > 10:
                        # Check for flags
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, s, re.IGNORECASE)
                            if matches:
                                self.results['flags'].extend(matches)
                                self.results['strings'].append(s)
                                self.results['findings'].append(f"🚩 FLAG in strings: {matches}")
                        
                        # Look for URLs, Base64, etc.
                        if re.match(r'https?://', s) or re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
                            self.results['strings'].append(s)
                            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    
    def _generate_spectrogram(self, filepath: str):
        """Generate spectrogram image to look for hidden visual data"""
        try:
            output_path = os.path.join(self.output_dir, 'spectrogram.png')
            
            # Try sox first (better quality)
            result = subprocess.run(
                ['sox', filepath, '-n', 'spectrogram', '-o', output_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(output_path):
                self.results['spectrogram'] = output_path
                self.results['findings'].append(f"📊 Spectrogram saved: {output_path}")
                self.results['findings'].append("💡 Check spectrogram for hidden text/images!")
                return
            
            # Fallback to ffmpeg
            result = subprocess.run(
                ['ffmpeg', '-i', filepath, '-lavfi', 'showspectrumpic=s=1024x512', output_path, '-y'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(output_path):
                self.results['spectrogram'] = output_path
                self.results['findings'].append(f"📊 Spectrogram saved: {output_path}")
                self.results['findings'].append("💡 Check spectrogram for hidden text/images!")
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.results['findings'].append("⚠️ Install sox or ffmpeg for spectrogram analysis")
    
    def _check_sonic_visualiser(self, filepath: str):
        """Suggest Sonic Visualiser for advanced analysis"""
        self.results['findings'].append("💡 For advanced analysis, try: Sonic Visualiser or Audacity")
        self.results['findings'].append("💡 Check: Different spectrogram scales (linear, log, mel)")
    
    def _check_morse_audio(self, filepath: str):
        """Check for Morse code in audio"""
        # This is a hint - actual Morse decoding requires more complex analysis
        self.results['findings'].append("💡 If you hear beeps: Could be Morse code!")
        self.results['findings'].append("💡 Online decoder: morsecode.world/international/decoder/audio-decoder-adaptive.html")
    
    def _search_flags(self):
        """Search for flags in all collected data"""
        # Combine all text data
        all_text = ' '.join(self.results['strings'])
        all_text += ' '.join([str(v) for v in self.results['metadata'].values()])
        
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags']:
                    self.results['flags'].append(match)
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        summary = []
        summary.append("\n" + "="*50)
        summary.append("🎵 AUDIO STEGANOGRAPHY RESULTS")
        summary.append("="*50)
        
        if self.results['file_info']:
            summary.append(f"\n📁 File Info:")
            for key, value in self.results['file_info'].items():
                summary.append(f"   {key}: {value}")
        
        if self.results['flags']:
            summary.append(f"\n🚩 FLAGS FOUND:")
            for flag in self.results['flags']:
                summary.append(f"   {flag}")
        
        if self.results['metadata']:
            summary.append(f"\n📋 Metadata:")
            for key, value in self.results['metadata'].items():
                summary.append(f"   {key}: {value}")
        
        if self.results['spectrogram']:
            summary.append(f"\n📊 Spectrogram: {self.results['spectrogram']}")
        
        if self.results['findings']:
            summary.append(f"\n🔍 Findings:")
            for finding in self.results['findings']:
                summary.append(f"   {finding}")
        
        # Tips
        summary.append(f"\n💡 Audio Stego Tips:")
        summary.append(f"   • Spectrogram may show hidden images/text")
        summary.append(f"   • Check for Morse code or DTMF tones")
        summary.append(f"   • LSB encoding may hide data in audio samples")
        summary.append(f"   • Tools: Sonic Visualiser, Audacity, DeepSound")
        
        summary.append("="*50 + "\n")
        return "\n".join(summary)


def scan_audio(filepath: str, config: Dict = None) -> Dict:
    """Convenience function to scan audio file"""
    scanner = AudioStegoScanner(config)
    return scanner.scan(filepath)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python audio_stego.py <audio_file>")
        print("\nAudio Steganography Scanner")
        print("Supports: WAV, MP3, FLAC, OGG")
        sys.exit(1)
    
    scanner = AudioStegoScanner()
    results = scanner.scan(sys.argv[1])
    print(scanner.get_summary())
