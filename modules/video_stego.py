#!/usr/bin/env python3
"""
Video Steganography Module
Extract hidden data from video files
"""

import subprocess
import os
import re
import tempfile
import shutil
from typing import Dict, List, Optional
from pathlib import Path


class VideoSteganography:
    """Analyze video files for hidden data"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = config.get('output_directory', 'output') if config else 'output'
        self.results = {
            'metadata': {},
            'frames_extracted': 0,
            'audio_tracks': [],
            'subtitles': [],
            'hidden_data': [],
            'flags_found': [],
            'anomalies': []
        }
        
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}'
        ]
    
    def _search_flags(self, text: str):
        """Search for flags in text"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.results['flags_found']:
                    self.results['flags_found'].append(match)
                    print(f"[FLAG] Found: {match}")
    
    def get_metadata(self, filepath: str) -> Dict:
        """Extract video metadata"""
        print("[*] Extracting video metadata...")
        
        metadata = {}
        
        # Try ffprobe
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', 
                 '-show_format', '-show_streams', filepath],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                metadata['format'] = data.get('format', {})
                metadata['streams'] = data.get('streams', [])
                
                # Check for hidden streams
                stream_count = len(metadata['streams'])
                if stream_count > 2:  # More than video + audio
                    self.results['anomalies'].append(f"Multiple streams detected: {stream_count}")
                
                # Check metadata for flags
                format_tags = metadata['format'].get('tags', {})
                for key, value in format_tags.items():
                    self._search_flags(str(value))
                    if 'flag' in key.lower() or 'secret' in key.lower():
                        self.results['hidden_data'].append(f"Metadata {key}: {value}")
                
        except FileNotFoundError:
            print("[!] ffprobe not installed")
        except Exception as e:
            print(f"[!] Metadata extraction error: {e}")
        
        # Try exiftool
        try:
            result = subprocess.run(
                ['exiftool', '-all', filepath],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self._search_flags(result.stdout)
                metadata['exif'] = result.stdout
                
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[!] Exiftool error: {e}")
        
        self.results['metadata'] = metadata
        return metadata
    
    def extract_frames(self, filepath: str, output_dir: str = None, 
                       interval: int = 1, max_frames: int = 100) -> List[str]:
        """Extract frames from video"""
        print(f"[*] Extracting frames (every {interval} seconds, max {max_frames})...")
        
        if output_dir is None:
            output_dir = os.path.join(self.output_dir, 'video_frames')
        
        os.makedirs(output_dir, exist_ok=True)
        
        extracted = []
        
        try:
            # Extract frames using ffmpeg
            output_pattern = os.path.join(output_dir, 'frame_%04d.png')
            
            result = subprocess.run(
                ['ffmpeg', '-i', filepath, '-vf', f'fps=1/{interval}',
                 '-frames:v', str(max_frames), output_pattern, '-y'],
                capture_output=True, text=True, timeout=300
            )
            
            # List extracted frames
            for f in os.listdir(output_dir):
                if f.startswith('frame_') and f.endswith('.png'):
                    extracted.append(os.path.join(output_dir, f))
            
            self.results['frames_extracted'] = len(extracted)
            print(f"[+] Extracted {len(extracted)} frames to {output_dir}")
            
            # Analyze first few frames for hidden data
            if extracted:
                self._analyze_frames(extracted[:10])
            
        except FileNotFoundError:
            print("[!] ffmpeg not installed")
        except Exception as e:
            print(f"[!] Frame extraction error: {e}")
        
        return extracted
    
    def _analyze_frames(self, frame_paths: List[str]):
        """Analyze frames for steganography"""
        print("[*] Analyzing frames for hidden data...")
        
        for frame_path in frame_paths:
            # Run strings on each frame
            try:
                result = subprocess.run(
                    ['strings', frame_path],
                    capture_output=True, text=True, timeout=30
                )
                self._search_flags(result.stdout)
            except:
                pass
            
            # Try zsteg if available
            try:
                result = subprocess.run(
                    ['zsteg', frame_path],
                    capture_output=True, text=True, timeout=30
                )
                self._search_flags(result.stdout)
                
                for line in result.stdout.split('\n'):
                    if 'flag' in line.lower() or len(line) > 20:
                        self.results['hidden_data'].append(f"Frame {os.path.basename(frame_path)}: {line[:100]}")
            except:
                pass
    
    def extract_audio(self, filepath: str, output_dir: str = None) -> List[str]:
        """Extract audio tracks from video"""
        print("[*] Extracting audio tracks...")
        
        if output_dir is None:
            output_dir = os.path.join(self.output_dir, 'video_audio')
        
        os.makedirs(output_dir, exist_ok=True)
        
        audio_files = []
        
        try:
            # Get number of audio streams
            result = subprocess.run(
                ['ffprobe', '-v', 'error', '-select_streams', 'a',
                 '-show_entries', 'stream=index', '-of', 'csv=p=0', filepath],
                capture_output=True, text=True, timeout=60
            )
            
            audio_streams = [i for i in result.stdout.strip().split('\n') if i]
            
            for i, stream_idx in enumerate(audio_streams):
                output_path = os.path.join(output_dir, f'audio_track_{i}.wav')
                
                subprocess.run(
                    ['ffmpeg', '-i', filepath, '-map', f'0:a:{i}',
                     '-acodec', 'pcm_s16le', output_path, '-y'],
                    capture_output=True, timeout=120
                )
                
                if os.path.exists(output_path):
                    audio_files.append(output_path)
            
            self.results['audio_tracks'] = audio_files
            print(f"[+] Extracted {len(audio_files)} audio tracks")
            
            # Analyze audio for spectrograms
            for audio_file in audio_files:
                self._analyze_audio(audio_file)
                
        except FileNotFoundError:
            print("[!] ffmpeg/ffprobe not installed")
        except Exception as e:
            print(f"[!] Audio extraction error: {e}")
        
        return audio_files
    
    def _analyze_audio(self, audio_path: str):
        """Analyze audio for hidden data"""
        print(f"[*] Analyzing audio: {os.path.basename(audio_path)}")
        
        # Generate spectrogram
        output_dir = os.path.dirname(audio_path)
        spectrogram_path = audio_path.replace('.wav', '_spectrogram.png')
        
        try:
            subprocess.run(
                ['sox', audio_path, '-n', 'spectrogram', '-o', spectrogram_path],
                capture_output=True, timeout=60
            )
            
            if os.path.exists(spectrogram_path):
                print(f"[+] Generated spectrogram: {spectrogram_path}")
                self.results['hidden_data'].append(f"Spectrogram: {spectrogram_path}")
        except:
            pass
    
    def extract_subtitles(self, filepath: str, output_dir: str = None) -> List[str]:
        """Extract subtitle tracks"""
        print("[*] Extracting subtitles...")
        
        if output_dir is None:
            output_dir = os.path.join(self.output_dir, 'video_subtitles')
        
        os.makedirs(output_dir, exist_ok=True)
        
        subtitle_files = []
        
        try:
            # Get subtitle streams
            result = subprocess.run(
                ['ffprobe', '-v', 'error', '-select_streams', 's',
                 '-show_entries', 'stream=index', '-of', 'csv=p=0', filepath],
                capture_output=True, text=True, timeout=60
            )
            
            subtitle_streams = [i for i in result.stdout.strip().split('\n') if i]
            
            for i, stream_idx in enumerate(subtitle_streams):
                output_path = os.path.join(output_dir, f'subtitles_{i}.srt')
                
                subprocess.run(
                    ['ffmpeg', '-i', filepath, '-map', f'0:s:{i}', output_path, '-y'],
                    capture_output=True, timeout=60
                )
                
                if os.path.exists(output_path):
                    subtitle_files.append(output_path)
                    
                    # Read and search for flags
                    with open(output_path, 'r', errors='ignore') as f:
                        content = f.read()
                        self._search_flags(content)
            
            self.results['subtitles'] = subtitle_files
            print(f"[+] Extracted {len(subtitle_files)} subtitle tracks")
            
        except FileNotFoundError:
            print("[!] ffmpeg/ffprobe not installed")
        except Exception as e:
            print(f"[!] Subtitle extraction error: {e}")
        
        return subtitle_files
    
    def check_appended_data(self, filepath: str) -> Optional[bytes]:
        """Check for data appended after video container"""
        print("[*] Checking for appended data...")
        
        try:
            # Get expected file size from container
            result = subprocess.run(
                ['ffprobe', '-v', 'error', '-show_entries', 'format=size',
                 '-of', 'default=noprint_wrappers=1:nokey=1', filepath],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                container_size = int(result.stdout.strip())
                actual_size = os.path.getsize(filepath)
                
                if actual_size > container_size + 1024:  # More than 1KB extra
                    extra_bytes = actual_size - container_size
                    self.results['anomalies'].append(f"Extra data after container: {extra_bytes} bytes")
                    print(f"[!] Found {extra_bytes} bytes appended after video!")
                    
                    # Extract and analyze
                    with open(filepath, 'rb') as f:
                        f.seek(container_size)
                        appended_data = f.read()
                    
                    # Check for flags in appended data
                    try:
                        text = appended_data.decode('utf-8', errors='ignore')
                        self._search_flags(text)
                    except:
                        pass
                    
                    return appended_data
                    
        except Exception as e:
            print(f"[!] Appended data check error: {e}")
        
        return None
    
    def analyze_lsb(self, filepath: str) -> List[str]:
        """Analyze video frames for LSB steganography"""
        print("[*] Checking for LSB steganography in video frames...")
        
        findings = []
        
        # Extract a few frames for LSB analysis
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract first 5 frames
            output_pattern = os.path.join(temp_dir, 'lsb_frame_%04d.png')
            
            subprocess.run(
                ['ffmpeg', '-i', filepath, '-vf', 'fps=1',
                 '-frames:v', '5', output_pattern, '-y'],
                capture_output=True, timeout=120
            )
            
            # Analyze each frame with zsteg
            for f in os.listdir(temp_dir):
                if f.endswith('.png'):
                    frame_path = os.path.join(temp_dir, f)
                    
                    try:
                        result = subprocess.run(
                            ['zsteg', '-a', frame_path],
                            capture_output=True, text=True, timeout=60
                        )
                        
                        self._search_flags(result.stdout)
                        
                        for line in result.stdout.split('\n'):
                            if line.strip() and 'nothing' not in line.lower():
                                findings.append(f"{f}: {line[:100]}")
                    except:
                        pass
            
            if findings:
                self.results['hidden_data'].extend(findings)
                
        except Exception as e:
            print(f"[!] LSB analysis error: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        
        return findings
    
    def analyze(self, filepath: str) -> Dict:
        """Full video analysis"""
        print(f"\n[*] Analyzing video: {filepath}")
        print("=" * 60)
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return self.results
        
        # Run all analyses
        self.get_metadata(filepath)
        self.extract_frames(filepath, max_frames=20)
        self.extract_audio(filepath)
        self.extract_subtitles(filepath)
        self.check_appended_data(filepath)
        self.analyze_lsb(filepath)
        
        # Summary
        print("\n" + "=" * 60)
        print("[*] Video Analysis Summary")
        print("=" * 60)
        
        if self.results['flags_found']:
            print(f"\n[FLAG] FLAGS FOUND: {len(self.results['flags_found'])}")
            for flag in self.results['flags_found']:
                print(f"  -> {flag}")
        
        if self.results['anomalies']:
            print(f"\n[!] ANOMALIES: {len(self.results['anomalies'])}")
            for anomaly in self.results['anomalies']:
                print(f"  -> {anomaly}")
        
        if self.results['hidden_data']:
            print(f"\n[+] HIDDEN DATA: {len(self.results['hidden_data'])}")
            for data in self.results['hidden_data'][:10]:
                print(f"  -> {data}")
        
        return self.results
    
    def get_summary(self) -> str:
        """Get formatted summary"""
        lines = ["Video Steganography Analysis", "=" * 40]
        
        lines.append(f"Frames extracted: {self.results['frames_extracted']}")
        lines.append(f"Audio tracks: {len(self.results['audio_tracks'])}")
        lines.append(f"Subtitle tracks: {len(self.results['subtitles'])}")
        lines.append(f"Hidden data items: {len(self.results['hidden_data'])}")
        lines.append(f"Anomalies: {len(self.results['anomalies'])}")
        lines.append(f"Flags found: {len(self.results['flags_found'])}")
        
        if self.results['flags_found']:
            lines.append("\nFlags:")
            for flag in self.results['flags_found']:
                lines.append(f"  {flag}")
        
        return '\n'.join(lines)
