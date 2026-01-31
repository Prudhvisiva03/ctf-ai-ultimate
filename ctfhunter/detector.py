"""
CTFHunter - File Type Detector
==============================

Automatically detects CTF challenge file types using magic bytes,
file extensions, and the 'file' command.
"""

import os
import subprocess
import mimetypes
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto


class FileCategory(Enum):
    """Enumeration of supported file categories."""
    IMAGE = auto()
    AUDIO = auto()
    VIDEO = auto()
    ARCHIVE = auto()
    DOCUMENT = auto()
    BINARY = auto()
    NETWORK = auto()
    TEXT = auto()
    UNKNOWN = auto()


@dataclass
class FileInfo:
    """Data class containing detected file information."""
    path: str
    name: str
    extension: str
    mime_type: str
    magic_description: str
    category: FileCategory
    size: int
    is_executable: bool
    suggested_tools: List[str]


class FileDetector:
    """
    File type detector for CTF challenges.
    
    Uses multiple detection methods:
    1. File extension analysis
    2. Magic bytes detection
    3. MIME type detection
    4. Linux 'file' command
    """
    
    # Magic byte signatures for common file types
    MAGIC_SIGNATURES = {
        b'\x89PNG\r\n\x1a\n': ('image/png', 'PNG image'),
        b'\xff\xd8\xff': ('image/jpeg', 'JPEG image'),
        b'GIF87a': ('image/gif', 'GIF image (87a)'),
        b'GIF89a': ('image/gif', 'GIF image (89a)'),
        b'BM': ('image/bmp', 'BMP image'),
        b'PK\x03\x04': ('application/zip', 'ZIP archive'),
        b'PK\x05\x06': ('application/zip', 'ZIP archive (empty)'),
        b'\x1f\x8b\x08': ('application/gzip', 'GZIP archive'),
        b'Rar!\x1a\x07': ('application/x-rar', 'RAR archive'),
        b'\x7fELF': ('application/x-executable', 'ELF executable'),
        b'MZ': ('application/x-dosexec', 'DOS/Windows executable'),
        b'\xd0\xcf\x11\xe0': ('application/msword', 'MS Office document'),
        b'%PDF': ('application/pdf', 'PDF document'),
        b'RIFF': ('audio/wav', 'RIFF/WAV audio'),
        b'ID3': ('audio/mpeg', 'MP3 audio (ID3)'),
        b'\xff\xfb': ('audio/mpeg', 'MP3 audio'),
        b'\xff\xfa': ('audio/mpeg', 'MP3 audio'),
        b'fLaC': ('audio/flac', 'FLAC audio'),
        b'OggS': ('audio/ogg', 'OGG audio'),
        b'\xd4\xc3\xb2\xa1': ('application/vnd.tcpdump.pcap', 'PCAP (little-endian)'),
        b'\xa1\xb2\xc3\xd4': ('application/vnd.tcpdump.pcap', 'PCAP (big-endian)'),
        b'\x0a\x0d\x0d\x0a': ('application/vnd.tcpdump.pcap', 'PCAPNG'),
        b'SQLite format 3': ('application/x-sqlite3', 'SQLite database'),
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': ('video/mp4', 'MP4 video'),
        b'\x00\x00\x00\x20\x66\x74\x79\x70': ('video/mp4', 'MP4 video'),
        b'\x1a\x45\xdf\xa3': ('video/webm', 'WebM/MKV video'),
    }
    
    # Extension to category mapping
    EXTENSION_CATEGORIES = {
        # Images
        '.png': FileCategory.IMAGE,
        '.jpg': FileCategory.IMAGE,
        '.jpeg': FileCategory.IMAGE,
        '.gif': FileCategory.IMAGE,
        '.bmp': FileCategory.IMAGE,
        '.tiff': FileCategory.IMAGE,
        '.webp': FileCategory.IMAGE,
        '.ico': FileCategory.IMAGE,
        '.svg': FileCategory.IMAGE,
        
        # Audio
        '.wav': FileCategory.AUDIO,
        '.mp3': FileCategory.AUDIO,
        '.flac': FileCategory.AUDIO,
        '.ogg': FileCategory.AUDIO,
        '.aac': FileCategory.AUDIO,
        '.m4a': FileCategory.AUDIO,
        
        # Video
        '.mp4': FileCategory.VIDEO,
        '.avi': FileCategory.VIDEO,
        '.mkv': FileCategory.VIDEO,
        '.mov': FileCategory.VIDEO,
        '.webm': FileCategory.VIDEO,
        
        # Archives
        '.zip': FileCategory.ARCHIVE,
        '.tar': FileCategory.ARCHIVE,
        '.gz': FileCategory.ARCHIVE,
        '.tgz': FileCategory.ARCHIVE,
        '.bz2': FileCategory.ARCHIVE,
        '.xz': FileCategory.ARCHIVE,
        '.7z': FileCategory.ARCHIVE,
        '.rar': FileCategory.ARCHIVE,
        
        # Documents
        '.pdf': FileCategory.DOCUMENT,
        '.doc': FileCategory.DOCUMENT,
        '.docx': FileCategory.DOCUMENT,
        '.xls': FileCategory.DOCUMENT,
        '.xlsx': FileCategory.DOCUMENT,
        '.ppt': FileCategory.DOCUMENT,
        '.pptx': FileCategory.DOCUMENT,
        
        # Network
        '.pcap': FileCategory.NETWORK,
        '.pcapng': FileCategory.NETWORK,
        '.cap': FileCategory.NETWORK,
        
        # Text
        '.txt': FileCategory.TEXT,
        '.log': FileCategory.TEXT,
        '.csv': FileCategory.TEXT,
        '.json': FileCategory.TEXT,
        '.xml': FileCategory.TEXT,
        '.html': FileCategory.TEXT,
        '.htm': FileCategory.TEXT,
        '.md': FileCategory.TEXT,
        '.py': FileCategory.TEXT,
        '.c': FileCategory.TEXT,
        '.cpp': FileCategory.TEXT,
        '.h': FileCategory.TEXT,
        '.js': FileCategory.TEXT,
        '.sh': FileCategory.TEXT,
        
        # Binaries
        '.exe': FileCategory.BINARY,
        '.dll': FileCategory.BINARY,
        '.so': FileCategory.BINARY,
        '.elf': FileCategory.BINARY,
        '.bin': FileCategory.BINARY,
        '.out': FileCategory.BINARY,
        '.o': FileCategory.BINARY,
        '.class': FileCategory.BINARY,
        '.jar': FileCategory.BINARY,
        '.apk': FileCategory.BINARY,
        '.dex': FileCategory.BINARY,
    }
    
    # Suggested tools per category
    CATEGORY_TOOLS = {
        FileCategory.IMAGE: ['file', 'exiftool', 'strings', 'binwalk', 'zsteg', 'steghide', 'stegseek', 'foremost'],
        FileCategory.AUDIO: ['file', 'exiftool', 'strings', 'binwalk', 'sonic-visualiser', 'audacity', 'steghide'],
        FileCategory.VIDEO: ['file', 'exiftool', 'strings', 'binwalk', 'ffmpeg', 'foremost'],
        FileCategory.ARCHIVE: ['file', 'strings', 'binwalk', 'unzip', 'tar', '7z', 'foremost'],
        FileCategory.DOCUMENT: ['file', 'exiftool', 'strings', 'pdftotext', 'pdfimages', 'binwalk'],
        FileCategory.BINARY: ['file', 'strings', 'checksec', 'readelf', 'objdump', 'ltrace', 'strace', 'gdb', 'radare2', 'ghidra'],
        FileCategory.NETWORK: ['file', 'strings', 'tshark', 'tcpdump', 'wireshark', 'scapy'],
        FileCategory.TEXT: ['file', 'strings', 'cat', 'head', 'tail', 'grep', 'xxd'],
        FileCategory.UNKNOWN: ['file', 'strings', 'xxd', 'binwalk', 'foremost'],
    }
    
    def __init__(self):
        """Initialize the file detector."""
        mimetypes.init()
    
    def detect(self, file_path: str) -> FileInfo:
        """
        Detect file type and gather comprehensive information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            FileInfo object containing all detected information
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValueError(f"Not a file: {file_path}")
        
        # Get basic file info
        abs_path = os.path.abspath(file_path)
        name = os.path.basename(file_path)
        extension = os.path.splitext(name)[1].lower()
        size = os.path.getsize(file_path)
        
        # Detect using multiple methods
        magic_mime, magic_desc = self._detect_magic(file_path)
        file_cmd_desc = self._run_file_command(file_path)
        mime_type = magic_mime or mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        
        # Determine category
        category = self._determine_category(extension, mime_type, file_cmd_desc)
        
        # Check if executable
        is_executable = self._is_executable(file_path, category, file_cmd_desc)
        
        # Get suggested tools
        suggested_tools = self.CATEGORY_TOOLS.get(category, self.CATEGORY_TOOLS[FileCategory.UNKNOWN])
        
        # Use the most descriptive description available
        description = magic_desc or file_cmd_desc or 'Unknown file type'
        
        return FileInfo(
            path=abs_path,
            name=name,
            extension=extension,
            mime_type=mime_type,
            magic_description=description,
            category=category,
            size=size,
            is_executable=is_executable,
            suggested_tools=suggested_tools
        )
    
    def _detect_magic(self, file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect file type using magic byte signatures.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (mime_type, description) or (None, None)
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
            
            for signature, (mime, desc) in self.MAGIC_SIGNATURES.items():
                if header.startswith(signature):
                    return mime, desc
            
            # Check for text file (printable ASCII)
            if all(b < 128 and (b >= 32 or b in (9, 10, 13)) for b in header if b != 0):
                return 'text/plain', 'ASCII text'
                
        except Exception:
            pass
        
        return None, None
    
    def _run_file_command(self, file_path: str) -> str:
        """
        Run the Linux 'file' command for detection.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File command output description
        """
        try:
            result = subprocess.run(
                ['file', '-b', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return ''
    
    def _determine_category(self, extension: str, mime_type: str, description: str) -> FileCategory:
        """
        Determine the file category based on all available information.
        
        Args:
            extension: File extension
            mime_type: Detected MIME type
            description: File description from file command
            
        Returns:
            FileCategory enum value
        """
        # First try extension
        if extension in self.EXTENSION_CATEGORIES:
            return self.EXTENSION_CATEGORIES[extension]
        
        # Then try MIME type
        if mime_type:
            if mime_type.startswith('image/'):
                return FileCategory.IMAGE
            elif mime_type.startswith('audio/'):
                return FileCategory.AUDIO
            elif mime_type.startswith('video/'):
                return FileCategory.VIDEO
            elif mime_type.startswith('text/'):
                return FileCategory.TEXT
            elif 'zip' in mime_type or 'tar' in mime_type or 'gzip' in mime_type or 'rar' in mime_type:
                return FileCategory.ARCHIVE
            elif 'pdf' in mime_type:
                return FileCategory.DOCUMENT
            elif 'pcap' in mime_type:
                return FileCategory.NETWORK
            elif 'executable' in mime_type or 'elf' in mime_type.lower():
                return FileCategory.BINARY
        
        # Finally try description
        desc_lower = description.lower()
        if 'image' in desc_lower or 'png' in desc_lower or 'jpeg' in desc_lower or 'gif' in desc_lower:
            return FileCategory.IMAGE
        elif 'audio' in desc_lower or 'wave' in desc_lower or 'mp3' in desc_lower:
            return FileCategory.AUDIO
        elif 'video' in desc_lower or 'mp4' in desc_lower:
            return FileCategory.VIDEO
        elif 'archive' in desc_lower or 'zip' in desc_lower or 'tar' in desc_lower or 'gzip' in desc_lower:
            return FileCategory.ARCHIVE
        elif 'pdf' in desc_lower:
            return FileCategory.DOCUMENT
        elif 'pcap' in desc_lower or 'capture' in desc_lower:
            return FileCategory.NETWORK
        elif 'elf' in desc_lower or 'executable' in desc_lower or 'binary' in desc_lower:
            return FileCategory.BINARY
        elif 'text' in desc_lower or 'ascii' in desc_lower or 'utf' in desc_lower:
            return FileCategory.TEXT
        
        return FileCategory.UNKNOWN
    
    def _is_executable(self, file_path: str, category: FileCategory, description: str) -> bool:
        """
        Check if the file is an executable binary.
        
        Args:
            file_path: Path to the file
            category: Detected file category
            description: File description
            
        Returns:
            True if file is executable
        """
        if category == FileCategory.BINARY:
            return True
        
        desc_lower = description.lower()
        if any(term in desc_lower for term in ['executable', 'elf', 'pe32', 'mach-o']):
            return True
        
        # Check file permissions on Unix
        try:
            return os.access(file_path, os.X_OK)
        except Exception:
            return False
    
    def get_category_name(self, category: FileCategory) -> str:
        """Get human-readable category name."""
        names = {
            FileCategory.IMAGE: "Image",
            FileCategory.AUDIO: "Audio",
            FileCategory.VIDEO: "Video",
            FileCategory.ARCHIVE: "Archive",
            FileCategory.DOCUMENT: "Document",
            FileCategory.BINARY: "Binary/Executable",
            FileCategory.NETWORK: "Network Capture",
            FileCategory.TEXT: "Text",
            FileCategory.UNKNOWN: "Unknown",
        }
        return names.get(category, "Unknown")
    
    def quick_detect(self, file_path: str) -> Tuple[FileCategory, str]:
        """
        Quickly detect file category without full analysis.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (category, description)
        """
        info = self.detect(file_path)
        return info.category, info.magic_description
