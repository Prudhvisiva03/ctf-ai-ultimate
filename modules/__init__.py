"""
CTFHunter - AI-Powered CTF Assistant Modules Package
The World's First Open-Source AI CTF Solver
Version: 2.1.0
Author: Prudhvi (CTF Community)
"""

__version__ = '2.1.0'
__author__ = 'Prudhvi'

# Legacy CTFHunter modules
from .file_scan import FileScanner
from .stego_scan import StegoScanner
from .zip_scan import ArchiveScanner
from .pcap_scan import PCAPScanner
from .elf_scan import ELFScanner
from .pdf_scan import PDFScanner
from .web_scan import WebScanner
from .reporter import Reporter

# New AI-powered modules
from .ai_engine import AIEngine
from .playbook_executor import PlaybookExecutor

# OSINT & Forensics modules
from .osint_scanner import OSINTScanner
from .crypto_analyzer import analyze_crypto, detect_encoding

# New v2.1 modules
from .qr_scanner import QRScanner, scan_qr
from .hash_identifier import HashIdentifier, identify_hash, crack_hash
from .audio_stego import AudioStegoScanner, scan_audio
from .html_reporter import HTMLReporter, generate_html_report

__all__ = [
    # Legacy modules
    'FileScanner',
    'StegoScanner',
    'ArchiveScanner',
    'PCAPScanner',
    'ELFScanner',
    'PDFScanner',
    'WebScanner',
    'Reporter',
    # AI modules
    'AIEngine',
    'PlaybookExecutor',
    # OSINT & Forensics
    'OSINTScanner',
    'analyze_crypto',
    'detect_encoding',
    # New v2.1 modules
    'QRScanner',
    'scan_qr',
    'HashIdentifier',
    'identify_hash',
    'crack_hash',
    'AudioStegoScanner',
    'scan_audio',
    'HTMLReporter',
    'generate_html_report'
]
