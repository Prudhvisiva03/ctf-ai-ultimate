"""
CTFHunter - AI-Powered CTF Assistant Modules Package
The World's First Open-Source AI CTF Solver
Version: 3.0.0
Author: Prudhvi (CTF Community)
"""

__version__ = '3.0.0'
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
from .ai_solver import AISolver
from .playbook_executor import PlaybookExecutor

# OSINT & Forensics modules
from .osint_scanner import OSINTScanner
from .crypto_analyzer import analyze_crypto, detect_encoding

# New v2.1 modules
from .qr_scanner import QRScanner, scan_qr
from .hash_identifier import HashIdentifier, identify_hash, crack_hash
from .audio_stego import AudioStegoScanner, scan_audio
from .html_reporter import HTMLReporter, generate_html_report

# New v2.2 modules - Advanced Analysis
from .encoding_detector import EncodingDetector, analyze_encoding
from .pattern_extractor import PatternExtractor, extract_patterns
from .magic_checker import MagicChecker, check_magic
from .cipher_cracker import CipherCracker, crack_cipher
from .chain_decoder import ChainDecoder, decode_chain, decode_file
from .tool_installer import ToolInstaller

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
    'AISolver',
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
    'generate_html_report',
    # New v2.2 modules
    'EncodingDetector',
    'analyze_encoding',
    'PatternExtractor',
    'extract_patterns',
    'MagicChecker',
    'check_magic',
    'CipherCracker',
    'crack_cipher',
    'ChainDecoder',
    'decode_chain',
    'decode_file',
    'ToolInstaller',
]
