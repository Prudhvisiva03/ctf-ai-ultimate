"""
CTFHunter Ultimate - Modules Package
Includes both legacy CTFHunter modules and new AI-powered components
"""

__version__ = '2.0.0'
__author__ = 'CTF Community'

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
    'PlaybookExecutor'
]
