"""
CTFHunter - Professional Kali Linux CTF Automation Tool
========================================================

A modular CLI tool that automatically detects CTF challenge file types,
runs the correct tools in the best order, and extracts possible flags.

Author: CTFHunter Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "CTFHunter Team"
__description__ = "Professional Kali Linux CTF Automation Tool"

from .core import CTFHunter
from .detector import FileDetector
from .flag_finder import FlagFinder

__all__ = ["CTFHunter", "FileDetector", "FlagFinder", "__version__"]
