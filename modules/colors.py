#!/usr/bin/env python3
"""
Color Utility Module for CTF-AI Ultimate
Provides cross-platform colored terminal output with emoji support
"""

import sys
import os
from typing import Optional

# Check if running on Windows
IS_WINDOWS = sys.platform.startswith('win')

# Enable ANSI colors on Windows 10+
if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass


class Colors:
    """ANSI color codes"""
    # Reset
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Bright background colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'


class Emoji:
    """Common emojis for terminal output"""
    # Status
    SUCCESS = '✅'
    ERROR = '❌'
    WARNING = '⚠️'
    INFO = 'ℹ️'
    QUESTION = '❓'
    
    # Actions
    SEARCH = '🔍'
    SCAN = '🔎'
    ANALYZE = '🔬'
    EXTRACT = '📤'
    DOWNLOAD = '⬇️'
    UPLOAD = '⬆️'
    
    # Files
    FILE = '📄'
    FOLDER = '📁'
    IMAGE = '🖼️'
    ARCHIVE = '📦'
    DOCUMENT = '📝'
    CODE = '💻'
    
    # Security
    LOCK = '🔒'
    UNLOCK = '🔓'
    KEY = '🔑'
    SHIELD = '🛡️'
    FLAG = '🚩'
    TARGET = '🎯'
    
    # Progress
    ROCKET = '🚀'
    FIRE = '🔥'
    SPARKLES = '✨'
    STAR = '⭐'
    TROPHY = '🏆'
    
    # Tools
    WRENCH = '🔧'
    HAMMER = '🔨'
    GEAR = '⚙️'
    TOOL = '🛠️'
    
    # Network
    GLOBE = '🌐'
    LINK = '🔗'
    WIFI = '📡'
    
    # AI
    ROBOT = '🤖'
    BRAIN = '🧠'
    MAGIC = '🪄'
    
    # Misc
    CLOCK = '⏰'
    HOURGLASS = '⏳'
    CHART = '📊'
    CLEAN = '🧹'
    PACKAGE = '📦'


def colorize(text: str, color: str, bold: bool = False, underline: bool = False) -> str:
    """
    Colorize text with ANSI codes
    
    Args:
        text: Text to colorize
        color: Color code from Colors class
        bold: Make text bold
        underline: Underline text
    
    Returns:
        Colorized text string
    """
    result = color
    if bold:
        result += Colors.BOLD
    if underline:
        result += Colors.UNDERLINE
    result += text + Colors.RESET
    return result


def success(text: str, emoji: bool = True) -> str:
    """Format success message"""
    prefix = f"{Emoji.SUCCESS} " if emoji else ""
    return colorize(f"{prefix}{text}", Colors.BRIGHT_GREEN, bold=True)


def error(text: str, emoji: bool = True) -> str:
    """Format error message"""
    prefix = f"{Emoji.ERROR} " if emoji else ""
    return colorize(f"{prefix}{text}", Colors.BRIGHT_RED, bold=True)


def warning(text: str, emoji: bool = True) -> str:
    """Format warning message"""
    prefix = f"{Emoji.WARNING} " if emoji else ""
    return colorize(f"{prefix}{text}", Colors.BRIGHT_YELLOW, bold=True)


def info(text: str, emoji: bool = True) -> str:
    """Format info message"""
    prefix = f"{Emoji.INFO} " if emoji else ""
    return colorize(f"{prefix}{text}", Colors.BRIGHT_CYAN)


def header(text: str, emoji: str = Emoji.STAR) -> str:
    """Format header text"""
    return colorize(f"\n{emoji} {text} {emoji}", Colors.BRIGHT_MAGENTA, bold=True)


def subheader(text: str) -> str:
    """Format subheader text"""
    return colorize(f"  {text}", Colors.CYAN, bold=True)


def highlight(text: str) -> str:
    """Highlight important text"""
    return colorize(text, Colors.BRIGHT_YELLOW, bold=True)


def dim(text: str) -> str:
    """Dim text for less important info"""
    return Colors.DIM + text + Colors.RESET


def code(text: str) -> str:
    """Format code/command text"""
    return colorize(text, Colors.BRIGHT_CYAN)


def path(text: str) -> str:
    """Format file path"""
    return colorize(text, Colors.BRIGHT_BLUE, underline=True)


def flag_text(text: str) -> str:
    """Format flag text"""
    return colorize(f"{Emoji.FLAG} {text}", Colors.BRIGHT_GREEN, bold=True)


def separator(char: str = "=", length: int = 60, color: str = Colors.BRIGHT_BLACK) -> str:
    """Create a separator line"""
    return colorize(char * length, color)


def box(text: str, width: int = 60, color: str = Colors.BRIGHT_CYAN) -> str:
    """Create a box around text"""
    lines = text.split('\n')
    top = "╔" + "═" * (width - 2) + "╗"
    bottom = "╚" + "═" * (width - 2) + "╝"
    
    result = [colorize(top, color)]
    for line in lines:
        padding = width - len(line) - 4
        result.append(colorize(f"║ {line}{' ' * padding} ║", color))
    result.append(colorize(bottom, color))
    
    return '\n'.join(result)


def progress_bar(current: int, total: int, width: int = 40, 
                 color: str = Colors.BRIGHT_GREEN) -> str:
    """
    Create a progress bar
    
    Args:
        current: Current progress value
        total: Total value
        width: Width of the progress bar
        color: Color for the filled portion
    
    Returns:
        Formatted progress bar string
    """
    if total == 0:
        percentage = 100
    else:
        percentage = int((current / total) * 100)
    
    filled = int((current / total) * width) if total > 0 else width
    bar = "█" * filled + "░" * (width - filled)
    
    return f"{colorize(bar, color)} {percentage}%"


def table_row(columns: list, widths: list, colors: Optional[list] = None) -> str:
    """
    Create a formatted table row
    
    Args:
        columns: List of column values
        widths: List of column widths
        colors: Optional list of colors for each column
    
    Returns:
        Formatted table row
    """
    if colors is None:
        colors = [Colors.WHITE] * len(columns)
    
    row = []
    for col, width, color in zip(columns, widths, colors):
        text = str(col).ljust(width)
        row.append(colorize(text, color))
    
    return " │ ".join(row)


def banner(title: str, subtitle: str = "", width: int = 70) -> str:
    """
    Create an ASCII art banner
    
    Args:
        title: Main title text
        subtitle: Optional subtitle
        width: Banner width
    
    Returns:
        Formatted banner string
    """
    lines = []
    
    # Top border
    lines.append(colorize("╔" + "═" * (width - 2) + "╗", Colors.BRIGHT_CYAN))
    
    # Title
    title_padding = (width - len(title) - 4) // 2
    lines.append(colorize(
        f"║{' ' * title_padding}{title}{' ' * (width - len(title) - title_padding - 2)}║",
        Colors.BRIGHT_MAGENTA, bold=True
    ))
    
    # Subtitle
    if subtitle:
        sub_padding = (width - len(subtitle) - 4) // 2
        lines.append(colorize(
            f"║{' ' * sub_padding}{subtitle}{' ' * (width - len(subtitle) - sub_padding - 2)}║",
            Colors.BRIGHT_CYAN
        ))
    
    # Bottom border
    lines.append(colorize("╚" + "═" * (width - 2) + "╝", Colors.BRIGHT_CYAN))
    
    return '\n'.join(lines)


def gradient_text(text: str, start_color: str = Colors.BRIGHT_CYAN, 
                  end_color: str = Colors.BRIGHT_MAGENTA) -> str:
    """
    Create gradient text effect (simplified version)
    
    Args:
        text: Text to apply gradient to
        start_color: Starting color
        end_color: Ending color
    
    Returns:
        Text with gradient effect
    """
    # Simplified: alternate between colors
    result = []
    for i, char in enumerate(text):
        color = start_color if i % 2 == 0 else end_color
        result.append(colorize(char, color))
    return ''.join(result)


# Convenience print functions
def print_success(text: str, emoji: bool = True):
    """Print success message"""
    print(success(text, emoji))


def print_error(text: str, emoji: bool = True):
    """Print error message"""
    print(error(text, emoji))


def print_warning(text: str, emoji: bool = True):
    """Print warning message"""
    print(warning(text, emoji))


def print_info(text: str, emoji: bool = True):
    """Print info message"""
    print(info(text, emoji))


def print_header(text: str, emoji: str = Emoji.STAR):
    """Print header"""
    print(header(text, emoji))


def print_separator(char: str = "=", length: int = 60, color: str = Colors.BRIGHT_BLACK):
    """Print separator line"""
    print(separator(char, length, color))


def print_banner(title: str, subtitle: str = "", width: int = 70):
    """Print banner"""
    print(banner(title, subtitle, width))


# Test function
if __name__ == "__main__":
    print_banner("CTF-AI Ultimate", "Color Test Suite")
    print()
    
    print_success("This is a success message!")
    print_error("This is an error message!")
    print_warning("This is a warning message!")
    print_info("This is an info message!")
    print()
    
    print_header("Testing Headers", Emoji.ROCKET)
    print(subheader("This is a subheader"))
    print()
    
    print(f"Highlighted text: {highlight('IMPORTANT')}")
    print(f"Code example: {code('python script.py')}")
    print(f"File path: {path('/path/to/file.txt')}")
    print(flag_text("picoCTF{test_flag_123}"))
    print()
    
    print_separator()
    print(progress_bar(75, 100))
    print_separator()
    print()
    
    print(box("This is a boxed message\nWith multiple lines", width=40))
