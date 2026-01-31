#!/usr/bin/env python3
"""
CTFHunter CLI - Command Line Interface
======================================

Professional CLI for the CTFHunter CTF automation tool.
Provides easy-to-use commands for analyzing CTF challenges.
"""

import argparse
import sys
import os
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from . import __version__, __description__
from .core import CTFHunter
from .detector import FileDetector


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='ctfhunter',
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ctfhunter --target challenge.png --mode auto
  ctfhunter --target capture.pcap --mode deep
  ctfhunter --target binary.elf --output ./results
  ctfhunter --target https://target.com --mode quick
  ctfhunter --list-tools
  ctfhunter --detect challenge.zip

For more information, visit: https://github.com/Prudhvisiva03/ctfhunter
        """
    )
    
    # Main arguments
    parser.add_argument(
        '--target', '-t',
        type=str,
        help='Target file or URL to analyze'
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['auto', 'quick', 'deep'],
        default='auto',
        help='Analysis mode: auto (default), quick, or deep'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='output',
        help='Output directory for results (default: ./output)'
    )
    
    # Utility arguments
    parser.add_argument(
        '--detect', '-d',
        type=str,
        metavar='FILE',
        help='Quick file type detection only'
    )
    
    parser.add_argument(
        '--list-tools', '-l',
        action='store_true',
        help='List available tools and their status'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output (only show flags)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output (show all tool outputs)'
    )
    
    return parser


def print_banner(console: Console):
    """Print the CTFHunter banner."""
    banner = """
[bold cyan]
   ██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██║        ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██║        ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold cyan]
[dim]                    Professional CTF Automation Tool v{version}[/dim]
    """.format(version=__version__)
    
    console.print(banner)


def list_tools(console: Console):
    """List available tools and their installation status."""
    hunter = CTFHunter()
    tools = hunter.list_tools()
    
    table = Table(title="Tool Availability", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan", width=20)
    table.add_column("Status", style="green", width=15)
    table.add_column("Install Command", style="dim", width=35)
    
    install_commands = {
        'file': 'apt install file',
        'strings': 'apt install binutils',
        'exiftool': 'apt install libimage-exiftool-perl',
        'binwalk': 'apt install binwalk',
        'foremost': 'apt install foremost',
        'steghide': 'apt install steghide',
        'stegseek': 'apt install stegseek',
        'zsteg': 'gem install zsteg',
        'tshark': 'apt install tshark',
        'checksec': 'apt install checksec',
        'readelf': 'apt install binutils',
        'objdump': 'apt install binutils',
        'gdb': 'apt install gdb',
        'radare2': 'apt install radare2',
        'john': 'apt install john',
        'hashcat': 'apt install hashcat',
        'ffmpeg': 'apt install ffmpeg',
        'pdftotext': 'apt install poppler-utils',
        'unzip': 'apt install unzip',
        'tar': 'apt install tar',
        '7z': 'apt install p7zip-full',
    }
    
    for tool, available in sorted(tools.items()):
        status = "[green]✓ Installed[/green]" if available else "[red]✗ Missing[/red]"
        install_cmd = install_commands.get(tool, f"apt install {tool}")
        table.add_row(tool, status, install_cmd if not available else "")
    
    console.print(table)
    
    installed = sum(1 for v in tools.values() if v)
    total = len(tools)
    
    console.print(f"\n[cyan]Tools installed: {installed}/{total}[/cyan]")
    
    if installed < total:
        console.print("\n[yellow]TIP: Install missing tools with:[/yellow]")
        console.print("[dim]sudo apt install binwalk foremost steghide tshark checksec[/dim]")


def detect_file(console: Console, filepath: str):
    """Quick file type detection."""
    if not os.path.exists(filepath):
        console.print(f"[red]Error: File not found: {filepath}[/red]")
        return
    
    detector = FileDetector()
    
    try:
        info = detector.detect(filepath)
        
        table = Table(title="File Detection", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="green")
        
        table.add_row("Name", info.name)
        table.add_row("Extension", info.extension or "(none)")
        table.add_row("Size", f"{info.size:,} bytes")
        table.add_row("MIME Type", info.mime_type)
        table.add_row("Description", info.magic_description)
        table.add_row("Category", detector.get_category_name(info.category))
        table.add_row("Executable", "Yes" if info.is_executable else "No")
        
        console.print(table)
        
        console.print("\n[cyan]Suggested tools:[/cyan]")
        for tool in info.suggested_tools[:8]:
            console.print(f"  • {tool}")
            
    except Exception as e:
        console.print(f"[red]Error detecting file: {e}[/red]")


def analyze_target(console: Console, target: str, mode: str, output_dir: str, quiet: bool):
    """Analyze a target file or URL."""
    # Validate target
    if not target.startswith(('http://', 'https://')) and not os.path.exists(target):
        console.print(f"[red]Error: Target not found: {target}[/red]")
        sys.exit(1)
    
    try:
        hunter = CTFHunter(output_dir=output_dir, verbose=not quiet)
        result = hunter.analyze(target, mode=mode)
        
        # Return exit code based on flags found
        if result.flags_found:
            return 0
        return 1
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        if not quiet:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


def main():
    """Main entry point."""
    console = Console()
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle utility commands
    if args.list_tools:
        print_banner(console)
        list_tools(console)
        return 0
    
    if args.detect:
        print_banner(console)
        detect_file(console, args.detect)
        return 0
    
    # Require target for analysis
    if not args.target:
        print_banner(console)
        console.print("[yellow]No target specified. Use --help for usage information.[/yellow]")
        console.print("\n[cyan]Quick Start:[/cyan]")
        console.print("  ctfhunter --target challenge.png --mode auto")
        console.print("  ctfhunter --target capture.pcap --mode deep")
        console.print("  ctfhunter --list-tools")
        return 1
    
    # Run analysis
    return analyze_target(
        console=console,
        target=args.target,
        mode=args.mode,
        output_dir=args.output,
        quiet=args.quiet
    )


if __name__ == '__main__':
    sys.exit(main() or 0)
