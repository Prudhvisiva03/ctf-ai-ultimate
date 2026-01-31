"""
CTFHunter - Core Engine
=======================

Main orchestration engine that coordinates file detection,
module execution, and result aggregation.
"""

import os
import sys
import json
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from .detector import FileDetector, FileInfo, FileCategory
from .flag_finder import FlagFinder, FlagMatch
from .modules import (
    SteganographyModule,
    CryptoModule,
    ForensicsModule,
    WebModule,
    ReverseModule,
    NetworkModule
)


@dataclass
class ToolResult:
    """Result from running a tool."""
    tool_name: str
    command: str
    success: bool
    output: str
    error: str
    execution_time: float
    flags_found: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result for a challenge."""
    target_file: str
    file_info: Dict[str, Any]
    analysis_time: str
    tools_run: List[ToolResult]
    flags_found: List[FlagMatch]
    extracted_files: List[str]
    summary: str
    output_directory: str


class CTFHunter:
    """
    Main CTFHunter orchestration engine.
    
    Coordinates file analysis, tool execution, and result aggregation
    for automated CTF challenge solving.
    """
    
    def __init__(self, output_dir: str = "output", verbose: bool = True):
        """
        Initialize CTFHunter.
        
        Args:
            output_dir: Base directory for output files
            verbose: Enable verbose output
        """
        self.output_dir = os.path.abspath(output_dir)
        self.verbose = verbose
        self.console = Console()
        
        # Initialize components
        self.detector = FileDetector()
        self.flag_finder = FlagFinder()
        
        # Initialize modules
        self.modules = {
            FileCategory.IMAGE: SteganographyModule(),
            FileCategory.AUDIO: SteganographyModule(),
            FileCategory.ARCHIVE: ForensicsModule(),
            FileCategory.DOCUMENT: ForensicsModule(),
            FileCategory.BINARY: ReverseModule(),
            FileCategory.NETWORK: NetworkModule(),
            FileCategory.TEXT: CryptoModule(),
            FileCategory.UNKNOWN: ForensicsModule(),
            FileCategory.VIDEO: ForensicsModule(),
        }
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
    
    def analyze(self, target: str, mode: str = "auto") -> AnalysisResult:
        """
        Analyze a CTF challenge file.
        
        Args:
            target: Path to target file
            mode: Analysis mode ('auto', 'quick', 'deep')
            
        Returns:
            AnalysisResult object
        """
        start_time = datetime.now()
        
        # Validate target
        if not os.path.exists(target):
            self.console.print(f"[red]Error: File not found: {target}[/red]")
            raise FileNotFoundError(f"File not found: {target}")
        
        # Create challenge output directory
        challenge_name = Path(target).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        challenge_dir = os.path.join(self.output_dir, f"{challenge_name}_{timestamp}")
        os.makedirs(challenge_dir, exist_ok=True)
        extracted_dir = os.path.join(challenge_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)
        
        # Copy target to output directory
        target_copy = os.path.join(challenge_dir, os.path.basename(target))
        shutil.copy2(target, target_copy)
        
        self._print_banner()
        self.console.print(f"\n[cyan]🎯 Target:[/cyan] {target}")
        self.console.print(f"[cyan]📁 Output:[/cyan] {challenge_dir}")
        self.console.print(f"[cyan]⚙️  Mode:[/cyan] {mode}\n")
        
        # Step 1: Detect file type
        self.console.print(Panel("[bold yellow]STEP 1: File Detection[/bold yellow]"))
        file_info = self.detector.detect(target)
        self._print_file_info(file_info)
        
        # Step 2: Run analysis tools
        self.console.print(Panel("[bold yellow]STEP 2: Running Analysis Tools[/bold yellow]"))
        tool_results = self._run_analysis(target, file_info, challenge_dir, extracted_dir, mode)
        
        # Step 3: Search for flags
        self.console.print(Panel("[bold yellow]STEP 3: Flag Search[/bold yellow]"))
        all_flags = self._search_flags(target, challenge_dir, extracted_dir, tool_results)
        
        # Step 4: Generate summary
        self.console.print(Panel("[bold yellow]STEP 4: Results Summary[/bold yellow]"))
        
        # Get list of extracted files
        extracted_files = []
        if os.path.exists(extracted_dir):
            for root, dirs, files in os.walk(extracted_dir):
                for f in files:
                    extracted_files.append(os.path.join(root, f))
        
        # Create result
        result = AnalysisResult(
            target_file=target,
            file_info=asdict(file_info),
            analysis_time=str(datetime.now() - start_time),
            tools_run=tool_results,
            flags_found=all_flags,
            extracted_files=extracted_files,
            summary=self._generate_summary(file_info, tool_results, all_flags),
            output_directory=challenge_dir
        )
        
        # Save results
        self._save_results(result, challenge_dir)
        
        # Print final summary
        self._print_final_summary(result)
        
        return result
    
    def _print_banner(self):
        """Print the CTFHunter banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗████████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗║
║  ██╔════╝╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝║
║  ██║        ██║   █████╗  ███████║██║   ██║██╔██╗ ██║   ██║   ║
║  ██║        ██║   ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ║
║  ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ║
║   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ║
║                                                               ║
║           Professional CTF Automation Tool v1.0               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
    
    def _print_file_info(self, info: FileInfo):
        """Print detected file information."""
        table = Table(title="File Information", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="green")
        
        table.add_row("Name", info.name)
        table.add_row("Path", info.path)
        table.add_row("Extension", info.extension or "(none)")
        table.add_row("Size", self._format_size(info.size))
        table.add_row("MIME Type", info.mime_type)
        table.add_row("Description", info.magic_description)
        table.add_row("Category", self.detector.get_category_name(info.category))
        table.add_row("Executable", "Yes" if info.is_executable else "No")
        table.add_row("Suggested Tools", ", ".join(info.suggested_tools[:5]) + "...")
        
        self.console.print(table)
        self.console.print()
    
    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def _run_analysis(self, target: str, file_info: FileInfo, 
                      challenge_dir: str, extracted_dir: str, mode: str) -> List[ToolResult]:
        """Run analysis tools based on file type."""
        results = []
        
        # Always run basic tools
        basic_tools = [
            ("file", ["file", target]),
            ("strings", ["strings", target]),
        ]
        
        # Add exiftool for images/audio/video
        if file_info.category in [FileCategory.IMAGE, FileCategory.AUDIO, FileCategory.VIDEO, FileCategory.DOCUMENT]:
            basic_tools.append(("exiftool", ["exiftool", target]))
        
        # Run basic tools
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            for tool_name, command in basic_tools:
                task = progress.add_task(f"Running {tool_name}...", total=None)
                result = self._run_tool(tool_name, command, challenge_dir)
                results.append(result)
                if result.success:
                    progress.update(task, description=f"[green]✓[/green] {tool_name}")
                else:
                    progress.update(task, description=f"[yellow]○[/yellow] {tool_name} (not available)")
                progress.remove_task(task)
        
        # Get the appropriate module
        module = self.modules.get(file_info.category, self.modules[FileCategory.UNKNOWN])
        
        # Run module-specific analysis
        self.console.print(f"\n[cyan]Running {self.detector.get_category_name(file_info.category)} analysis...[/cyan]\n")
        module_results = module.analyze(target, challenge_dir, extracted_dir, mode)
        results.extend(module_results)
        
        return results
    
    def _run_tool(self, tool_name: str, command: List[str], 
                  output_dir: str, timeout: int = 60) -> ToolResult:
        """
        Run a tool and capture its output.
        
        Args:
            tool_name: Name of the tool
            command: Command to run
            output_dir: Directory to save output
            timeout: Command timeout in seconds
            
        Returns:
            ToolResult object
        """
        start = datetime.now()
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            elapsed = (datetime.now() - start).total_seconds()
            
            # Save output to file
            output_file = os.path.join(output_dir, f"{tool_name}_output.txt")
            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"Command: {' '.join(command)}\n")
                f.write(f"Exit Code: {result.returncode}\n")
                f.write(f"{'='*60}\n")
                f.write("STDOUT:\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n{'='*60}\n")
                    f.write("STDERR:\n")
                    f.write(result.stderr)
            
            # Search for flags in output
            flags = []
            for match in self.flag_finder.search_text(result.stdout, tool_name):
                flags.append(match.flag)
            
            return ToolResult(
                tool_name=tool_name,
                command=' '.join(command),
                success=result.returncode == 0,
                output=result.stdout[:5000],  # Limit output size
                error=result.stderr[:1000] if result.stderr else "",
                execution_time=elapsed,
                flags_found=flags
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=tool_name,
                command=' '.join(command),
                success=False,
                output="",
                error="Command timed out",
                execution_time=timeout,
                flags_found=[]
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name=tool_name,
                command=' '.join(command),
                success=False,
                output="",
                error=f"Tool '{tool_name}' not found. Please install it.",
                execution_time=0,
                flags_found=[]
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                command=' '.join(command),
                success=False,
                output="",
                error=str(e),
                execution_time=0,
                flags_found=[]
            )
    
    def _search_flags(self, target: str, challenge_dir: str, 
                      extracted_dir: str, tool_results: List[ToolResult]) -> List[FlagMatch]:
        """Search for flags in all available data."""
        all_flags: List[FlagMatch] = []
        seen_flags = set()
        
        # Search original file
        self.console.print("[dim]Searching original file...[/dim]")
        for match in self.flag_finder.search_file(target):
            if match.flag not in seen_flags:
                seen_flags.add(match.flag)
                all_flags.append(match)
        
        # Search tool outputs
        self.console.print("[dim]Searching tool outputs...[/dim]")
        for result in tool_results:
            for flag in result.flags_found:
                if flag not in seen_flags:
                    seen_flags.add(flag)
                    all_flags.append(FlagMatch(
                        flag=flag,
                        pattern_name="tool_output",
                        source=result.tool_name,
                        context=""
                    ))
            
            # Also search full output
            for match in self.flag_finder.search_text(result.output, result.tool_name):
                if match.flag not in seen_flags:
                    seen_flags.add(match.flag)
                    all_flags.append(match)
        
        # Search extracted files
        if os.path.exists(extracted_dir):
            self.console.print("[dim]Searching extracted files...[/dim]")
            for match in self.flag_finder.search_directory(extracted_dir):
                if match.flag not in seen_flags:
                    seen_flags.add(match.flag)
                    all_flags.append(match)
        
        # Search output directory files
        self.console.print("[dim]Searching output files...[/dim]")
        for file in os.listdir(challenge_dir):
            if file.endswith('_output.txt'):
                filepath = os.path.join(challenge_dir, file)
                for match in self.flag_finder.search_file(filepath):
                    if match.flag not in seen_flags:
                        seen_flags.add(match.flag)
                        all_flags.append(match)
        
        return all_flags
    
    def _generate_summary(self, file_info: FileInfo, 
                          tool_results: List[ToolResult], 
                          flags: List[FlagMatch]) -> str:
        """Generate analysis summary."""
        lines = []
        lines.append(f"File: {file_info.name}")
        lines.append(f"Type: {self.detector.get_category_name(file_info.category)}")
        lines.append(f"Description: {file_info.magic_description}")
        lines.append("")
        
        successful_tools = [r for r in tool_results if r.success]
        failed_tools = [r for r in tool_results if not r.success]
        
        lines.append(f"Tools Run: {len(tool_results)}")
        lines.append(f"  - Successful: {len(successful_tools)}")
        lines.append(f"  - Failed: {len(failed_tools)}")
        lines.append("")
        
        if flags:
            lines.append(f"🚩 FLAGS FOUND: {len(flags)}")
            for i, flag in enumerate(flags, 1):
                lines.append(f"  [{i}] {flag.flag}")
        else:
            lines.append("No flags found automatically.")
            lines.append("Check the output files for manual analysis.")
        
        return '\n'.join(lines)
    
    def _save_results(self, result: AnalysisResult, challenge_dir: str):
        """Save analysis results to files."""
        # Save JSON report
        json_report = os.path.join(challenge_dir, "report.json")
        
        # Convert to serializable format
        report_data = {
            "target_file": result.target_file,
            "file_info": result.file_info,
            "analysis_time": result.analysis_time,
            "tools_run": [
                {
                    "tool_name": r.tool_name,
                    "command": r.command,
                    "success": r.success,
                    "execution_time": r.execution_time,
                    "flags_found": r.flags_found
                }
                for r in result.tools_run
            ],
            "flags_found": [
                {
                    "flag": f.flag,
                    "pattern_name": f.pattern_name,
                    "source": f.source
                }
                for f in result.flags_found
            ],
            "extracted_files": result.extracted_files,
            "summary": result.summary
        }
        
        with open(json_report, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Save text report
        txt_report = os.path.join(challenge_dir, "report.txt")
        with open(txt_report, 'w') as f:
            f.write("="*60 + "\n")
            f.write("CTFHunter Analysis Report\n")
            f.write("="*60 + "\n\n")
            f.write(result.summary)
            f.write("\n\n")
            f.write("="*60 + "\n")
            f.write("Tool Outputs\n")
            f.write("="*60 + "\n")
            for tool in result.tools_run:
                f.write(f"\n[{tool.tool_name}]\n")
                f.write(f"Command: {tool.command}\n")
                f.write(f"Status: {'SUCCESS' if tool.success else 'FAILED'}\n")
                if tool.error:
                    f.write(f"Error: {tool.error}\n")
        
        self.console.print(f"\n[green]✓ Results saved to:[/green] {challenge_dir}")
    
    def _print_final_summary(self, result: AnalysisResult):
        """Print final analysis summary."""
        self.console.print()
        
        # Print flags found
        if result.flags_found:
            self.console.print(Panel(
                f"[bold green]🚩 FOUND {len(result.flags_found)} FLAG(S)![/bold green]",
                style="green"
            ))
            
            table = Table(show_header=True, header_style="bold green")
            table.add_column("#", style="dim", width=4)
            table.add_column("Flag", style="green")
            table.add_column("Source", style="cyan")
            
            for i, flag in enumerate(result.flags_found, 1):
                table.add_row(str(i), flag.flag, flag.source)
            
            self.console.print(table)
        else:
            self.console.print(Panel(
                "[yellow]No flags found automatically.\nCheck output files for manual analysis.[/yellow]",
                style="yellow"
            ))
        
        # Print extracted files count
        if result.extracted_files:
            self.console.print(f"\n[cyan]📦 Extracted {len(result.extracted_files)} file(s)[/cyan]")
        
        # Print output location
        self.console.print(f"\n[dim]Full results saved to: {result.output_directory}[/dim]")
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick scan without full analysis.
        
        Args:
            target: Path to target file
            
        Returns:
            Quick scan results
        """
        file_info = self.detector.detect(target)
        flags = self.flag_finder.search_file(target)
        
        return {
            "file": target,
            "type": self.detector.get_category_name(file_info.category),
            "description": file_info.magic_description,
            "size": self._format_size(file_info.size),
            "flags_found": [f.flag for f in flags],
            "suggested_tools": file_info.suggested_tools
        }
    
    def list_tools(self) -> Dict[str, bool]:
        """
        Check which tools are installed.
        
        Returns:
            Dictionary of tool names and availability
        """
        tools = [
            'file', 'strings', 'exiftool', 'binwalk', 'foremost',
            'steghide', 'stegseek', 'zsteg', 'tshark', 'checksec',
            'readelf', 'objdump', 'gdb', 'radare2', 'john',
            'hashcat', 'ffmpeg', 'pdftotext', 'unzip', 'tar', '7z'
        ]
        
        availability = {}
        for tool in tools:
            availability[tool] = shutil.which(tool) is not None
        
        return availability
