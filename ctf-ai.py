#!/usr/bin/env python3
"""






















































































}    ]        "💡 QR codes may be split across multiple images"        "💡 Check for inverted colors (white QR on black background)",        "💡 Multiple QR codes may be layered or hidden",        "💡 QR codes can be partially damaged - try error correction",    "hints": [    ],        "THM\\{[^}]+\\}"        "HTB\\{[^}]+\\}",        "CTF\\{[^}]+\\}",        "FLAG\\{[^}]+\\}",        "flag\\{[^}]+\\}",        "DCH\\{[^}]+\\}",        "digitalcyberhunt\\{[^}]+\\}",    "flag_patterns": [    ],        }            "flag_search": true            "timeout": 30,            "args": ["-n", "6", "{target}"],            "tool": "strings",            "type": "tool",            "description": "Search for hidden strings",            "name": "String Search",        {        },            "flag_search": true            "timeout": 30,            "args": ["{target}"],            "tool": "exiftool",            "type": "tool",            "description": "Check image metadata",            "name": "EXIF Check",        {        },            "flag_search": true            "timeout": 30,            "args": ["--raw", "-q", "/tmp/enhanced_qr.png"],            "tool": "zbarimg",            "type": "tool",            "description": "Try decoding enhanced image",            "name": "Enhanced QR Decode",        {        },            "flag_search": false            "timeout": 30,            "args": ["{target}", "-contrast", "-sharpen", "0x2", "/tmp/enhanced_qr.png"],            "tool": "convert",            "type": "tool",            "description": "Try to enhance image for better QR detection",            "name": "Image Enhancement",        {        },            "flag_search": true            "timeout": 30,            "args": ["{target}"],            "tool": "zxing",            "type": "tool",            "description": "Decode using zxing library",            "name": "Zxing Decode",        {        },            "flag_search": true            "timeout": 30,            "args": ["--raw", "-q", "{target}"],            "tool": "zbarimg",            "type": "tool",            "description": "Decode QR codes using zbarimg",            "name": "ZBar QR Decode",        {        },            "flag_search": false            "timeout": 10,            "args": ["{target}"],            "tool": "file",            "type": "tool",            "description": "Verify image file type",            "name": "File Type Check",        {    "methods": [    "execution_strategy": "sequential",    "file_types": [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"],    "category": "qr",    "description": "Detect and decode QR codes from images - Very common in CTF challenges",CTFHunter AI - Interactive AI-Powered CTF Assistant
The world's first open-source AI CTF solver with natural language interface
Version: 2.1.0
Author: Prudhvi (CTF Community)

Features:
- Natural language commands
- Multi-AI support (OpenAI, Ollama, Claude, Groq)
- Intelligent playbook selection
- Adaptive execution strategies
- Kali Linux tool integration
"""

import sys
import os
import subprocess
import json
import argparse
from pathlib import Path

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.ai_engine import AIEngine
from modules.playbook_executor import PlaybookExecutor
from modules.file_scan import FileScanner
from modules.reporter import Reporter
from modules.colors import (
    Colors, Emoji, colorize, success, error, warning, info,
    header, highlight, code, path as color_path, flag_text,
    separator, print_success, print_error, print_warning,
    print_info, print_header, print_separator, print_banner as color_banner
)


class CTF_AI_Assistant:
    """Interactive AI-powered CTF assistant"""
    
    def __init__(self, config_file='config.json'):
        """Initialize the assistant"""
        self.config = self.load_config(config_file)
        
        # Initialize components
        self.ai_engine = AIEngine(self.config)
        self.playbook_executor = PlaybookExecutor(self.config)
        self.file_scanner = FileScanner(self.config)
        # Reporter will be created per-challenge with unique output dir
        
        self.session_history = []
        
    def load_config(self, config_file):
        """Load configuration"""
        try:
            # 1. Check current directory first (essential for sudo)
            current_dir_config = os.path.join(os.getcwd(), config_file)
            if os.path.exists(current_dir_config):
                print(f"[*] Loading config from: {current_dir_config}")
                with open(current_dir_config, 'r') as f:
                    config = json.load(f)
                    self._handle_cleanup(config)
                    return config

            # 2. Check script directory
            script_dir = Path(__file__).parent
            config_path = script_dir / config_file
            
            if config_path.exists():
                print(f"[*] Loading config from: {config_path}")
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self._handle_cleanup(config)
                    return config
            else:
                print(f"⚠️  Config file not found, using defaults")
                return self.get_default_config()
        except Exception as e:
            print(f"⚠️  Error loading config: {e}")
            return self.get_default_config()

    def _handle_cleanup(self, config):
        """Handle auto-cleanup of output directory"""
        if config.get('auto_cleanup', False):
            output_dir = config.get('output_directory', 'output')
            if os.path.exists(output_dir):
                import shutil
                print(f"🧹 Auto-cleanup: Removing {output_dir}...")
                shutil.rmtree(output_dir)
                # Recreate it immediately to avoid errors
                os.makedirs(output_dir, exist_ok=True)
    
    def get_default_config(self):
        """Default configuration"""
        return {
            'ai_provider': 'openai',
            'ai_model': 'gpt-4',
            'output_directory': 'output',
            'flag_patterns': [
                r'digitalcyberhunt\{[^}]+\}',
                r'DCH\{[^}]+\}',
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'picoCTF\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'THM\{[^}]+\}',
                r'OSCTF\{[^}]+\}',
                r'cyberhunt\{[^}]+\}'
            ]
        }
    
    def print_banner(self):
        """Print welcome banner"""
        # Colorful ASCII art banner
        print()
        print(colorize("╔═══════════════════════════════════════════════════════════════╗", Colors.BRIGHT_CYAN))
        print(colorize("║                                                               ║", Colors.BRIGHT_CYAN))
        print(colorize("║   ▄████▄   ▀█████████▄     ▄████████  ▄█   ▄██████▄   ▄█      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║  ███    ███   ███    ███   ███    ███ ███  ███    ███ ███      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║  ███    █▀    ███    ███   ███    █▀  ███▌ ███    ███ ███      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║  ███          ███    ███  ▄███▄▄▄     ███▌ ███    ███ ███      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║  ███          ███    ███ ▀▀███▀▀▀     ███▌ ███    ███ ███      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║  ███    █▄    ███    ███   ███        ███  ███    ███ ███      ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║   ▀██████▀   ▄█████████▀   ███        █▀   ▀██████▀   █▀       ║", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("║                                                               ║", Colors.BRIGHT_CYAN))
        print(colorize("║         ULTIMATE AI-POWERED CTF ASSISTANT v2.0                ║", Colors.BRIGHT_YELLOW, bold=True))
        print(colorize("║              Your Personal CTF Solver                         ║", Colors.BRIGHT_CYAN))
        print(colorize("║                                                               ║", Colors.BRIGHT_CYAN))
        print(colorize("╚═══════════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
        print()
        
        # Feature highlights
        features = [
            (f"{Emoji.ROBOT} AI-Powered", Colors.BRIGHT_GREEN),
            (f"{Emoji.WRENCH} Kali Tools", Colors.BRIGHT_YELLOW),
            (f"{Emoji.BRAIN} Smart Playbooks", Colors.BRIGHT_BLUE),
            (f"{Emoji.TARGET} Flag Hunter", Colors.BRIGHT_RED)
        ]
        print(" | ".join([colorize(text, color, bold=True) for text, color in features]))
        print()
        
        # Show AI status
        if self.ai_engine.is_available():
            print_success(f"AI Engine: {self.ai_engine.provider} ({self.ai_engine.model})", emoji=True)
        else:
            print_warning("AI Engine: Offline mode (manual tools only)", emoji=True)
        
        print_success(f"Playbooks loaded: {len(self.playbook_executor.get_available_playbooks())}", emoji=True)
        print("")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        self.print_banner()
        
        print(colorize("━" * 65, Colors.BRIGHT_BLACK))
        print(colorize("Type your request in natural language or use commands:", Colors.BRIGHT_CYAN, bold=True))
        print(f"  {Emoji.TARGET} {colorize('solve <file>', Colors.BRIGHT_GREEN)}        - Analyze and solve a challenge")
        print(f"  {Emoji.SEARCH} {colorize('analyze <file>', Colors.BRIGHT_YELLOW)}      - Deep analysis without AI")
        print(f"  {Emoji.MAGIC} {colorize('menu', Colors.BRIGHT_MAGENTA)}                - Interactive challenge menu")
        print(f"  {Emoji.FOLDER} {colorize('playbooks', Colors.BRIGHT_BLUE)}           - List available playbooks")
        print(f"  {Emoji.GEAR} {colorize('settings', Colors.BRIGHT_MAGENTA)}            - Show current settings")
        print(f"  {Emoji.QUESTION} {colorize('help', Colors.BRIGHT_CYAN)}                - Show help")
        print(f"  {Emoji.UNLOCK} {colorize('quit/exit', Colors.BRIGHT_RED)}           - Exit")
        print(colorize("━" * 65, Colors.BRIGHT_BLACK))
        print("")
        
        while True:
            try:
                # Get user input with colorful prompt
                prompt = colorize(f"{Emoji.ROBOT} You: ", Colors.BRIGHT_CYAN, bold=True)
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                # Handle quit
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print()
                    print(colorize(f"👋 Goodbye! Happy hacking! {Emoji.FIRE}", Colors.BRIGHT_YELLOW, bold=True))
                    print()
                    break
                
                # Handle commands
                if user_input.lower() == 'help':
                    self.show_help()
                    continue
                
                if user_input.lower() == 'playbooks':
                    self.list_playbooks()
                    continue
                
                if user_input.lower() == 'settings':
                    self.show_settings()
                    continue
                
                if user_input.lower() == 'menu':
                    self.menu_mode()
                    continue
                
                # Process natural language request
                self.process_request(user_input)
                
            except KeyboardInterrupt:
                print_warning("\nInterrupted by user", emoji=True)
                break
            except Exception as e:
                print_error(f"Error: {str(e)}", emoji=True)
                import traceback
                traceback.print_exc()
    
    def process_request(self, request: str):
        """Process a naturallanguage request"""
        print("")
        
        # Parse the request
        parsed = self.parse_request(request)
        
        if not parsed['valid']:
            print_error(parsed.get('error', 'Invalid request'), emoji=True)
            print_info("Try: solve <filename> or help", emoji=False)
            return
        
        action = parsed['action']
        target = parsed['target']
        
        if action in ['solve', 'analyze', 'find flag in', 'check']:
            self.solve_challenge(target, use_ai=(action == 'solve'))
        else:
            print_error(f"Unknown action: {action}", emoji=True)
            print_info("Try: solve <filename>", emoji=False)
    
    def parse_request(self, request: str) -> dict:
        """Parse natural language request"""
        request_lower = request.lower()
        
        # Common patterns
        patterns = {
            'solve': ['solve', 'find flag in', 'analyze', 'hack', 'crack'],
            'analyze': ['check', 'scan', 'examine', 'inspect']
        }
        
        # Find action
        action = None
        for key, keywords in patterns.items():
            if any(kw in request_lower for kw in keywords):
                action = key
                break
        
        if not action:
            return {'valid': False, 'error': 'Could not understand request'}
        
        # Extract target (filename/URL)
        words = request.split()
        
        # Find potential file/URL
        target = None
        for word in words:
            # Check if it's a file
            if os.path.exists(word):
                target = word
                break
            # Check if it's a URL
            if word.startswith('http://') or word.startswith('https://'):
                target = word
                break
            # Check if it looks like a filename
            if '.' in word:
                target = word
                break
        
        if not target:
            # Check if it's a system command
            import shutil
            command_word = words[0]
            if shutil.which(command_word):
                 print_info(f"Executing system command: {request}", emoji=False)
                 os.system(request)
                 return {'valid': False, 'error': 'System command executed'}
            
            return {'valid': False, 'error': 'No target file or URL specified'}
        
        return {
            'valid': True,
            'action': action,
            'target': target
        }
    
    def menu_mode(self):
        """Interactive menu for selecting challenge type and solving with AI"""
        print()
        print(colorize("╔═══════════════════════════════════════════════════════════════╗", Colors.BRIGHT_CYAN))
        print(colorize("║           🎯 INTERACTIVE CHALLENGE SOLVER MENU 🎯             ║", Colors.BRIGHT_YELLOW, bold=True))
        print(colorize("╚═══════════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
        print()
        
        # Challenge type menu
        challenge_types = [
            ("1", "🔐 Cryptography", "crypto", "Encrypted messages, ciphers, encoding", Colors.BRIGHT_RED),
            ("2", "🖼️  Steganography", "image", "Hidden data in images (PNG, JPG, BMP)", Colors.BRIGHT_MAGENTA),
            ("3", "💾 Disk Forensics", "disk", "Disk images, MFT, file recovery", Colors.BRIGHT_BLUE),
            ("4", "📦 Archive Analysis", "archive", "ZIP, TAR, compressed files", Colors.BRIGHT_YELLOW),
            ("5", "📡 Network/PCAP", "pcap", "Network captures, packet analysis", Colors.BRIGHT_CYAN),
            ("6", "💻 Binary/Reverse", "binary", "ELF, executables, reverse engineering", Colors.BRIGHT_GREEN),
            ("7", "📄 PDF Forensics", "pdf", "PDF files, metadata, hidden content", Colors.BRIGHT_RED),
            ("8", "🌐 Web Challenges", "web", "Websites, web vulnerabilities", Colors.BRIGHT_BLUE),
            ("9", "🔍 Generic Scan", "generic", "Auto-detect challenge type", Colors.BRIGHT_WHITE)
        ]
        
        print(colorize("Select Challenge Type:", Colors.BRIGHT_CYAN, bold=True))
        print(colorize("═" * 65, Colors.BRIGHT_BLACK))
        
        for num, emoji_name, _, desc, color in challenge_types:
            print(f"  {colorize(num, color, bold=True)}. {emoji_name:20s} - {colorize(desc, Colors.DIM)}")
        
        print(colorize("═" * 65, Colors.BRIGHT_BLACK))
        print(f"  {colorize('0', Colors.BRIGHT_RED, bold=True)}. {Emoji.UNLOCK} Exit to main menu")
        print()
        
        # Get user choice
        try:
            choice_prompt = colorize(f"{Emoji.QUESTION} Select option (0-9): ", Colors.BRIGHT_CYAN, bold=True)
            choice = input(choice_prompt).strip()
            
            if choice == '0':
                print_info("Returning to main menu...", emoji=False)
                return
            
            # Validate choice
            if choice not in [str(i) for i in range(1, 10)]:
                print_error("Invalid choice! Please select 1-9.", emoji=True)
                return
            
            # Get selected challenge type
            selected = challenge_types[int(choice) - 1]
            challenge_type = selected[2]
            type_name = selected[1]
            
            print()
            print_success(f"Selected: {type_name}", emoji=True)
            print()
            
            # Ask for file path
            file_prompt = colorize(f"{Emoji.FILE} Enter file path (or URL for web): ", Colors.BRIGHT_YELLOW, bold=True)
            filepath = input(file_prompt).strip()
            
            if not filepath:
                print_error("No file path provided!", emoji=True)
                return
            
            # Check if file exists (unless it's a URL)
            if not filepath.startswith('http') and not os.path.exists(filepath):
                print_error(f"File not found: {filepath}", emoji=True)
                return
            
            # Ask for challenge description (optional)
            print()
            desc_prompt = colorize(f"{Emoji.DOCUMENT} Challenge description (optional, press Enter to skip): ", Colors.BRIGHT_CYAN)
            description = input(desc_prompt).strip()
            
            # AI Guidance based on challenge type
            if self.ai_engine.is_available():
                print()
                print(colorize(f"{Emoji.BRAIN} AI Guidance for {type_name}:", Colors.BRIGHT_GREEN, bold=True))
                print(colorize("─" * 65, Colors.BRIGHT_BLACK))
                
                guidance = self.get_ai_guidance(challenge_type, filepath, description)
                print(colorize(guidance, Colors.BRIGHT_WHITE))
                print(colorize("─" * 65, Colors.BRIGHT_BLACK))
                print()
                
                # Ask if user wants to proceed
                proceed_prompt = colorize(f"{Emoji.ROCKET} Proceed with AI-powered analysis? (y/n): ", Colors.BRIGHT_YELLOW, bold=True)
                proceed = input(proceed_prompt).strip().lower()
                
                if proceed != 'y':
                    print_info("Analysis cancelled.", emoji=False)
                    return
            
            # Solve the challenge
            print()
            print(colorize(f"{Emoji.SPARKLES} Starting AI-powered analysis...", Colors.BRIGHT_MAGENTA, bold=True))
            print()
            
            self.solve_challenge(filepath, use_ai=True, description=description or None)
            
        except KeyboardInterrupt:
            print()
            print_warning("Menu cancelled by user", emoji=True)
        except Exception as e:
            print()
            print_error(f"Error in menu mode: {str(e)}", emoji=True)
            import traceback
            traceback.print_exc()
    
    def get_ai_guidance(self, challenge_type: str, filepath: str, description: str = "") -> str:
        """Get AI guidance for specific challenge type"""
        
        guidance_map = {
            "crypto": f"""{Emoji.KEY} Cryptography Challenge Tips:
• Look for common ciphers: Caesar, Vigenere, Base64, ROT13
• Check for XOR encryption patterns
• Analyze frequency distribution
• Try online cipher identifiers
• Look for key hints in the description""",
            
            "image": f"""{Emoji.IMAGE} Steganography Challenge Tips:
• Check EXIF metadata with exiftool
• Try LSB (Least Significant Bit) extraction
• Use tools: steghide, zsteg, stegsolve
• Look for hidden files with binwalk
• Check different color channels
• Try strings command for embedded text""",
            
            "disk": f"""{Emoji.SHIELD} Disk Forensics Tips:
• Scan MFT (Master File Table) for deleted files
• Use tools: sleuthkit, autopsy, volatility
• Look for hidden partitions
• Check file slack space
• Recover deleted files with photorec
• Analyze file timestamps""",
            
            "archive": f"""{Emoji.ARCHIVE} Archive Analysis Tips:
• Try password cracking with john/hashcat
• Check for nested archives
• Look for hidden files (ls -la)
• Try different extraction tools
• Check for zip comment fields
• Look for alternate data streams""",
            
            "pcap": f"""{Emoji.WIFI} Network/PCAP Analysis Tips:
• Use Wireshark for packet inspection
• Follow TCP/HTTP streams
• Look for file transfers (FTP, HTTP)
• Check for suspicious DNS queries
• Extract objects with NetworkMiner
• Analyze protocol statistics""",
            
            "binary": f"""{Emoji.CODE} Binary/Reverse Engineering Tips:
• Check with 'file' command first
• Use strings to find readable text
• Disassemble with objdump or radare2
• Debug with gdb or ltrace
• Look for hardcoded keys/flags
• Check for anti-debugging techniques""",
            
            "pdf": f"""{Emoji.DOCUMENT} PDF Forensics Tips:
• Extract metadata with pdfinfo
• Check for embedded files with pdfdetach
• Look for JavaScript with pdf-parser
• Extract images with pdfimages
• Check for hidden layers
• Analyze PDF structure with peepdf""",
            
            "web": f"""{Emoji.GLOBE} Web Challenge Tips:
• View page source (Ctrl+U)
• Check robots.txt and sitemap.xml
• Inspect cookies and local storage
• Try SQL injection, XSS
• Check for hidden directories (dirb, gobuster)
• Analyze JavaScript files
• Look for API endpoints""",
            
            "generic": f"""{Emoji.SEARCH} Generic Analysis Tips:
• Start with 'file' command to identify type
• Run strings to find readable text
• Check with binwalk for embedded files
• Look for magic bytes and file signatures
• Try hexdump for binary analysis
• Use exiftool for metadata"""
        }
        
        base_guidance = guidance_map.get(challenge_type, guidance_map["generic"])
        
        # Add file-specific info
        if os.path.exists(filepath):
            import magic
            try:
                file_type = magic.from_file(filepath)
                file_size = os.path.getsize(filepath)
                size_str = f"{file_size:,} bytes"
                
                base_guidance += f"\n\n{Emoji.INFO} File Info:\n• Type: {file_type}\n• Size: {size_str}"
            except:
                pass
        
        if description:
            base_guidance += f"\n\n{Emoji.DOCUMENT} Challenge Description:\n{description}"
        
        return base_guidance
    
    def solve_challenge(self, initial_target: str, use_ai=True, description=None):
        """Solve a CTF challenge (Recursive)"""
        print()
        print(colorize(f"{Emoji.TARGET} Target: ", Colors.BRIGHT_CYAN, bold=True) + color_path(initial_target))
        if description:
            print(colorize(f"{Emoji.DOCUMENT} Challenge: ", Colors.BRIGHT_YELLOW, bold=True) + description)
        print("")
        
        # Check if target exists
        if not initial_target.startswith('http') and not os.path.exists(initial_target):
            print_error(f"File not found: {initial_target}", emoji=True)
            return

        # Queue for files to analyze (BFS)
        analysis_queue = [initial_target]
        processed_files = set()
        all_results = []
        challenge_info = {
            'description': description,
            'target': initial_target
        }
        
        while analysis_queue:
            current_target = analysis_queue.pop(0)
            
            # Avoid loops
            if current_target in processed_files:
                continue
            processed_files.add(current_target)
            
            print()
            print(colorize(f"{Emoji.ANALYZE} Analyzing: ", Colors.BRIGHT_CYAN, bold=True) + highlight(os.path.basename(current_target)))
            print(colorize("━" * 60, Colors.BRIGHT_BLACK))
            
            # Step 1: File analysis
            file_info = self.get_file_info(current_target)
            scan_results = self.file_scanner.scan(current_target)
            
            # Check for auto-extracted/decoded files to queue
            if scan_results.get('decoded_file'):
                new_file = scan_results['decoded_file']
                if new_file not in processed_files:
                    print(colorize(f"   ↪️  Queueing new file: ", Colors.BRIGHT_YELLOW) + color_path(new_file))
                    analysis_queue.append(new_file)
            
            if use_ai and self.ai_engine.is_available():
                # Step 2: AI analysis
                print()
                print(colorize(f"{Emoji.ROBOT} Step 2: AI analyzing challenge type...", Colors.BRIGHT_GREEN, bold=True))
                
                # Check for Smart Solver requirements (Description + Text File)
                is_text = False
                try:
                    if file_info.get('size', 0) < 20000: # Max 20KB for code generation
                        with open(current_target, 'rb') as f:
                            content = f.read(512)
                            is_text = not b'\x00' in content
                except: pass

                if description and is_text:
                    print(colorize(f"{Emoji.MAGIC} Smart Solver Activated: Analyzing problem description & file content...", Colors.BRIGHT_MAGENTA, bold=True))
                    with open(current_target, 'r', errors='ignore') as f:
                        file_content = f.read()
                    
                    solver_script = self.ai_engine.generate_solver_script(description, file_content)
                    
                    if solver_script:
                        print()
                        print(colorize(f"{Emoji.CODE} AI Generated Solver Script:", Colors.BRIGHT_CYAN, bold=True))
                        print(colorize("-" * 60, Colors.BRIGHT_BLACK))
                        lines = solver_script.splitlines()
                        for i, line in enumerate(lines[:10]):
                            print(colorize(f"{i+1:3}: ", Colors.BRIGHT_BLACK) + line)
                        if len(lines) > 10: 
                            print(colorize(f"... ({len(lines)-10} more lines)", Colors.DIM))
                        print(colorize("-" * 60, Colors.BRIGHT_BLACK))
                        
                        # Save and Run
                        output_dir = self.config['output_directory']
                        os.makedirs(output_dir, exist_ok=True)
                        
                        # Copy target file to output dir so script can find it
                        import shutil
                        target_filename = os.path.basename(current_target)
                        local_target_path = os.path.join(output_dir, target_filename)
                        shutil.copy2(current_target, local_target_path)
                        
                        solver_path = os.path.join(output_dir, 'ai_solver.py')
                        with open(solver_path, 'w') as f:
                            f.write(solver_script)
                            
                        print_info(f"Executing solver: {solver_path}", emoji=False)
                        try:
                            # Run the generated script in the output directory
                            result = subprocess.run(
                                [sys.executable, 'ai_solver.py'],
                                cwd=output_dir, # Run INSIDE the output dir
                                capture_output=True,
                                text=True,
                                timeout=30
                            )
                            
                            print()
                            print(colorize(f"{Emoji.DOCUMENT} Solver Output:", Colors.BRIGHT_YELLOW, bold=True))
                            print(result.stdout)
                            if result.stderr:
                                print_warning(f"Error: {result.stderr}", emoji=True)
                                
                            # Check for flags in output
                            generated_flags = []
                            for line in result.stdout.splitlines():
                                found = self.file_scanner.search_flags(line)
                                if found:
                                    generated_flags.extend(found)
                            
                            if generated_flags:
                                print()
                                print(colorize(f"{Emoji.TROPHY} OPENAI SOLVED IT! Found {len(generated_flags)} flag(s)!", Colors.BRIGHT_GREEN, bold=True))
                                results = {'flags': generated_flags, 'status': 'success'}
                                all_results.append(results)
                                # Skip normal playbook execution if solved
                                continue 
                                
                        except Exception as e:
                            print_warning(f"Solver execution failed: {e}", emoji=True)

                # Regular Playbook Analysis
                file_info['scan_findings'] = scan_results.get('findings', [])
                analysis = self.ai_engine.analyze_challenge(file_info)
                playbook_name = analysis.get('recommended_playbook', 'generic')
                confidence = analysis.get('confidence', 0) * 100
                print(colorize(f"   {Emoji.BRAIN} Strategy: ", Colors.BRIGHT_CYAN) + 
                      highlight(playbook_name) + 
                      colorize(f" ({confidence:.0f}%)", Colors.BRIGHT_GREEN))
            else:
                # Manual playbook selection
                playbook_name = self.select_playbook_by_extension(file_info)
                print(colorize(f"   {Emoji.WRENCH} Strategy: ", Colors.BRIGHT_YELLOW) + 
                      highlight(playbook_name) + 
                      colorize(" (Manual)", Colors.DIM))
            
            # Step 3: Execute playbook
            # Only execute if it's not 'generic' OR we haven't found anything yet
            if playbook_name != 'generic' or len(analysis_queue) == 0:
                # Initialize Tool Installer
                from modules.tool_installer import ToolInstaller
                installer = ToolInstaller(self.config)
                
                # Check tools for the selected playbook
                playbook_file = os.path.join(os.path.dirname(__file__), 'playbooks', f"{playbook_name}.yaml")
                if os.path.exists(playbook_file):
                    print_info(f"Verifying tools for {playbook_name}...", emoji=False)
                    installer.verify_playbook_tools(playbook_file)
                
                print()
                print(colorize(f"{Emoji.ROCKET} Executing playbook...", Colors.BRIGHT_MAGENTA, bold=True))
                
                results = self.playbook_executor.execute_playbook(
                    playbook_name,
                    current_target,
                    ai_engine=self.ai_engine if use_ai else None
                )
                all_results.append(results)
                
                # Report Flags Immediately
                if results.get('flags'):
                    print()
                    print(colorize(f"{Emoji.SPARKLES} FLAG FOUND in ", Colors.BRIGHT_GREEN, bold=True) + 
                          highlight(os.path.basename(current_target)) + colorize(":", Colors.BRIGHT_GREEN, bold=True))
                    for flag in results['flags']:
                        desc = self.describe_flag(flag)
                        print(f"   {flag_text(flag)}")
                        print(colorize(f"      {Emoji.INFO} {desc}", Colors.BRIGHT_CYAN))
            
            print(colorize("━" * 60, Colors.BRIGHT_BLACK))

        # Final Summary
        print()
        print(colorize("═" * 65, Colors.BRIGHT_CYAN))
        print(colorize(f"{Emoji.CHART} SESSION COMPLETE", Colors.BRIGHT_YELLOW, bold=True).center(65))
        print(colorize("═" * 65, Colors.BRIGHT_CYAN))
        
        total_flags = sum(len(r.get('flags', [])) for r in all_results)
        if total_flags > 0:
            print()
            print(colorize(f"{Emoji.TROPHY} GRAND TOTAL: ", Colors.BRIGHT_GREEN, bold=True) + 
                  colorize(f"{total_flags} Flag(s) Found!", Colors.BRIGHT_YELLOW, bold=True))
        else:
            print()
            print_warning("No flags found in this session.", emoji=True)
        
        # Step 5: Generate report (for the initial file) with unique output directory
        report_data = {
            'sub_analyses': all_results,
            'challenge_info': challenge_info
        }
        
        # Create reporter with unique output directory for this challenge
        reporter = Reporter(self.config, challenge_name=initial_target)
        reporter.generate_report(report_data, initial_target)
        
        print()
        print_success("Done! Check the 'output' directory.", emoji=True)
        print("")
    
    def get_file_info(self, filepath: str) -> dict:
        """Get basic file information"""
        if filepath.startswith('http'):
            return {
                'filename': filepath,
                'type': 'url',
                'extension': '',
                'size': 0
            }
        
        try:
            import magic
            
            file_type = magic.from_file(filepath)
            mime_type = magic.from_file(filepath, mime=True)
            
            return {
                'filename': os.path.basename(filepath),
                'type': file_type,
                'mime': mime_type,
                'extension': Path(filepath).suffix,
                'size': os.path.getsize(filepath)
            }
        except:
            return {
                'filename': os.path.basename(filepath),
                'type': 'unknown',
                'extension': Path(filepath).suffix,
                'size': os.path.getsize(filepath) if os.path.exists(filepath) else 0
            }

    def describe_flag(self, flag_text: str) -> str:
        """Get description for a flag based on config"""
        descriptions = self.config.get('flag_descriptions', {})
        
        # Check specific prefixes
        for prefix, desc in descriptions.items():
            if prefix in flag_text:
                return desc
        
        return "Unknown Flag Format"
    
    def select_playbook_by_extension(self, file_info: dict) -> str:
        """Simple playbook selection based on file extension"""
        ext = file_info.get('extension', '').lower()
        file_type = file_info.get('type', '').lower()
        
        # Check file type for disk images (they often have no extension)
        if any(keyword in file_type for keyword in ['boot sector', 'filesystem', 'disk image', 'fat', 'ntfs', 'ext2', 'ext3', 'ext4']):
            return 'disk_forensics'
        
        mapping = {
            '.png': 'png_stego',
            '.bmp': 'png_stego',
            '.jpg': 'jpg_stego',
            '.jpeg': 'jpg_stego',
            '.zip': 'archive_analysis',
            '.tar': 'archive_analysis',
            '.gz': 'archive_analysis',
            '.rar': 'archive_analysis',
            '.7z': 'archive_analysis',
            '.pcap': 'pcap_analysis',
            '.pcapng': 'pcap_analysis',
            '.pdf': 'pdf_forensics',
            '.elf': 'binary_analysis',
            '.dd': 'disk_forensics',
            '.img': 'disk_forensics',
            '.raw': 'disk_forensics',
            '.vmdk': 'disk_forensics',
            '.vdi': 'disk_forensics',
            '': 'binary_analysis'
        }
        
        return mapping.get(ext, 'generic')
    
    def list_playbooks(self):
        """List available playbooks"""
        playbooks = self.playbook_executor.get_available_playbooks()
        
        print()
        print(colorize(f"{Emoji.FOLDER} Available Playbooks:", Colors.BRIGHT_MAGENTA, bold=True))
        print(colorize("═" * 60, Colors.BRIGHT_BLACK))
        for i, name in enumerate(playbooks, 1):
            playbook = self.playbook_executor.playbooks.get(name, {})
            desc = playbook.get('description', 'No description')
            num = colorize(f"  {i:2}.", Colors.BRIGHT_CYAN, bold=True)
            name_colored = colorize(f"{name:25s}", Colors.BRIGHT_YELLOW)
            desc_colored = colorize(f"- {desc}", Colors.WHITE)
            print(f"{num} {name_colored} {desc_colored}")
        print("")
    
    def show_settings(self):
        """Show current settings"""
        print()
        print(colorize(f"{Emoji.GEAR} Current Settings:", Colors.BRIGHT_CYAN, bold=True))
        print(colorize("═" * 60, Colors.BRIGHT_BLACK))
        
        # AI Provider
        print(colorize("  AI Provider:      ", Colors.BRIGHT_YELLOW) + 
              highlight(self.ai_engine.provider))
        
        # AI Model
        print(colorize("  AI Model:         ", Colors.BRIGHT_YELLOW) + 
              highlight(self.ai_engine.model))
        
        # AI Status
        if self.ai_engine.is_available():
            status = colorize(f"{Emoji.SUCCESS} Available", Colors.BRIGHT_GREEN, bold=True)
        else:
            status = colorize(f"{Emoji.ERROR} Offline", Colors.BRIGHT_RED, bold=True)
        print(colorize("  AI Status:        ", Colors.BRIGHT_YELLOW) + status)
        
        # Output Directory
        print(colorize("  Output Directory: ", Colors.BRIGHT_YELLOW) + 
              color_path(self.config.get('output_directory', 'output')))
        
        # Playbooks
        print(colorize("  Playbooks:        ", Colors.BRIGHT_YELLOW) + 
              highlight(str(len(self.playbook_executor.get_available_playbooks()))))
        print("")
    
    def show_help(self):
        """Show help"""
        print()
        print(colorize("╔══════════════════════════════════════════════════════════════╗", Colors.BRIGHT_CYAN))
        print(colorize("║                         HELP GUIDE                           ║", Colors.BRIGHT_YELLOW, bold=True))
        print(colorize("╚══════════════════════════════════════════════════════════════╝", Colors.BRIGHT_CYAN))
        print()
        
        # Natural Language Commands
        print(colorize(f"{Emoji.TARGET} NATURAL LANGUAGE COMMANDS:", Colors.BRIGHT_GREEN, bold=True))
        commands = [
            ("solve challenge.png", "Solve a CTF challenge with AI"),
            ("find flag in file.zip", "Search for flags in archives"),
            ("analyze capture.pcap", "Analyze network captures"),
            ("check binary.elf", "Examine binary files")
        ]
        for cmd, desc in commands:
            print(f"  {Emoji.SPARKLES} {code(cmd):30s} - {desc}")
        print()
        
        # Direct Commands
        print(colorize(f"{Emoji.FOLDER} DIRECT COMMANDS:", Colors.BRIGHT_BLUE, bold=True))
        direct_cmds = [
            ("playbooks", "List all available playbooks"),
            ("settings", "Show current configuration"),
            ("help", "Show this help"),
            ("quit / exit", "Exit the program")
        ]
        for cmd, desc in direct_cmds:
            print(f"  {Emoji.STAR} {code(cmd):30s} - {desc}")
        print()
        
        # Examples
        print(colorize(f"{Emoji.FIRE} EXAMPLES:", Colors.BRIGHT_YELLOW, bold=True))
        examples = [
            "solve mystery.png",
            "find flag in challenge.zip",
            "analyze http://target.com",
            "check suspicious.elf"
        ]
        for ex in examples:
            print(f"  {colorize(f'{Emoji.ROBOT} You:', Colors.BRIGHT_CYAN, bold=True)} {highlight(ex)}")
        print()
        
        # Configuration
        print(colorize(f"{Emoji.GEAR} CONFIGURATION:", Colors.BRIGHT_MAGENTA, bold=True))
        print(f"  Edit {color_path('config.json')} to set:")
        print(f"  {Emoji.ROBOT} ai_provider (openai, ollama, claude, groq, none)")
        print(f"  {Emoji.BRAIN} ai_model (gpt-4, llama3, etc.)")
        print(f"  {Emoji.KEY} API keys for cloud AI providers")
        print()
        
        # AI Providers
        print(colorize(f"{Emoji.WRENCH} AI PROVIDERS:", Colors.BRIGHT_CYAN, bold=True))
        providers = [
            ("openai", "GPT-4 (best, costs money)", Colors.BRIGHT_GREEN),
            ("ollama", "Local AI (free, needs setup)", Colors.BRIGHT_BLUE),
            ("claude", "Claude by Anthropic", Colors.BRIGHT_MAGENTA),
            ("groq", "Fast inference (free tier)", Colors.BRIGHT_YELLOW),
            ("none", "Manual mode (no AI)", Colors.BRIGHT_RED)
        ]
        for name, desc, color in providers:
            provider_name = f"{name:10s}"
            print(f"  {Emoji.STAR} {colorize(provider_name, color, bold=True)} - {desc}")
        print()
        
        print(colorize(f"{Emoji.INFO} More info: Check README.md", Colors.DIM))
        print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='CTF-AI Ultimate - AI-Powered CTF Assistant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended)
  ctf-ai
  
  # Direct solve
  ctf-ai --solve challenge.png
  
  # Use specific AI provider
  ctf-ai --ai=ollama --solve file.zip
  
  # Manual mode (no AI)
  ctf-ai --ai=none --solve challenge.pcap
"""
    )
    
    parser.add_argument(
        '--solve',
        metavar='FILE',
        help='Directly solve a challenge file'
    )
    
    parser.add_argument('--ai', choices=['openai', 'anthropic', 'gemini', 'ollama', 'groq', 'none'], 
                      help='AI provider to use (overrides config)')
    parser.add_argument('-d', '--description', help='Challenge description or hint')
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Force interactive mode'
    )
    

    
    args = parser.parse_args()
    
    try:
        # Initialize assistant
        assistant = CTF_AI_Assistant(config_file=args.config)
        
        # Override AI provider if specified
        if args.ai:
            assistant.config['ai_provider'] = args.ai
            assistant.ai_engine = AIEngine(assistant.config)
        
        # Direct solve mode
        if args.solve and not args.interactive:
            assistant.print_banner()
            print("")
            assistant.solve_challenge(args.solve, use_ai=True, description=args.description)
        else:
            # Interactive mode
            assistant.interactive_mode()
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
