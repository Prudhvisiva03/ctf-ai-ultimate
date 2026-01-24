#!/usr/bin/env python3
"""
CTF-AI Ultimate - Interactive AI-Powered CTF Assistant
The world's first open-source AI CTF solver with natural language interface

Features:
- Natural language commands
- Multi-AI support (OpenAI, Ollama, Claude, Groq)
- Intelligent playbook selection
- Adaptive execution strategies
- Kali Linux tool integration
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.ai_engine import AIEngine
from modules.playbook_executor import PlaybookExecutor
from modules.file_scan import FileScanner
from modules.reporter import Reporter


class CTF_AI_Assistant:
    """Interactive AI-powered CTF assistant"""
    
    def __init__(self, config_file='config.json'):
        """Initialize the assistant"""
        self.config = self.load_config(config_file)
        
        # Initialize components
        self.ai_engine = AIEngine(self.config)
        self.playbook_executor = PlaybookExecutor(self.config)
        self.file_scanner = FileScanner(self.config)
        self.reporter = Reporter(self.config)
        
        self.session_history = []
        
    def load_config(self, config_file):
        """Load configuration"""
        try:
            script_dir = Path(__file__).parent
            config_path = script_dir / config_file
            
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                print(f"⚠️  Config file not found, using defaults")
                return self.get_default_config()
        except Exception as e:
            print(f"⚠️  Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Default configuration"""
        return {
            'ai_provider': 'openai',
            'ai_model': 'gpt-4',
            'output_directory': 'output',
            'flag_patterns': [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}'
            ]
        }
    
    def print_banner(self):
        """Print welcome banner"""
        banner = """
\033[36m╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ▄████▄   ▀█████████▄     ▄████████  ▄█   ▄██████▄   ▄█      ║
║  ███    ███   ███    ███   ███    ███ ███  ███    ███ ███      ║
║  ███    █▀    ███    ███   ███    █▀  ███▌ ███    ███ ███      ║
║  ███          ███    ███  ▄███▄▄▄     ███▌ ███    ███ ███      ║
║  ███          ███    ███ ▀▀███▀▀▀     ███▌ ███    ███ ███      ║
║  ███    █▄    ███    ███   ███        ███  ███    ███ ███      ║
║   ▀██████▀   ▄█████████▀   ███        █▀   ▀██████▀   █▀       ║
║                                                               ║
║         ULTIMATE AI-POWERED CTF ASSISTANT v2.0                ║
║              Your Personal CTF Solver                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝\033[0m

\033[1;32m🤖 AI-Powered\033[0m | \033[1;33m🔧 Kali Tools\033[0m | \033[1;34m🧠 Smart Playbooks\033[0m | \033[1;31m🎯 Flag Hunter\033[0m
"""
        print(banner)
        
        # Show AI status
        if self.ai_engine.is_available():
            print(f"✅ AI Engine: {self.ai_engine.provider} ({self.ai_engine.model})")
        else:
            print(f"⚠️  AI Engine: Offline mode (manual tools only)")
        
        print(f"✅ Playbooks loaded: {len(self.playbook_executor.get_available_playbooks())}")
        print("")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        self.print_banner()
        
        print("━" * 65)
        print("Type your request in natural language or use commands:")
        print("  • solve <file>        - Analyze and solve a challenge")
        print("  • analyze <file>      - Deep analysis without AI")
        print("  • playbooks           - List available playbooks")
        print("  • settings            - Show current settings")
        print("  • help                - Show help")
        print("  • quit/exit           - Exit")
        print("━" * 65)
        print("")
        
        while True:
            try:
                # Get user input
                user_input = input("🤖 You: ").strip()
                
                if not user_input:
                    continue
                
                # Handle quit
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("\n👋 Goodbye! Happy hacking! 🔥\n")
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
                
                # Process natural language request
                self.process_request(user_input)
                
            except KeyboardInterrupt:
                print("\n\n[!] Interrupted by user")
                break
            except Exception as e:
                print(f"\n❌ Error: {str(e)}")
                import traceback
                traceback.print_exc()
    
    def process_request(self, request: str):
        """Process a naturallanguage request"""
        print("")
        
        # Parse the request
        parsed = self.parse_request(request)
        
        if not parsed['valid']:
            print(f"❌ {parsed.get('error', 'Invalid request')}")
            print("💡 Try: solve <filename> or help")
            return
        
        action = parsed['action']
        target = parsed['target']
        
        if action in ['solve', 'analyze', 'find flag in', 'check']:
            self.solve_challenge(target, use_ai=(action == 'solve'))
        else:
            print(f"❌ Unknown action: {action}")
            print("💡 Try: solve <filename>")
    
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
            return {'valid': False, 'error': 'No target file or URL specified'}
        
        return {
            'valid': True,
            'action': action,
            'target': target
        }
    
    def solve_challenge(self, initial_target: str, use_ai=True):
        """Solve a CTF challenge (Recursive)"""
        print(f"🎯 Target: {initial_target}")
        print("")
        
        # Check if target exists
        if not initial_target.startswith('http') and not os.path.exists(initial_target):
            print(f"❌ File not found: {initial_target}")
            return

        # Queue for files to analyze (BFS)
        analysis_queue = [initial_target]
        processed_files = set()
        all_results = []
        
        while analysis_queue:
            current_target = analysis_queue.pop(0)
            
            # Avoid loops
            if current_target in processed_files:
                continue
            processed_files.add(current_target)
            
            print(f"\n⚡ Analyzing: {os.path.basename(current_target)}")
            print("━" * 40)
            
            # Step 1: File analysis
            file_info = self.get_file_info(current_target)
            scan_results = self.file_scanner.scan(current_target)
            
            # Check for auto-extracted/decoded files to queue
            if scan_results.get('decoded_file'):
                new_file = scan_results['decoded_file']
                if new_file not in processed_files:
                    print(f"   ↪️  Queueing new file: {new_file}")
                    analysis_queue.append(new_file)
            
            if use_ai and self.ai_engine.is_available():
                # Step 2: AI analysis
                print("\n🤖 Step 2: AI analyzing challenge type...")
                
                # Pass scan findings to AI
                file_info['scan_findings'] = scan_results.get('findings', [])
                
                analysis = self.ai_engine.analyze_challenge(file_info)
                playbook_name = analysis.get('recommended_playbook', 'generic')
                print(f"   Strategy: {playbook_name} ({analysis.get('confidence', 0)*100:.0f}%)")
            else:
                # Manual playbook selection
                playbook_name = self.select_playbook_by_extension(file_info)
                print(f"   Strategy: {playbook_name} (Manual)")
            
            # Step 3: Execute playbook
            # Only execute if it's not 'generic' OR we haven't found anything yet
            if playbook_name != 'generic' or len(analysis_queue) == 0:
                print(f"\n🚀 Executing playbook...")
                
                results = self.playbook_executor.execute_playbook(
                    playbook_name,
                    current_target,
                    ai_engine=self.ai_engine if use_ai else None
                )
                all_results.append(results)
                
                # Report Flags Immediately
                if results.get('flags'):
                    print(f"\n🎉 FLAG FOUND in {os.path.basename(current_target)}:")
                    for flag in results['flags']:
                        desc = self.describe_flag(flag)
                        print(f"   🚩 {flag}")
                        print(f"      ℹ️  {desc}")
            
            print("━" * 40)

        # Final Summary
        print("\n" + "="*65)
        print("📊 SESSION COMPLETE")
        print("="*65)
        
        total_flags = sum(len(r.get('flags', [])) for r in all_results)
        if total_flags > 0:
            print(f"\n🏆 GRAND TOTAL: {total_flags} Flag(s) Found!")
        else:
            print("\n⚠️  No flags found in this session.")
        
        # Step 5: Generate report (for the initial file)
        self.reporter.generate_report({'sub_analyses': all_results}, initial_target)
        
        print("\n✅ Done! Check the 'output' directory.")
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
            '': 'binary_analysis'
        }
        
        return mapping.get(ext, 'generic')
    
    def list_playbooks(self):
        """List available playbooks"""
        playbooks = self.playbook_executor.get_available_playbooks()
        
        print("\n📚 Available Playbooks:")
        print("=" * 50)
        for i, name in enumerate(playbooks, 1):
            playbook = self.playbook_executor.playbooks.get(name, {})
            desc = playbook.get('description', 'No description')
            print(f"  {i}. {name:20s} - {desc}")
        print("")
    
    def show_settings(self):
        """Show current settings"""
        print("\n⚙️  Current Settings:")
        print("=" * 50)
        print(f"  AI Provider: {self.ai_engine.provider}")
        print(f"  AI Model: {self.ai_engine.model}")
        print(f"  AI Status: {'✅ Available' if self.ai_engine.is_available() else '❌ Offline'}")
        print(f"  Output Directory: {self.config.get('output_directory', 'output')}")
        print(f"  Playbooks: {len(self.playbook_executor.get_available_playbooks())}")
        print("")
    
    def show_help(self):
        """Show help"""
        help_text = """
╔══════════════════════════════════════════════════════════════╗
║                         HELP GUIDE                           ║
╚══════════════════════════════════════════════════════════════╝

🎯 NATURAL LANGUAGE COMMANDS:
  • solve challenge.png
  • find flag in file.zip
  • analyze capture.pcap
  • check binary.elf

📋 DIRECT COMMANDS:
  • playbooks          - List all available playbooks
  • settings           - Show current configuration
  • help               - Show this help
  • quit / exit        - Exit the program

💡 EXAMPLES:
  🤖 You: solve mystery.png
  🤖 You: find flag in challenge.zip
  🤖 You: analyze http://target.com
  🤖 You: check suspicious.elf

⚙️  CONFIGURATION:
  Edit config.json to set:
  • ai_provider (openai, ollama, claude, groq, none)
  • ai_model (gpt-4, llama3, etc.)
  • API keys for cloud AI providers

🔧 AI PROVIDERS:
  • openai  - GPT-4 (best, costs money)
  • ollama  - Local AI (free, needs setup)
  • claude  - Claude by Anthropic
  • groq    - Fast inference (free tier)
  • none    - Manual mode (no AI)

📚 More info: Check README.md
"""
        print(help_text)


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
    
    parser.add_argument(
        '--ai',
        choices=['openai', 'ollama', 'claude', 'groq', 'none'],
        help='AI provider to use'
    )
    
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
            assistant.solve_challenge(args.solve, use_ai=True)
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
