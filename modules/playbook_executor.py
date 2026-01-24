"""
Playbook Executor - Runs challenge-specific method sequences
Each playbook defines a sequence of tools and methods for a specific challenge type
"""

import json
import os
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path


class PlaybookExecutor:
    """Executes challenge-specific playbooks with intelligent method sequencing"""
    
    def __init__(self, config: Dict, playbooks_dir: str = 'playbooks'):
        self.config = config
        self.playbooks_dir = playbooks_dir
        self.playbooks = self._load_playbooks()
        self.execution_log = []
        
    def _load_playbooks(self) -> Dict:
        """Load all playbook definitions"""
        playbooks = {}
        
        # Get script directory
        script_dir = Path(__file__).parent.parent
        playbooks_path = script_dir / self.playbooks_dir
        
        if not playbooks_path.exists():
            print(f"⚠️  Playbooks directory not found: {playbooks_path}")
            return self._get_default_playbooks()
        
        # Load each playbook JSON file
        for playbook_file in playbooks_path.glob('*.json'):
            try:
                with open(playbook_file, 'r') as f:
                    playbook_name = playbook_file.stem
                    playbooks[playbook_name] = json.load(f)
                    print(f"[+] Loaded playbook: {playbook_name}")
            except Exception as e:
                print(f"⚠️  Failed to load {playbook_file}: {e}")
        
        if not playbooks:
            print("[*] No playbooks loaded, using defaults")
            return self._get_default_playbooks()
        
        return playbooks
    
    def _get_default_playbooks(self) -> Dict:
        """Return default playbooks if files not found"""
        return {
            'generic': {
                'name': 'Generic Analysis',
                'description': 'Basic file analysis',
                'methods': [
                    {'name': 'file_scan', 'module': 'file_scan'},
                    {'name': 'strings_search', 'module': 'file_scan'}
                ]
            }
        }
    
    def get_available_playbooks(self) -> List[str]:
        """Get list of available playbook names"""
        return list(self.playbooks.keys())
    
    def execute_playbook(self, playbook_name: str, target: str, ai_engine=None) -> Dict:
        """
        Execute a specific playbook on a target
        
        Args:
            playbook_name: Name of the playbook to execute
            target: Target file or URL
            ai_engine: Optional AI engine for intelligent execution
            
        Returns:
            Dict with execution results
        """
        if playbook_name not in self.playbooks:
            print(f"❌ Playbook '{playbook_name}' not found")
            return {'success': False, 'error': 'Playbook not found'}
        
        playbook = self.playbooks[playbook_name]
        
        print(f"\n{'='*60}")
        print(f"🎯 Executing Playbook: {playbook.get('name', playbook_name)}")
        print(f"   {playbook.get('description', '')}")
        print(f"{'='*60}\n")
        
        results = {
            'playbook': playbook_name,
            'target': target,
            'methods_executed': [],
            'findings': [],
            'flags': [],
            'success': False
        }
        
        # Get execution strategy
        strategy = playbook.get('execution_strategy', 'sequential')
        methods = playbook.get('methods', [])
        
        if strategy == 'sequential':
            results = self._execute_sequential(methods, target, results, ai_engine)
        elif strategy == 'parallel':
            results = self._execute_parallel(methods, target, results, ai_engine)
        elif strategy == 'adaptive':
            results = self._execute_adaptive(methods, target, results, ai_engine)
        
        # Check if any flags were found
        if results['flags']:
            results['success'] = True
            print(f"\n{'='*60}")
            print(f"🎉 SUCCESS! Found {len(results['flags'])} flag(s)")
            for flag in results['flags']:
                print(f"   ✅ {flag}")
            print(f"{'='*60}\n")
        
        return results
    
    def _execute_sequential(self, methods: List[Dict], target: str, results: Dict, ai_engine=None) -> Dict:
        """Execute methods one by one"""
        for i, method in enumerate(methods, 1):
            print(f"\n[{i}/{len(methods)}] Executing: {method.get('name', 'Unknown')}")
            print(f"    Description: {method.get('description', 'N/A')}")
            
            try:
                method_result = self._execute_method(method, target)
                results['methods_executed'].append({
                    'name': method.get('name'),
                    'success': method_result.get('success', False),
                    'output': method_result.get('output', '')
                })
                
                # Collect findings
                if method_result.get('findings'):
                    results['findings'].extend(method_result['findings'])
                
                # Collect flags
                if method_result.get('flags'):
                    results['flags'].extend(method_result['flags'])
                    print(f"    🔥 Found flag(s): {method_result['flags']}")
                
                # Use AI to interpret results if available
                if ai_engine and ai_engine.is_available() and method_result.get('output'):
                    interpretation = ai_engine.interpret_tool_output(
                        method.get('name', 'unknown'),
                        method_result.get('output', '')
                    )
                    
                    if interpretation.get('flags_found'):
                        results['flags'].extend(interpretation['flags_found'])
                    
                    if interpretation.get('interesting_findings'):
                        results['findings'].extend(interpretation['interesting_findings'])
                
                # Stop conditions
                stop_on_success = method.get('stop_on_success', False)
                if stop_on_success and method_result.get('flags'):
                    print(f"    ✅ Flag found, stopping playbook execution")
                    break
                    
            except Exception as e:
                print(f"    ❌ Method failed: {str(e)}")
                results['methods_executed'].append({
                    'name': method.get('name'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _execute_parallel(self, methods: List[Dict], target: str, results: Dict, ai_engine=None) -> Dict:
        """Execute methods in parallel (simplified - actually sequential for now)"""
        # For simplicity, we'll execute sequentially but mark as parallel execution
        print("[*] Parallel execution mode (methods can run simultaneously)")
        return self._execute_sequential(methods, target, results, ai_engine)
    
    def _execute_adaptive(self, methods: List[Dict], target: str, results: Dict, ai_engine=None) -> Dict:
        """Execute methods adaptively based on AI suggestions"""
        if not ai_engine or not ai_engine.is_available():
            print("[*] AI not available, falling back to sequential execution")
            return self._execute_sequential(methods, target, results, ai_engine)
        
        print("[*] Adaptive execution mode (AI-guided)")
        
        # Start with first method
        for i, method in enumerate(methods, 1):
            print(f"\n[{i}/{len(methods)}] Executing: {method.get('name')}")
            
            try:
                method_result = self._execute_method(method, target)
                results['methods_executed'].append({
                    'name': method.get('name'),
                    'success': method_result.get('success', False)
                })
                
                if method_result.get('flags'):
                    results['flags'].extend(method_result['flags'])
                    print(f"    🔥 Flag found!")
                
                # Ask AI if we should continue or try something different
                if i < len(methods):
                    suggestion = ai_engine.suggest_next_steps(
                        results,
                        [m.get('name') for m in results['methods_executed']]
                    )
                    
                    if suggestion.get('stop'):
                        print(f"\n🤖 AI suggests stopping: {suggestion.get('reasoning')}")
                        break
                        
            except Exception as e:
                print(f"    ❌ Failed: {str(e)}")
        
        return results
    
    def _execute_method(self, method: Dict, target: str) -> Dict:
        """Execute a single method"""
        method_type = method.get('type', 'tool')
        
        if method_type == 'tool':
            return self._execute_tool(method, target)
        elif method_type == 'module':
            return self._execute_module(method, target)
        elif method_type == 'script':
            return self._execute_script(method, target)
        else:
            return {'success': False, 'error': f'Unknown method type: {method_type}'}
    
    def _execute_tool(self, method: Dict, target: str) -> Dict:
        """Execute an external tool"""
        tool_name = method.get('tool')
        args = method.get('args', [])
        
        # Replace {target} placeholder
        args = [arg.replace('{target}', target) for arg in args]
        
        # Build command
        command = [tool_name] + args
        
        try:
            print(f"    Running: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=method.get('timeout', 60)
            )
            
            output = result.stdout + result.stderr
            
            # Parse output for flags
            flags = self._search_flags(output)
            
            # Parse output for findings
            findings = self._parse_tool_output(tool_name, output, method)
            
            return {
                'success': result.returncode == 0,
                'output': output,
                'flags': flags,
                'findings': findings,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Tool execution timeout'}
        except FileNotFoundError:
            print(f"    ⚠️  Tool not found: {tool_name}")
            return {'success': False, 'error': f'Tool not installed: {tool_name}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_module(self, method: Dict, target: str) -> Dict:
        """Execute a CTFHunter module"""
        module_name = method.get('module')
        function_name = method.get('function', 'scan')
        
        try:
            # Dynamic import
            if module_name == 'file_scan':
                from modules.file_scan import FileScanner
                scanner = FileScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'stego_scan':
                from modules.stego_scan import StegoScanner
                scanner = StegoScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'pcap_scan':
                from modules.pcap_scan import PCAPScanner
                scanner = PCAPScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'elf_scan':
                from modules.elf_scan import ELFScanner
                scanner = ELFScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'pdf_scan':
                from modules.pdf_scan import PDFScanner
                scanner = PDFScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'zip_scan':
                from modules.zip_scan import ArchiveScanner
                scanner = ArchiveScanner(self.config)
                result = scanner.scan(target)
                
            elif module_name == 'web_scan':
                from modules.web_scan import WebScanner
                scanner = WebScanner(self.config)
                result = scanner.scan(target)
            else:
                return {'success': False, 'error': f'Unknown module: {module_name}'}
            
            # Extract flags from result
            flags = self._collect_flags_from_result(result)
            
            return {
                'success': True,
                'output': json.dumps(result, indent=2, default=str),
                'flags': flags,
                'findings': [],
                'result': result
            }
            
        except Exception as e:
            print(f"    ❌ Module execution failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _execute_script(self, method: Dict, target: str) -> Dict:
        """Execute a custom script"""
        script_path = method.get('script')
        
        try:
            result = subprocess.run(
                ['python3', script_path, target],
                capture_output=True,
                text=True,
                timeout=method.get('timeout', 120)
            )
            
            output = result.stdout + result.stderr
            flags = self._search_flags(output)
            
            return {
                'success': result.returncode == 0,
                'output': output,
                'flags': flags,
                'findings': []
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _search_flags(self, text: str) -> List[str]:
        """Search for flags in text"""
        import re
        
        flags = []
        patterns = self.config.get('flag_patterns', [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}'
        ])
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))
    
    def _parse_tool_output(self, tool_name: str, output: str, method: Dict) -> List[str]:
        """Parse tool-specific output for findings"""
        findings = []
        
        # Tool-specific parsing
        if tool_name == 'binwalk' and 'embedded' in output.lower():
            findings.append("Embedded files detected by binwalk")
        
        if tool_name == 'exiftool' and output:
            findings.append("Metadata extracted successfully")
        
        if tool_name == 'zsteg' and output.strip():
            findings.append("Steganography data found by zsteg")
        
        # Generic keyword detection
        keywords = method.get('success_keywords', [])
        for keyword in keywords:
            if keyword.lower() in output.lower():
                findings.append(f"Found keyword: {keyword}")
        
        return findings
    
    def _collect_flags_from_result(self, result: Dict) -> List[str]:
        """Recursively collect all flags from a result dictionary"""
        flags = []
        
        def search_dict(d):
            if isinstance(d, dict):
                if 'flags' in d and isinstance(d['flags'], list):
                    flags.extend(d['flags'])
                for value in d.values():
                    search_dict(value)
            elif isinstance(d, list):
                for item in d:
                    search_dict(item)
        
        search_dict(result)
        return list(set(flags))
