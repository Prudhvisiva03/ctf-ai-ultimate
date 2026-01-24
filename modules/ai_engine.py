"""
AI Engine - Multi-Provider AI Support
Supports: OpenAI, Ollama, Claude, Groq, and offline mode
"""

import os
import json
import subprocess
from typing import Dict, List, Optional, Any


class AIEngine:
    """Intelligent AI engine with multi-provider support"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.provider = config.get('ai_provider', 'openai')
        self.model = config.get('ai_model', 'gpt-4')
        self.api_key = config.get('openai_api_key', '')
        
        # Initialize based on provider
        self._initialize_provider()
    
    def _initialize_provider(self):
        """Initialize the selected AI provider"""
        if self.provider == 'openai':
            self._init_openai()
        elif self.provider == 'ollama':
            self._init_ollama()
        elif self.provider == 'claude':
            self._init_claude()
        elif self.provider == 'groq':
            self._init_groq()
        elif self.provider == 'none':
            print("[*] AI disabled - running in manual mode")
        else:
            print(f"⚠️  Unknown AI provider: {self.provider}, falling back to manual mode")
            self.provider = 'none'
    
    def _init_openai(self):
        """Initialize OpenAI"""
        try:
            import openai
            if self.api_key:
                openai.api_key = self.api_key
                print(f"✅ OpenAI initialized (Model: {self.model})")
            else:
                print("⚠️  OpenAI API key not set, switching to offline mode")
                self.provider = 'none'
        except ImportError:
            print("⚠️  OpenAI library not installed. Run: pip install openai")
            self.provider = 'none'
    
    def _init_ollama(self):
        """Initialize Ollama (local AI)"""
        try:
            # Check if Ollama is running
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"✅ Ollama initialized (Model: {self.model})")
            else:
                print("⚠️  Ollama not running. Start with: ollama serve")
                self.provider = 'none'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("⚠️  Ollama not installed. Visit: https://ollama.ai")
            self.provider = 'none'
    
    def _init_claude(self):
        """Initialize Claude"""
        try:
            import anthropic
            claude_key = self.config.get('claude_api_key', '')
            if claude_key:
                print(f"✅ Claude initialized (Model: {self.model})")
            else:
                print("⚠️  Claude API key not set")
                self.provider = 'none'
        except ImportError:
            print("⚠️  Anthropic library not installed. Run: pip install anthropic")
            self.provider = 'none'
    
    def _init_groq(self):
        """Initialize Groq"""
        try:
            groq_key = self.config.get('groq_api_key', '')
            if groq_key:
                print(f"✅ Groq initialized (Model: {self.model})")
            else:
                print("⚠️  Groq API key not set")
                self.provider = 'none'
        except Exception as e:
            print(f"⚠️  Groq initialization failed: {e}")
            self.provider = 'none'
    
    def is_available(self) -> bool:
        """Check if AI is available"""
        return self.provider != 'none'
    
    def analyze_challenge(self, file_info: Dict, scan_results: Dict = None) -> Dict:
        """
        Analyze a CTF challenge and determine the approach
        
        Returns:
            {
                'challenge_type': 'png_stego',
                'confidence': 0.95,
                'recommended_playbook': 'png_stego',
                'reasoning': 'Detected PNG image with suspicious file size...',
                'alternative_playbooks': ['generic_stego', 'file_carving']
            }
        """
        if not self.is_available():
            return self._fallback_analysis(file_info)
        
        # Build analysis prompt
        prompt = self._build_analysis_prompt(file_info, scan_results)
        
        try:
            # Get AI response
            response = self._query_ai(prompt, system_prompt=self._get_analyzer_system_prompt())
            
            # Parse response
            analysis = self._parse_analysis_response(response)
            
            return analysis
            
        except Exception as e:
            print(f"⚠️  AI analysis failed: {e}")
            return self._fallback_analysis(file_info)
    
    def suggest_next_steps(self, current_results: Dict, playbook_history: List[str]) -> Dict:
        """
        Suggest next steps based on current findings
        
        Returns:
            {
                'next_playbook': 'alternative_method',
                'reasoning': 'Previous methods found embedded file, try extracting...',
                'confidence': 0.8,
                'stop': False  # or True if no more steps
            }
        """
        if not self.is_available():
            return {'stop': True, 'reasoning': 'No AI available for suggestions'}
        
        prompt = self._build_suggestion_prompt(current_results, playbook_history)
        
        try:
            response = self._query_ai(prompt, system_prompt=self._get_advisor_system_prompt())
            suggestions = self._parse_suggestion_response(response)
            return suggestions
        except Exception as e:
            print(f"⚠️  AI suggestion failed: {e}")
            return {'stop': True, 'reasoning': str(e)}
    
    def interpret_tool_output(self, tool_name: str, output: str) -> Dict:
        """
        Interpret tool output using AI
        
        Returns:
            {
                'flags_found': ['flag{example}'],
                'interesting_findings': ['Embedded ZIP file at offset 0x1234'],
                'recommendations': ['Extract embedded file', 'Analyze ZIP contents'],
                'confidence': 0.9
            }
        """
        if not self.is_available():
            return self._simple_output_parse(output)
        
        prompt = f"""
Analyze this output from {tool_name}:

{output[:2000]}  # Limit output size

Identify:
1. Any flags (flag{{...}}, FLAG{{...}}, ctf{{...}})
2. Interesting findings (embedded files, suspicious strings, etc.)
3. Recommended next actions

Respond in JSON format.
"""
        
        try:
            response = self._query_ai(prompt, system_prompt=self._get_interpreter_system_prompt())
            interpretation = self._parse_json_response(response)
            return interpretation
        except Exception as e:
            print(f"⚠️  AI interpretation failed: {e}")
            return self._simple_output_parse(output)
    
    def _query_ai(self, prompt: str, system_prompt: str = "", temperature: float = 0.7) -> str:
        """Query the configured AI provider"""
        
        if self.provider == 'openai':
            return self._query_openai(prompt, system_prompt, temperature)
        elif self.provider == 'ollama':
            return self._query_ollama(prompt, system_prompt, temperature)
        elif self.provider == 'claude':
            return self._query_claude(prompt, system_prompt, temperature)
        elif self.provider == 'groq':
            return self._query_groq(prompt, system_prompt, temperature)
        else:
            return ""
    
    def _query_openai(self, prompt: str, system_prompt: str, temperature: float) -> str:
        """Query OpenAI API"""
        import openai
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=1500
        )
        
        return response.choices[0].message.content
    
    def _query_ollama(self, prompt: str, system_prompt: str, temperature: float) -> str:
        """Query Ollama local AI"""
        import requests
        
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': self.model,
                'prompt': full_prompt,
                'stream': False,
                'temperature': temperature
            },
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json().get('response', '')
        else:
            raise Exception(f"Ollama query failed: {response.status_code}")
    
    def _query_claude(self, prompt: str, system_prompt: str, temperature: float) -> str:
        """Query Claude API"""
        import anthropic
        
        client = anthropic.Anthropic(api_key=self.config.get('claude_api_key'))
        
        message = client.messages.create(
            model=self.model,
            max_tokens=1500,
            temperature=temperature,
            system=system_prompt,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return message.content[0].text
    
    def _query_groq(self, prompt: str, system_prompt: str, temperature: float) -> str:
        """Query Groq API"""
        import requests
        
        headers = {
            'Authorization': f'Bearer {self.config.get("groq_api_key")}',
            'Content-Type': 'application/json'
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers=headers,
            json={
                'model': self.model,
                'messages': messages,
                'temperature': temperature,
                'max_tokens': 1500
            },
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            raise Exception(f"Groq query failed: {response.status_code}")
    
    def _build_analysis_prompt(self, file_info: Dict, scan_results: Dict = None) -> str:
        """Build prompt for challenge analysis"""
        prompt = f"""
Analyze this CTF challenge:

File Information:
- Filename: {file_info.get('filename', 'unknown')}
- Type: {file_info.get('type', 'unknown')}
- Size: {file_info.get('size', 0)} bytes
- Extension: {file_info.get('extension', 'unknown')}
"""
        
        if scan_results:
            prompt += f"\nInitial Scan Results:\n{json.dumps(scan_results, indent=2)[:500]}"
        
        prompt += """

Determine:
1. Most likely challenge type (stego, forensics, crypto, web, binary, etc.)
2. Recommended playbook to use
3. Confidence level (0-1)
4. Your reasoning
5. Alternative approaches if primary fails

Respond in JSON format:
{
    "challenge_type": "png_stego",
    "recommended_playbook": "png_stego",
    "confidence": 0.9,
    "reasoning": "explanation",
    "alternative_playbooks": ["list", "of", "alternatives"]
}
"""
        return prompt
    
    def _build_suggestion_prompt(self, current_results: Dict, playbook_history: List[str]) -> str:
        """Build prompt for next steps suggestion"""
        prompt = f"""
Current CTF Progress:

Playbooks Already Tried:
{json.dumps(playbook_history, indent=2)}

Current Findings:
{json.dumps(current_results, indent=2)[:1000]}

Based on the results so far, what should we try next?

Respond in JSON:
{{
    "next_playbook": "playbook_name" or null,
    "reasoning": "explanation",
    "confidence": 0.8,
    "stop": false  # true if no more steps recommended
}}
"""
        return prompt
    
    def _get_analyzer_system_prompt(self) -> str:
        """System prompt for challenge analyzer"""
        return """You are an expert CTF player and challenge analyzer. 
Your job is to analyze CTF challenges and determine the best approach to solve them.
Be specific about challenge types and recommend concrete playbooks.
Base your analysis on evidence, not guesses."""
    
    def _get_advisor_system_prompt(self) -> str:
        """System prompt for next-steps advisor"""
        return """You are an expert CTF strategist.
Based on current findings, suggest the next best approach.
If no flags have been found yet, recommend alternative methods.
If a flag has been found, recommend stopping or verifying the result."""
    
    def _get_interpreter_system_prompt(self) -> str:
        """System prompt for tool output interpreter"""
        return """You are an expert at interpreting security tool outputs.
Identify flags, interesting findings, and recommend next actions.
Return results in clean JSON format."""
    
    def _parse_analysis_response(self, response: str) -> Dict:
        """Parse AI analysis response"""
        try:
            # Try to extract JSON from response
            data = self._parse_json_response(response)
            return data
        except:
            # Fallback parsing
            return {
                'challenge_type': 'unknown',
                'recommended_playbook': 'generic',
                'confidence': 0.5,
                'reasoning': response,
                'alternative_playbooks': []
            }
    
    def _parse_suggestion_response(self, response: str) -> Dict:
        """Parse AI suggestion response"""
        try:
            return self._parse_json_response(response)
        except:
            return {
                'stop': True,
                'reasoning': 'Failed to parse AI response'
            }
    
    def _parse_json_response(self, response: str) -> Dict:
        """Extract and parse JSON from AI response"""
        # Try to find JSON in response
        import re
        
        # Look for JSON block
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            return json.loads(json_str)
        
        # If no JSON found, try parsing entire response
        return json.loads(response)
    
    def _fallback_analysis(self, file_info: Dict) -> Dict:
        """Simple rule-based analysis when AI is not available"""
        ext = file_info.get('extension', '').lower()
        file_type = file_info.get('type', '').lower()
        
        # Simple mapping
        if ext in ['.png', '.bmp']:
            return {
                'challenge_type': 'png_stego',
                'recommended_playbook': 'png_stego',
                'confidence': 0.7,
                'reasoning': 'PNG/BMP image detected - trying steganography',
                'alternative_playbooks': ['generic_stego', 'file_carving']
            }
        elif ext in ['.jpg', '.jpeg']:
            return {
                'challenge_type': 'jpg_stego',
                'recommended_playbook': 'jpg_stego',
                'confidence': 0.7,
                'reasoning': 'JPEG image detected - trying steganography',
                'alternative_playbooks': ['generic_stego']
            }
        elif ext in ['.zip', '.tar', '.gz', '.rar', '.7z']:
            return {
                'challenge_type': 'archive',
                'recommended_playbook': 'archive_analysis',
                'confidence': 0.8,
                'reasoning': 'Archive file detected',
                'alternative_playbooks': []
            }
        elif ext in ['.pcap', '.pcapng']:
            return {
                'challenge_type': 'pcap',
                'recommended_playbook': 'pcap_analysis',
                'confidence': 0.9,
                'reasoning': 'PCAP file detected',
                'alternative_playbooks': []
            }
        elif ext == '.pdf':
            return {
                'challenge_type': 'pdf',
                'recommended_playbook': 'pdf_forensics',
                'confidence': 0.8,
                'reasoning': 'PDF file detected',
                'alternative_playbooks': []
            }
        elif 'elf' in file_type or ext in ['', '.elf', '.bin']:
            return {
                'challenge_type': 'binary',
                'recommended_playbook': 'binary_analysis',
                'confidence': 0.7,
                'reasoning': 'Binary/ELF file detected',
                'alternative_playbooks': []
            }
        else:
            return {
                'challenge_type': 'unknown',
                'recommended_playbook': 'generic',
                'confidence': 0.5,
                'reasoning': 'Unknown file type - trying generic analysis',
                'alternative_playbooks': ['file_carving', 'strings_analysis']
            }
    
    def _simple_output_parse(self, output: str) -> Dict:
        """Simple parsing when AI is not available"""
        import re
        
        # Search for flags
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}'
        ]
        
        flags = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            flags.extend(matches)
        
        return {
            'flags_found': list(set(flags)),
            'interesting_findings': [],
            'recommendations': [],
            'confidence': 0.5
        }
