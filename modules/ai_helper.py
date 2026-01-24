"""
AI Helper Module
Provides AI-powered hints and explanations (optional with API key)
"""

import os
import json


class AIHelper:
    def __init__(self, config):
        self.config = config
        self.api_key = config.get('openai_api_key', '')
        
    def is_available(self):
        """Check if AI helper is available"""
        return bool(self.api_key)
    
    def get_hint(self, scan_results):
        """Get AI hint based on scan results"""
        if not self.is_available():
            print("⚠️  AI Helper not configured. Set 'openai_api_key' in config.json")
            return None
        
        try:
            import openai
            
            # Set API key
            openai.api_key = self.api_key
            
            # Prepare prompt
            prompt = self._build_prompt(scan_results)
            
            print("[*] Requesting AI analysis...")
            
            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert CTF player and cybersecurity analyst. Analyze the scan results and provide actionable hints for solving the challenge. Focus on explaining the findings and suggesting next forensic steps. Never guess random flags - only discuss flags that were actually found in the scan."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            hint = response.choices[0].message.content
            
            print("\n" + "="*60)
            print("🤖 AI HINT:")
            print("="*60)
            print(hint)
            print("="*60 + "\n")
            
            return hint
            
        except ImportError:
            print("❌ OpenAI library not installed. Install with: pip install openai")
            return None
        except Exception as e:
            print(f"❌ AI Helper error: {str(e)}")
            return None
    
    def _build_prompt(self, scan_results):
        """Build prompt from scan results"""
        
        # Summarize findings
        summary = {
            'file_type': scan_results.get('file_type', 'Unknown'),
            'findings': []
        }
        
        # Add flags if found
        if 'flags' in scan_results:
            summary['findings'].append(f"Flags found: {scan_results['flags']}")
        
        # Add embedded files
        if 'embedded_files' in scan_results:
            summary['findings'].append(f"Embedded files detected: {len(scan_results['embedded_files'])}")
        
        # Add steganography results
        if 'stego_findings' in scan_results:
            summary['findings'].append("Steganography analysis performed")
        
        # Add archive results
        if 'archive_type' in scan_results:
            summary['findings'].append(f"Archive type: {scan_results['archive_type']}")
        
        # Add PCAP results
        if 'tcp_streams' in scan_results:
            summary['findings'].append(f"TCP streams analyzed: {len(scan_results['tcp_streams'])}")
        
        # Add binary results
        if 'dangerous_functions' in scan_results:
            summary['findings'].append(f"Dangerous functions: {scan_results['dangerous_functions']}")
        
        # Add web results
        if 'html_analysis' in scan_results:
            summary['findings'].append("Web page analyzed")
        
        prompt = f"""
CTF Challenge Analysis:

File Type: {summary['file_type']}

Scan Findings:
{chr(10).join(['- ' + f for f in summary['findings']])}

Based on these scan results, please:
1. Explain what the findings indicate
2. Suggest the next forensic or analysis steps
3. Identify potential attack vectors or hidden data locations
4. Recommend specific tools or techniques to try next

Do NOT guess flags. Only discuss flags that were actually found in the scan results.
"""
        
        return prompt
    
    def explain_finding(self, finding_type, details):
        """Get explanation for specific finding"""
        if not self.is_available():
            return None
        
        try:
            import openai
            openai.api_key = self.api_key
            
            prompt = f"Explain this CTF finding and suggest next steps:\n\nType: {finding_type}\nDetails: {details}"
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a CTF expert. Provide concise, actionable explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=300
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Error: {str(e)}")
            return None
