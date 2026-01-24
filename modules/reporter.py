"""
Reporter Module
Generates comprehensive scan reports in TXT and JSON formats
"""

import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, config):
        self.config = config
        self.output_dir = config.get('output_directory', 'output')
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_report(self, scan_results, target):
        """Generate comprehensive report"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate TXT report
        txt_report = self._generate_txt_report(scan_results, target, timestamp)
        txt_file = os.path.join(self.output_dir, 'report.txt')
        
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(txt_report)
        
        print(f"\n[+] Text report saved to: {txt_file}")
        
        # Generate JSON report
        json_report = self._generate_json_report(scan_results, target, timestamp)
        json_file = os.path.join(self.output_dir, 'report.json')
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=4, default=str)
        
        print(f"[+] JSON report saved to: {json_file}")
        
        # Save flags to separate file if found
        if 'flags' in scan_results or self._find_flags_in_results(scan_results):
            self._save_flags(scan_results)
        
        return {
            'txt_report': txt_file,
            'json_report': json_file
        }
    
    def _generate_txt_report(self, scan_results, target, timestamp):
        """Generate text report"""
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("CTFHunter Ultimate - Scan Report")
        report_lines.append("=" * 80)
        report_lines.append(f"\nTarget: {target}")
        report_lines.append(f"Scan Date: {timestamp}")
        report_lines.append(f"CTFHunter Version: 1.0")
        
        # Challenge Description (if provided)
        if 'challenge_info' in scan_results and scan_results['challenge_info'].get('description'):
            report_lines.append(f"\n📝 Challenge Description:")
            report_lines.append(f"   {scan_results['challenge_info']['description']}")
        
        report_lines.append("\n" + "=" * 80)
        
        # Executive Summary
        report_lines.append("\n[EXECUTIVE SUMMARY]")
        report_lines.append("-" * 80)
        
        summary = self._generate_summary(scan_results)
        for line in summary:
            report_lines.append(line)
        
        # Flags Found
        report_lines.append("\n\n[FLAGS DISCOVERED]")
        report_lines.append("-" * 80)
        
        flags = self._collect_all_flags(scan_results)
        if flags:
            for i, flag in enumerate(flags, 1):
                report_lines.append(f"{i}. {flag}")
        else:
            report_lines.append("No flags found in this scan")
        
        # Actions Performed
        report_lines.append("\n\n[ACTIONS PERFORMED]")
        report_lines.append("-" * 80)
        
        actions = self._list_actions(scan_results)
        for action in actions:
            report_lines.append(f"✓ {action}")
        
        # Key Findings
        report_lines.append("\n\n[KEY FINDINGS]")
        report_lines.append("-" * 80)
        
        findings = self._extract_findings(scan_results)
        for finding in findings:
            report_lines.append(f"\n• {finding}")
        
        # Extracted Files
        report_lines.append("\n\n[EXTRACTED FILES]")
        report_lines.append("-" * 80)
        
        extracted = self._list_extracted_files(scan_results)
        if extracted:
            for ext in extracted:
                report_lines.append(f"• {ext}")
        else:
            report_lines.append("No files were extracted")
        
        # Recommendations
        report_lines.append("\n\n[RECOMMENDED NEXT STEPS]")
        report_lines.append("-" * 80)
        
        recommendations = self._generate_recommendations(scan_results, target)
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"{i}. {rec}")
        
        # Footer
        report_lines.append("\n" + "=" * 80)
        report_lines.append("End of Report")
        report_lines.append("=" * 80)
        
        return '\n'.join(report_lines)
    
    def _generate_json_report(self, scan_results, target, timestamp):
        """Generate JSON report"""
        
        return {
            'metadata': {
                'target': target,
                'scan_date': timestamp,
                'ctfhunter_version': '1.0'
            },
            'summary': {
                'flags_found': len(self._collect_all_flags(scan_results)),
                'actions_performed': len(self._list_actions(scan_results)),
                'files_extracted': len(self._list_extracted_files(scan_results))
            },
            'flags': self._collect_all_flags(scan_results),
            'scan_results': scan_results,
            'recommendations': self._generate_recommendations(scan_results, target)
        }
    
    def _generate_summary(self, scan_results):
        """Generate executive summary"""
        summary = []
        
        if 'file_type' in scan_results:
            summary.append(f"File Type Detected: {scan_results['file_type']}")
        
        flags = self._collect_all_flags(scan_results)
        summary.append(f"Flags Discovered: {len(flags)}")
        
        if 'embedded_files' in scan_results:
            summary.append(f"Embedded Files: {len(scan_results['embedded_files'])}")
        
        if 'contents' in scan_results:
            summary.append(f"Extracted Files: {len(scan_results['contents'])}")
        
        return summary
    
    def _collect_all_flags(self, scan_results):
        """Recursively collect all flags from scan results"""
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
        
        search_dict(scan_results)
        
        # Remove duplicates
        return list(set(flags))
    
    def _find_flags_in_results(self, scan_results):
        """Check if any flags exist in results"""
        return len(self._collect_all_flags(scan_results)) > 0
    
    def _list_actions(self, scan_results):
        """List actions performed during scan"""
        actions = []
        
        if 'file_type' in scan_results:
            actions.append("File type detection")
        
        if 'metadata' in scan_results:
            actions.append("Metadata extraction")
        
        if 'strings' in scan_results:
            actions.append("Strings analysis")
        
        if 'embedded_files' in scan_results:
            actions.append("Embedded file detection")
        
        if 'stego_findings' in scan_results or 'zsteg' in scan_results:
            actions.append("Steganography analysis")
        
        if 'archive_type' in scan_results:
            actions.append("Archive extraction")
        
        if 'tcp_streams' in scan_results:
            actions.append("Network packet analysis")
        
        if 'checksec' in scan_results:
            actions.append("Binary security analysis")
        
        if 'html_analysis' in scan_results:
            actions.append("Web reconnaissance")
        
        return actions
    
    def _extract_findings(self, scan_results):
        """Extract key findings"""
        findings = []
        
        # Check for interesting metadata
        if 'metadata' in scan_results and isinstance(scan_results['metadata'], dict):
            for key, value in scan_results['metadata'].items():
                if any(keyword in key.lower() for keyword in ['author', 'creator', 'comment']):
                    findings.append(f"Metadata: {key} = {value}")
        
        # Check for dangerous functions
        if 'dangerous_functions' in scan_results and scan_results['dangerous_functions']:
            findings.append(f"Dangerous functions detected: {', '.join(scan_results['dangerous_functions'])}")
        
        # Check for hidden HTML content
        if 'html_analysis' in scan_results:
            html = scan_results['html_analysis']
            if html.get('comments'):
                findings.append(f"HTML comments found: {len(html['comments'])}")
            if html.get('hidden_inputs'):
                findings.append(f"Hidden input fields found: {len(html['hidden_inputs'])}")
        
        # Check for interesting files
        if 'interesting_files' in scan_results and scan_results['interesting_files']:
            findings.append(f"Interesting files found: {len(scan_results['interesting_files'])}")
        
        return findings
    
    def _list_extracted_files(self, scan_results):
        """List extracted files"""
        extracted = []
        
        if 'contents' in scan_results:
            for item in scan_results['contents']:
                if isinstance(item, dict) and 'relative_path' in item:
                    extracted.append(item['relative_path'])
        
        if 'http_objects' in scan_results:
            objs = scan_results['http_objects']
            if isinstance(objs, dict) and 'files' in objs:
                extracted.extend(objs['files'])
        
        return extracted
    
    def _generate_recommendations(self, scan_results, target="<file>"):
        """Generate intelligent recommendations based on findings"""
        recommendations = []
        
        # If flags found, we're done!
        if self._find_flags_in_results(scan_results):
            recommendations.append("✅ Flag(s) found! Challenge solved.")
            return recommendations
        
        # Analyze what was found and suggest next steps
        
        # Check for Base64 in metadata/EXIF
        if 'metadata' in scan_results:
            metadata = scan_results['metadata']
            import re
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            
            for key, value in (metadata.items() if isinstance(metadata, dict) else []):
                if isinstance(value, str) and re.search(base64_pattern, value):
                    recommendations.append(f"🔍 HINT: Found Base64-like string in {key}: '{value[:50]}...'")
                    recommendations.append(f"   💻 COMMAND: echo '{value}' | base64 -d")
                    recommendations.append(f"   💻 COMMAND: steghide extract -sf {target} -p $(echo '{value}' | base64 -d)")
        
        # Check for steghide-protected files
        if 'stego_findings' in scan_results or any('steghide' in str(v).lower() for v in str(scan_results).split()):
            if 'could not extract' in str(scan_results).lower():
                recommendations.append("🔍 HINT: Steghide data detected but needs a password")
                recommendations.append(f"   💻 COMMAND: steghide extract -sf {target} -p password")
                recommendations.append(f"   💻 COMMAND: stegseek {target} /usr/share/wordlists/rockyou.txt")
        
        # Check for embedded files
        if 'embedded_files' in scan_results and scan_results['embedded_files']:
            count = len(scan_results['embedded_files'])
            recommendations.append(f"🔍 HINT: Found {count} embedded file signature(s)")
            recommendations.append(f"   💻 COMMAND: binwalk -e {target}")
            recommendations.append(f"   💻 COMMAND: foremost -i {target} -o output_carved")
        
        # Check for encoded data patterns
        output_str = str(scan_results).lower()
        if 'hex' in output_str or 'base64' in output_str or 'base32' in output_str:
            recommendations.append("🔍 HINT: Encoded data detected in output")
            recommendations.append(f"   💻 COMMAND: strings {target} | grep -E '[A-Za-z0-9+/]{{20,}}' | base64 -d")
            recommendations.append(f"   💻 COMMAND: xxd -p {target} | tr -d '\\n' | xxd -r -p")
        
        # Archive-specific
        if 'archive_type' in scan_results:
            recommendations.append("🔍 HINT: Archive file detected")
            recommendations.append(f"   💻 COMMAND: 7z x {target}")
            recommendations.append(f"   💻 COMMAND: unzip -l {target}")
            recommendations.append(f"   💻 COMMAND: tar -tvf {target}")
        
        # Image-specific (PNG/JPG)
        if any(ext in str(scan_results.get('file_type', '')).lower() for ext in ['png', 'jpeg', 'jpg']):
            recommendations.append("🔍 HINT: Image file - try these techniques:")
            recommendations.append(f"   💻 COMMAND: zsteg -a {target}  # For PNG")
            recommendations.append(f"   💻 COMMAND: exiftool {target}")
            recommendations.append(f"   💻 COMMAND: steghide extract -sf {target} -p ''")
            recommendations.append(f"   💻 COMMAND: strings {target} | grep -i flag")
        
        # Binary-specific
        if 'checksec' in scan_results or 'elf' in str(scan_results.get('file_type', '')).lower():
            recommendations.append("🔍 HINT: Binary file detected")
            recommendations.append(f"   💻 COMMAND: ./{target}")
            recommendations.append(f"   💻 COMMAND: ltrace ./{target}")
            recommendations.append(f"   💻 COMMAND: strings {target} | grep -E '(flag|FLAG|picoCTF)'")
            recommendations.append(f"   💻 COMMAND: objdump -d {target} | less")
        
        # PCAP-specific
        if 'tcp_streams' in scan_results or 'pcap' in str(scan_results.get('file_type', '')).lower()):
            recommendations.append("🔍 HINT: Network capture detected")
            recommendations.append(f"   💻 COMMAND: wireshark {target}")
            recommendations.append(f"   💻 COMMAND: tshark -r {target} -Y http -T fields -e http.request.uri")
            recommendations.append(f"   💻 COMMAND: tshark -r {target} -Y dns -T fields -e dns.qry.name")
            recommendations.append(f"   💻 COMMAND: tcpflow -r {target}")
        
        # PDF-specific
        if 'pdf' in str(scan_results.get('file_type', '')).lower():
            recommendations.append("🔍 HINT: PDF file detected")
            recommendations.append(f"   💻 COMMAND: pdftotext {target} output.txt")
            recommendations.append(f"   💻 COMMAND: pdfdetach -list {target}")
            recommendations.append(f"   💻 COMMAND: strings {target} | grep -i flag")
        
        # Web-specific
        if 'html_analysis' in scan_results:
            html = scan_results['html_analysis']
            if html.get('comments'):
                recommendations.append(f"🔍 HINT: Found {len(html['comments'])} HTML comment(s)")
                recommendations.append(f"   💻 COMMAND: grep -o '<!--.*-->' {target}")
            if html.get('hidden_inputs'):
                recommendations.append(f"🔍 HINT: Found {len(html['hidden_inputs'])} hidden input(s)")
                recommendations.append(f"   💻 COMMAND: grep 'type=\"hidden\"' {target}")
        
        # Generic fallback - FILE CORRUPTION CHECK
        if not recommendations and scan_results.get('file_type') == 'data':
            recommendations.append("🔍 HINT: File appears corrupted or has wrong header")
            recommendations.append(f"   💻 COMMAND: xxd -l 32 {target}  # Check first 32 bytes")
            recommendations.append(f"   💻 COMMAND: file {target}")
            recommendations.append(f"   💻 COMMAND: binwalk {target}")
            # Add specific repair commands for common formats
            recommendations.append("   ")
            recommendations.append("   🔧 If it's a corrupted JPEG (look for JFIF in hex):")
            recommendations.append(f"   💻 COMMAND: printf '\\xff\\xd8\\xff' | dd of={target} bs=1 count=3 conv=notrunc")
            recommendations.append("   ")
            recommendations.append("   🔧 If it's a corrupted PNG (look for PNG in hex):")
            recommendations.append(f"   💻 COMMAND: printf '\\x89PNG\\r\\n\\x1a\\n' | dd of={target} bs=1 count=8 conv=notrunc")
        
        # Final fallback
        if not recommendations:
            recommendations.append("🔍 No obvious clues found. Try these commands:")
            recommendations.append(f"   💻 COMMAND: strings {target} | grep -iE '(flag|ctf|pico)'")
            recommendations.append(f"   💻 COMMAND: binwalk -e {target}")
            recommendations.append(f"   💻 COMMAND: xxd {target} | less")
            recommendations.append(f"   💻 COMMAND: file {target}")
        
        return recommendations
    
    def _save_flags(self, scan_results):
        """Save all found flags to results.txt"""
        flags = self._collect_all_flags(scan_results)
        
        if flags:
            results_file = os.path.join(self.output_dir, 'results.txt')
            
            with open(results_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("FLAGS DISCOVERED\n")
                f.write("=" * 60 + "\n\n")
                
                for i, flag in enumerate(flags, 1):
                    f.write(f"{i}. {flag}\n")
                
                f.write("\n" + "=" * 60 + "\n")
            
            print(f"[+] Flags saved to: {results_file}")
