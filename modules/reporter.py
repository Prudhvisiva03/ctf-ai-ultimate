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
        
        recommendations = self._generate_recommendations(scan_results)
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
            'recommendations': self._generate_recommendations(scan_results)
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
    
    def _generate_recommendations(self, scan_results):
        """Generate recommendations for next steps"""
        recommendations = []
        
        # Generic recommendations
        if not self._find_flags_in_results(scan_results):
            recommendations.append("No flags found - consider manual analysis of extracted files")
        
        # Archive-specific
        if 'archive_type' in scan_results:
            recommendations.append("Scan extracted files individually for hidden data")
        
        # Stego-specific
        if 'stego_findings' in scan_results:
            recommendations.append("Try additional steganography tools (outguess, stegpy, etc.)")
        
        # Binary-specific
        if 'checksec' in scan_results:
            recommendations.append("Perform dynamic analysis with gdb or radare2")
            recommendations.append("Check for hardcoded strings or encoding schemes")
        
        # Web-specific
        if 'html_analysis' in scan_results:
            recommendations.append("Test for SQL injection, XSS, or other web vulnerabilities")
            recommendations.append("Analyze client-side JavaScript for logic flaws")
        
        # PCAP-specific
        if 'tcp_streams' in scan_results:
            recommendations.append("Analyze extracted HTTP objects for hidden data")
            recommendations.append("Look for covert channels in DNS or ICMP")
        
        # PDF-specific
        if 'pdfinfo' in scan_results:
            recommendations.append("Check for alternate data streams or embedded JavaScript")
        
        # If no specific recommendations
        if not recommendations:
            recommendations.append("Manual review of scan results recommended")
            recommendations.append("Try different analysis tools or techniques")
        
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
