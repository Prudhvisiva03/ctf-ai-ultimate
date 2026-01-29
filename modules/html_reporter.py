#!/usr/bin/env python3
"""
HTML Report Generator - Generate beautiful HTML reports for CTF analysis
Professional reports for CTF competitions and showcases
Author: Prudhvi (CTFHunter)
Version: 2.1.0
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional


class HTMLReporter:
    """Generate professional HTML reports for CTF analysis"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = self.config.get('output_directory', 'output')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(self, results: Dict, target: str = "Unknown") -> str:
        """Generate HTML report from analysis results"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Extract data from results
        flags = results.get('flags', [])
        findings = results.get('findings', [])
        methods = results.get('methods_executed', [])
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTFHunter Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            border-radius: 20px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        
        .logo {{
            font-size: 3em;
            font-weight: bold;
            background: linear-gradient(45deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .subtitle {{
            color: #888;
            margin-top: 10px;
            font-size: 1.1em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #1e3a5f 0%, #16213e 100%);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00d4ff;
        }}
        
        .stat-label {{
            color: #888;
            margin-top: 5px;
        }}
        
        .section {{
            background: linear-gradient(135deg, #1e3a5f 0%, #16213e 100%);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }}
        
        .section-title {{
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #00d4ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .flag-found {{
            background: linear-gradient(135deg, #00ff88 0%, #00d4ff 100%);
            color: #1a1a2e;
            padding: 15px 25px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 1.2em;
            font-weight: bold;
            margin: 10px 0;
            word-break: break-all;
            box-shadow: 0 5px 20px rgba(0,255,136,0.3);
        }}
        
        .no-flag {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            text-align: center;
        }}
        
        .finding-item {{
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #00d4ff;
        }}
        
        .method-item {{
            display: flex;
            align-items: center;
            padding: 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            margin: 5px 0;
        }}
        
        .method-status {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 15px;
        }}
        
        .status-success {{
            background: #00ff88;
            box-shadow: 0 0 10px #00ff88;
        }}
        
        .status-failed {{
            background: #ff6b6b;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
        }}
        
        .info-label {{
            color: #888;
        }}
        
        .info-value {{
            color: #00d4ff;
            word-break: break-all;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 30px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            margin: 5px;
        }}
        
        .badge-success {{
            background: #00ff88;
            color: #1a1a2e;
        }}
        
        .badge-info {{
            background: #00d4ff;
            color: #1a1a2e;
        }}
        
        .badge-warning {{
            background: #ffd93d;
            color: #1a1a2e;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr 1fr;
            }}
            .logo {{
                font-size: 2em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🏴‍☠️ CTFHunter</div>
            <div class="subtitle">AI-Powered CTF Analysis Report</div>
            <div style="margin-top: 15px;">
                <span class="badge badge-info">v2.1.0</span>
                <span class="badge badge-success">Analysis Complete</span>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{len(flags)}</div>
                <div class="stat-label">🚩 Flags Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(findings)}</div>
                <div class="stat-label">🔍 Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(methods)}</div>
                <div class="stat-label">🔧 Methods Used</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{'✅' if flags else '❌'}</div>
                <div class="stat-label">Status</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📁 Target Information</div>
            <div class="info-grid">
                <div class="info-label">Target:</div>
                <div class="info-value">{target}</div>
                <div class="info-label">Scan Time:</div>
                <div class="info-value">{timestamp}</div>
                <div class="info-label">Tool:</div>
                <div class="info-value">CTFHunter v2.1.0</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">🚩 Flags</div>
            {self._render_flags(flags)}
        </div>
        
        <div class="section">
            <div class="section-title">🔍 Findings</div>
            {self._render_findings(findings)}
        </div>
        
        <div class="section">
            <div class="section-title">🔧 Methods Executed</div>
            {self._render_methods(methods)}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>CTFHunter</strong> - World's First AI-Powered CTF Assistant</p>
            <p style="margin-top: 10px;">
                <a href="https://github.com/Prudhvisiva03/ctfhunter" style="color: #00d4ff;">GitHub</a>
            </p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                Made with ❤️ by Prudhvi
            </p>
        </div>
    </div>
</body>
</html>'''
        
        # Save report
        report_path = os.path.join(self.output_dir, 'report.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_path
    
    def _render_flags(self, flags: List[str]) -> str:
        """Render flags section"""
        if not flags:
            return '<div class="no-flag">❌ No flags found yet. Keep analyzing!</div>'
        
        html = ''
        for flag in flags:
            html += f'<div class="flag-found">🚩 {flag}</div>'
        return html
    
    def _render_findings(self, findings: List) -> str:
        """Render findings section"""
        if not findings:
            return '<div class="finding-item">No specific findings recorded.</div>'
        
        html = ''
        for finding in findings[:20]:  # Limit to 20
            if isinstance(finding, dict):
                text = finding.get('message', str(finding))
            else:
                text = str(finding)
            html += f'<div class="finding-item">{text}</div>'
        return html
    
    def _render_methods(self, methods: List) -> str:
        """Render methods section"""
        if not methods:
            return '<div class="method-item"><span class="method-status status-success"></span>Analysis completed</div>'
        
        html = ''
        for method in methods:
            if isinstance(method, dict):
                name = method.get('name', 'Unknown')
                success = method.get('success', True)
            else:
                name = str(method)
                success = True
            
            status_class = 'status-success' if success else 'status-failed'
            html += f'''<div class="method-item">
                <span class="method-status {status_class}"></span>
                <span>{name}</span>
            </div>'''
        return html


def generate_html_report(results: Dict, target: str = "Unknown", config: Dict = None) -> str:
    """Convenience function to generate HTML report"""
    reporter = HTMLReporter(config)
    return reporter.generate(results, target)


if __name__ == "__main__":
    # Demo report
    demo_results = {
        'flags': ['digitalcyberhunt{th1s_1s_a_t3st_fl4g}', 'flag{demo_flag}'],
        'findings': [
            '🔍 Found hidden data in PNG chunks',
            '📱 QR Code detected and decoded',
            '🔐 Base64 encoded string found',
            '📍 GPS coordinates extracted: 17.3850, 78.4867'
        ],
        'methods_executed': [
            {'name': 'File Type Analysis', 'success': True},
            {'name': 'Zsteg Scan', 'success': True},
            {'name': 'EXIF Extraction', 'success': True},
            {'name': 'String Analysis', 'success': True},
            {'name': 'Binwalk Extraction', 'success': False}
        ]
    }
    
    reporter = HTMLReporter()
    report_path = reporter.generate(demo_results, "demo_challenge.png")
    print(f"✅ Demo report generated: {report_path}")
