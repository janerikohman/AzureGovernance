#!/usr/bin/env python3
"""
Azure RBAC Anomalies Report Generator
Converts anomalies JSON to HTML and Markdown reports.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict


def load_anomalies_file(filepath: Path) -> Dict[str, Any]:
    """Load anomalies JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_markdown_report(anomalies_data: Dict[str, Any], output_path: Path):
    """Generate Markdown report for anomalies."""
    lines = []
    summary = anomalies_data.get('summary', {})
    anomalies = anomalies_data.get('anomalies', [])
    metadata = anomalies_data.get('metadata', {})
    
    # Header
    lines.append("# Azure RBAC Anomalies Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if metadata.get('generatedAt'):
        lines.append(f"**Original Report:** {metadata.get('generatedAt', 'Unknown')}")
    lines.append("")
    
    # Summary
    lines.append("## Executive Summary")
    lines.append("")
    
    # Include metadata if available
    if metadata:
        lines.append(f"- **Subscription:** {metadata.get('subscriptionName', 'Unknown')} ({metadata.get('subscriptionId', 'Unknown')})")
        lines.append(f"- **Resource Group:** {metadata.get('resourceGroup', 'Unknown')}")
        lines.append(f"- **Resources Analyzed:** {metadata.get('resourceCount', 0)}")
        filter_type = 'Direct assignments only' if not metadata.get('includeInherited') else 'All assignments (including inherited)'
        lines.append(f"- **Filter:** {filter_type}")
        lines.append(f"- **Include Inherited:** {'Yes' if metadata.get('includeInherited') else 'No'}")
        lines.append(f"- **Include Group Members:** {'Yes' if metadata.get('listMembers') else 'No'}")
        lines.append("")
    
    lines.append(f"- **Total Anomalies:** {summary.get('total', 0)}")
    lines.append(f"- **High Severity:** {summary.get('high', 0)}")
    lines.append(f"- **Medium Severity:** {summary.get('medium', 0)}")
    lines.append(f"- **Low Severity:** {summary.get('low', 0)}")
    lines.append("")
    
    if summary.get('total', 0) == 0:
        lines.append("✅ **No anomalies detected!**")
        lines.append("")
    else:
        lines.append("---")
        lines.append("")
        
        # Group by severity
        by_severity = defaultdict(list)
        for anomaly in anomalies:
            by_severity[anomaly['severity']].append(anomaly)
        
        severity_order = ['HIGH', 'MEDIUM', 'LOW']
        severity_emoji = {
            'HIGH': '🔴',
            'MEDIUM': '🟠',
            'LOW': '🟡'
        }
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            
            anomalies_list = by_severity[severity]
            lines.append(f"## {severity_emoji[severity]} {severity} Severity ({len(anomalies_list)} issues)")
            lines.append("")
            
            # Group by category
            by_category = defaultdict(list)
            for anomaly in anomalies_list:
                by_category[anomaly['category']].append(anomaly)
            
            for category, items in by_category.items():
                lines.append(f"### {category} ({len(items)} issues)")
                lines.append("")
                
                for i, anomaly in enumerate(items, 1):
                    lines.append(f"#### Issue {i}: {anomaly['resource_name']}")
                    lines.append("")
                    lines.append(f"- **Resource Type:** {anomaly['resource_type']}")
                    lines.append(f"- **Role:** {anomaly['role']} ({anomaly['plane']})")
                    lines.append(f"- **Principal:** {anomaly['principal']} ({anomaly['principal_type']})")
                    lines.append(f"- **Scope:** `{anomaly['scope']}`")
                    lines.append("")
                    lines.append(f"⚠️ **Issue:** {anomaly['reason']}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")
    
    # Summary table
    if anomalies:
        lines.append("## Appendix: All Anomalies Summary")
        lines.append("")
        lines.append("| Severity | Category | Resource | Role | Principal | Reason |")
        lines.append("|----------|----------|----------|------|-----------|--------|")
        for anomaly in anomalies:
            lines.append(f"| {anomaly['severity']} | {anomaly['category']} | {anomaly['resource_name']} | {anomaly['role']} | {anomaly['principal']} | {anomaly['reason']} |")
        lines.append("")
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def generate_html_report(anomalies_data: Dict[str, Any], output_path: Path):
    """Generate HTML report for anomalies."""
    html = []
    summary = anomalies_data.get('summary', {})
    anomalies = anomalies_data.get('anomalies', [])
    metadata = anomalies_data.get('metadata', {})
    
    # HTML header with styling
    html.append("""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Azure RBAC Anomalies Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #d13438;
            border-bottom: 3px solid #d13438;
            padding-bottom: 10px;
        }
        h2 {
            color: #2a4b8d;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        h3 {
            color: #333;
            margin-top: 20px;
        }
        .summary-box {
            background-color: #f0f4f8;
            border-left: 4px solid #2a4b8d;
            padding: 15px;
            margin: 20px 0;
        }
        .summary-box ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .summary-box.success {
            background-color: #dffcf0;
            border-left-color: #107c10;
        }
        .severity-high { color: #d13438; font-weight: bold; }
        .severity-medium { color: #ff6b00; font-weight: bold; }
        .severity-low { color: #107c10; font-weight: bold; }
        .anomaly-card {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
            background-color: #fafafa;
        }
        .anomaly-card.high { border-left: 5px solid #d13438; }
        .anomaly-card.medium { border-left: 5px solid #ff6b00; }
        .anomaly-card.low { border-left: 5px solid #ffc83d; }
        .anomaly-card h4 {
            margin-top: 0;
            color: #333;
        }
        .anomaly-reason {
            background-color: #fff4ce;
            border-left: 3px solid #ff6b00;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
            font-weight: 500;
        }
        .anomaly-reason.high {
            background-color: #fed5d7;
            border-left-color: #d13438;
        }
        .anomaly-reason.low {
            background-color: #fff9e6;
            border-left-color: #ffc83d;
        }
        .scope-code {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 5px 8px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85em;
            word-break: break-all;
            display: block;
            margin: 5px 0;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-size: 0.9em;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #2a4b8d;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge-high {
            background-color: #fed5d7;
            color: #d13438;
        }
        .badge-medium {
            background-color: #fff4ce;
            color: #ff6b00;
        }
        .badge-low {
            background-color: #fff9e6;
            color: #ffc83d;
        }
        .section-collapsible {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            background-color: #fafafa;
        }
        .section-collapsible summary {
            cursor: pointer;
            font-weight: bold;
            padding: 5px;
            user-select: none;
        }
        .section-collapsible summary:hover {
            background-color: #f0f0f0;
            border-radius: 2px;
        }
        .section-collapsible summary h2 {
            margin: 0;
            padding: 0;
            display: inline;
            font-size: 1.5em;
        }
        .section-collapsible[open] {
            background-color: #fff;
        }
        .detail-item {
            margin: 8px 0;
        }
        .detail-label {
            font-weight: bold;
            color: #555;
        }
        .no-anomalies {
            text-align: center;
            padding: 40px;
            font-size: 1.2em;
            color: #107c10;
        }
    </style>
</head>
<body>
    <div class="container">
""")
    
    # Title
    html.append("<h1>⚠️ Azure RBAC Anomalies Report</h1>")
    html.append(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
    if metadata.get('generatedAt'):
        html.append(f"<p><strong>Original Report:</strong> {metadata.get('generatedAt', 'Unknown')}</p>")
    
    # Summary box
    if summary.get('total', 0) == 0:
        html.append('<div class="summary-box success">')
        html.append('<div class="no-anomalies">✅ No anomalies detected!</div>')
        html.append('</div>')
    else:
        html.append('<div class="summary-box">')
        html.append('<h2>Executive Summary</h2>')
        html.append('<ul>')
        
        # Include metadata if available
        if metadata:
            html.append(f'<li><strong>Subscription:</strong> {metadata.get("subscriptionName", "Unknown")} ({metadata.get("subscriptionId", "Unknown")})</li>')
            html.append(f'<li><strong>Resource Group:</strong> {metadata.get("resourceGroup", "Unknown")}</li>')
            html.append(f'<li><strong>Resources Analyzed:</strong> {metadata.get("resourceCount", 0)}</li>')
            filter_type = 'Direct assignments only' if not metadata.get('includeInherited') else 'All assignments (including inherited)'
            html.append(f'<li><strong>Filter:</strong> {filter_type}</li>')
            html.append(f'<li><strong>Include Inherited:</strong> {"Yes" if metadata.get("includeInherited") else "No"}</li>')
            html.append(f'<li><strong>Include Group Members:</strong> {"Yes" if metadata.get("listMembers") else "No"}</li>')
        
        html.append(f'<li><strong>Total Anomalies:</strong> {summary.get("total", 0)}</li>')
        html.append(f'<li><span class="severity-high">High Severity:</span> {summary.get("high", 0)}</li>')
        html.append(f'<li><span class="severity-medium">Medium Severity:</span> {summary.get("medium", 0)}</li>')
        html.append(f'<li><span class="severity-low">Low Severity:</span> {summary.get("low", 0)}</li>')
        html.append('</ul>')
        html.append('</div>')
        
        # Table of Contents
        by_severity = defaultdict(list)
        for anomaly in anomalies:
            by_severity[anomaly['severity']].append(anomaly)
        
        html.append('<div class="summary-box" style="background-color: #f9f9f9; border-left-color: #666;">')
        html.append('<h2>📑 Quick Navigation</h2>')
        html.append('<ul style="list-style: none; padding-left: 0;">')
        if 'HIGH' in by_severity:
            html.append(f'<li>🔴 <a href="#high-severity">High Severity Issues</a> ({len(by_severity["HIGH"])})</li>')
        if 'MEDIUM' in by_severity:
            html.append(f'<li>🟠 <a href="#medium-severity">Medium Severity Issues</a> ({len(by_severity["MEDIUM"])})</li>')
        if 'LOW' in by_severity:
            html.append(f'<li>🟡 <a href="#low-severity">Low Severity Issues</a> ({len(by_severity["LOW"])})</li>')
        html.append(f'<li>📋 <a href="#summary-table">Complete Summary Table</a></li>')
        html.append('</ul>')
        html.append('</div>')
        
        # Anomalies by severity
        severity_order = ['HIGH', 'MEDIUM', 'LOW']
        severity_emoji = {
            'HIGH': '🔴',
            'MEDIUM': '🟠',
            'LOW': '🟡'
        }
        severity_anchor = {
            'HIGH': 'high-severity',
            'MEDIUM': 'medium-severity',
            'LOW': 'low-severity'
        }
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            
            anomalies_list = by_severity[severity]
            html.append('<details class="section-collapsible" open>')
            html.append(f'<summary><h2 id="{severity_anchor[severity]}">{severity_emoji[severity]} {severity} Severity ({len(anomalies_list)} issues)</h2></summary>')
            
            # Group by category
            by_category = defaultdict(list)
            for anomaly in anomalies_list:
                by_category[anomaly['category']].append(anomaly)
            
            for category, items in by_category.items():
                html.append(f'<h3>📌 {category} ({len(items)} issues)</h3>')
                
                for i, anomaly in enumerate(items, 1):
                    severity_class = severity.lower()
                    html.append(f'<div class="anomaly-card {severity_class}">')
                    html.append(f'<h4>Issue {i}: {anomaly["resource_name"]}</h4>')
                    
                    html.append('<div class="detail-item">')
                    html.append(f'<span class="detail-label">Resource Type:</span> {anomaly["resource_type"]}')
                    html.append('</div>')
                    
                    html.append('<div class="detail-item">')
                    html.append(f'<span class="detail-label">Role:</span> {anomaly["role"]} ({anomaly["plane"]})')
                    html.append('</div>')
                    
                    html.append('<div class="detail-item">')
                    html.append(f'<span class="detail-label">Principal:</span> {anomaly["principal"]} ({anomaly["principal_type"]})')
                    html.append('</div>')
                    
                    html.append('<div class="detail-item">')
                    html.append(f'<span class="detail-label">Scope:</span>')
                    html.append(f'<code class="scope-code">{anomaly["scope"]}</code>')
                    html.append('</div>')
                    
                    html.append(f'<div class="anomaly-reason {severity_class}">')
                    html.append(f'⚠️ <strong>Issue:</strong> {anomaly["reason"]}')
                    html.append('</div>')
                    
                    html.append('</div>')
            
            html.append('</details>')
        
        # Summary table
        html.append('<h2 id="summary-table">Appendix: All Anomalies Summary</h2>')
        html.append('<table>')
        html.append('<tr><th>Severity</th><th>Category</th><th>Resource</th><th>Type</th><th>Role</th><th>Principal</th><th>Reason</th></tr>')
        for anomaly in anomalies:
            severity_class = anomaly['severity'].lower()
            html.append(f'<tr>')
            html.append(f'<td><span class="badge badge-{severity_class}">{anomaly["severity"]}</span></td>')
            html.append(f'<td>{anomaly["category"]}</td>')
            html.append(f'<td>{anomaly["resource_name"]}</td>')
            html.append(f'<td>{anomaly["resource_type"]}</td>')
            html.append(f'<td>{anomaly["role"]}</td>')
            html.append(f'<td>{anomaly["principal"]}</td>')
            html.append(f'<td>{anomaly["reason"]}</td>')
            html.append(f'</tr>')
        html.append('</table>')
    
    # Footer
    html.append("""
    </div>
</body>
</html>
""")
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))


def main():
    parser = argparse.ArgumentParser(
        description='Generate anomalies reports from RBAC anomalies JSON files',
        epilog='Example:\n  python anomalies_report.py anomalies.json'
    )
    parser.add_argument(
        'input',
        type=str,
        help='Path to anomalies JSON file'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='./reports',
        help='Directory to write report files (default: ./reports)'
    )
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    if not input_path.is_file():
        print(f"Error: {input_path} is not a file", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loading anomalies file: {input_path}")
    anomalies_data = load_anomalies_file(input_path)
    
    summary = anomalies_data.get('summary', {})
    total = summary.get('total', 0)
    
    print(f"Found {total} anomalies:")
    print(f"  - High: {summary.get('high', 0)}")
    print(f"  - Medium: {summary.get('medium', 0)}")
    print(f"  - Low: {summary.get('low', 0)}")
    
    # Extract base name from input file
    base_name = input_path.stem
    
    # Generate reports
    md_path = output_dir / f'{base_name}-report.md'
    html_path = output_dir / f'{base_name}-report.html'
    
    print(f"\nGenerating markdown report: {md_path}")
    generate_markdown_report(anomalies_data, md_path)
    
    print(f"Generating HTML report: {html_path}")
    generate_html_report(anomalies_data, html_path)
    
    print("\n" + "="*60)
    print("Anomalies Report Generation Complete!")
    print(f"  - Markdown: {md_path}")
    print(f"  - HTML: {html_path}")
    print("="*60)


if __name__ == '__main__':
    main()
