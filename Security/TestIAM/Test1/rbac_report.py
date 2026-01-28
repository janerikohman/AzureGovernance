#!/usr/bin/env python3
"""
Azure RBAC Report Generator
Converts RBAC JSON output to HTML and Markdown reports with deduplication and grouping.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Set
from collections import defaultdict


def format_member(member):
    """Safely format member information handling both dict and string types."""
    if isinstance(member, dict):
        display_name = member.get('DisplayName', 'Unknown')
        object_type = member.get('ObjectType', 'Unknown')
        return f"{display_name} ({object_type})"
    elif isinstance(member, str):
        return member
    else:
        return str(member)


def load_rbac_file(filepath: Path) -> Dict[str, Any]:
    """Load RBAC JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def classify_role_risk(role_name: str) -> str:
    """Classify role risk level."""
    high_risk_keywords = [
        'Owner', 'Contributor', 'Administrator', 'Admin',
        'User Access Administrator', 'Role Based Access Control Administrator'
    ]
    
    medium_risk_keywords = [
        'Operator', 'Editor', 'Writer', 'Publisher'
    ]
    
    for keyword in high_risk_keywords:
        if keyword.lower() in role_name.lower():
            return 'High Risk'
    
    for keyword in medium_risk_keywords:
        if keyword.lower() in role_name.lower():
            return 'Medium Risk'
    
    return 'Standard'


def create_assignment_key(entry: Dict[str, Any]) -> str:
    """Create a unique key for grouping identical assignments."""
    return f"{entry['resource_name']}|{entry['role_name']}|{entry['principal_id']}|{entry['plane']}"


def group_assignments(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group identical assignments and track scopes.
    Returns a dict where each key represents a unique assignment,
    and the value includes all scopes this assignment appears at.
    """
    grouped = {}
    
    for entry in entries:
        key = create_assignment_key(entry)
        
        if key not in grouped:
            grouped[key] = entry.copy()
            grouped[key]['scopes'] = [entry['scope']]
            grouped[key]['scope_count'] = 1
            grouped[key]['all_entries'] = [entry]
        else:
            # Track multiple scopes for same assignment
            if entry['scope'] not in grouped[key]['scopes']:
                grouped[key]['scopes'].append(entry['scope'])
                grouped[key]['scope_count'] += 1
            grouped[key]['all_entries'].append(entry)
    
    return grouped


def extract_rbac_entries(rbac_data: Dict[str, Any], filter_type: str = 'all') -> List[Dict[str, Any]]:
    """
    Extract RBAC assignments from the data.
    
    Args:
        rbac_data: RBAC data dictionary
        filter_type: 'all', 'direct' (resource-level only), or 'inherited' (from parent scopes)
    
    Returns:
        List of assignments with context.
    """
    entries = []
    metadata = rbac_data.get('metadata', {})
    
    for resource in rbac_data.get('resources', []):
        resource_name = resource['resourceName']
        resource_type = resource['resourceType']
        resource_id = resource['resourceId']
        
        # Process control plane roles
        for role_name, assignments in resource['controlPlane'].items():
            for assignment in assignments:
                is_inherited = assignment['isInherited']
                
                # Apply filter
                if filter_type == 'direct' and is_inherited:
                    continue
                if filter_type == 'inherited' and not is_inherited:
                    continue
                
                entry = {
                    'resource_name': resource_name,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'role_name': role_name,
                    'plane': 'Control Plane',
                    'principal_id': assignment['principalId'],
                    'principal_type': assignment['principalType'],
                    'display_name': assignment['displayName'],
                    'sign_in_name': assignment['signInName'],
                    'scope': assignment['scope'],
                    'is_inherited': is_inherited,
                    'members': assignment.get('members', []),
                    'risk_level': classify_role_risk(role_name)
                }
                entries.append(entry)
        
        # Process data plane roles
        for role_name, assignments in resource['dataPlane'].items():
            for assignment in assignments:
                is_inherited = assignment['isInherited']
                
                # Apply filter
                if filter_type == 'direct' and is_inherited:
                    continue
                if filter_type == 'inherited' and not is_inherited:
                    continue
                
                entry = {
                    'resource_name': resource_name,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'role_name': role_name,
                    'plane': 'Data Plane',
                    'principal_id': assignment['principalId'],
                    'principal_type': assignment['principalType'],
                    'display_name': assignment['displayName'],
                    'sign_in_name': assignment['signInName'],
                    'scope': assignment['scope'],
                    'is_inherited': is_inherited,
                    'members': assignment.get('members', []),
                    'risk_level': classify_role_risk(role_name)
                }
                entries.append(entry)
    
    return entries


def generate_markdown_report(rbac_data: Dict[str, Any], entries: List[Dict[str, Any]], grouped: Dict[str, Any], output_path: Path, filter_type: str = 'all'):
    """Generate Markdown report."""
    lines = []
    metadata = rbac_data.get('metadata', {})
    
    # Header
    lines.append("# Azure RBAC Assignment Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Original Report:** {metadata.get('generatedAt', 'Unknown')}")
    lines.append("")
    
    # Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Subscription:** {metadata.get('subscriptionName', 'Unknown')} ({metadata.get('subscriptionId', 'Unknown')})")
    lines.append(f"- **Resource Group:** {metadata.get('resourceGroup', 'Unknown')}")
    lines.append(f"- **Resources Analyzed:** {metadata.get('resourceCount', 0)}")
    lines.append(f"- **Filter:** {filter_type.capitalize()} assignments only")
    lines.append(f"- **Total Role Assignments (Raw):** {len(entries)}")
    lines.append(f"- **Unique Assignments:** {len(grouped)}")
    lines.append(f"- **Include Inherited:** {'Yes' if metadata.get('includeInherited') else 'No'}")
    lines.append(f"- **Include Group Members:** {'Yes' if metadata.get('listMembers') else 'No'}")
    lines.append("")
    
    # Risk summary
    risk_counts = defaultdict(int)
    for entry in grouped.values():
        risk_counts[entry['risk_level']] += 1
    
    if risk_counts:
        lines.append("## Risk Summary")
        lines.append("")
        lines.append(f"- **High Risk Roles:** {risk_counts['High Risk']}")
        lines.append(f"- **Medium Risk Roles:** {risk_counts['Medium Risk']}")
        lines.append(f"- **Standard Roles:** {risk_counts['Standard']}")
        lines.append("")
    
    # High risk assignments
    high_risk = [e for e in grouped.values() if e['risk_level'] == 'High Risk']
    if high_risk:
        lines.append("## ⚠️ High Risk Role Assignments")
        lines.append("")
        for entry in high_risk:
            lines.append(f"### {entry['role_name']}")
            lines.append("")
            lines.append(f"**Resource:** {entry['resource_name']} ({entry['resource_type']})")
            lines.append("")
            lines.append(f"**Principal:** {entry['display_name']} ({entry['principal_type']})")
            lines.append("")
            
            if entry['scope_count'] > 1:
                lines.append(f"**Scopes ({entry['scope_count']}):**")
                lines.append("")
                for scope in entry['scopes']:
                    lines.append(f"- {scope}")
                lines.append("")
            else:
                lines.append(f"**Scope:** {entry['scope']}")
                lines.append("")
            
            lines.append(f"**Plane:** {entry['plane']}")
            lines.append("")
            lines.append(f"**Inherited:** {'Yes' if entry['is_inherited'] else 'No'}")
            lines.append("")
            
            # Show members if available
            if entry['members']:
                lines.append("**Group Members:**")
                lines.append("")
                for member in entry['members']:
                    lines.append(f"- {format_member(member)}")
                lines.append("")
            
            lines.append("---")
            lines.append("")
    
    # By resource summary
    lines.append("## Role Assignments by Resource")
    lines.append("")
    
    by_resource = defaultdict(list)
    for entry in grouped.values():
        by_resource[entry['resource_name']].append(entry)
    
    for resource_name in sorted(by_resource.keys()):
        resource_entries = by_resource[resource_name]
        resource_type = resource_entries[0]['resource_type']
        lines.append(f"### {resource_name} ({resource_type})")
        lines.append("")
        
        # Group by plane
        by_plane = defaultdict(list)
        for entry in resource_entries:
            by_plane[entry['plane']].append(entry)
        
        for plane in ['Control Plane', 'Data Plane']:
            plane_entries = by_plane.get(plane, [])
            if not plane_entries:
                continue
            
            lines.append(f"#### {plane}")
            lines.append("")
            
            # Group by role
            by_role = defaultdict(list)
            for entry in plane_entries:
                by_role[entry['role_name']].append(entry)
            
            for role_name in sorted(by_role.keys()):
                role_entries = by_role[role_name]
                risk = role_entries[0]['risk_level']
                lines.append(f"**{role_name}** ({risk})")
                lines.append("")
                
                for entry in role_entries:
                    inherited_marker = " (inherited)" if entry['is_inherited'] else ""
                    scope_marker = f" [{entry['scope_count']} scope(s)]" if entry['scope_count'] > 1 else ""
                    lines.append(f"- {entry['display_name']}{inherited_marker}{scope_marker}")
                
                lines.append("")
        
        lines.append("")
    
    # By role
    lines.append("## Role Assignments by Role")
    lines.append("")
    
    by_plane = defaultdict(list)
    for entry in grouped.values():
        by_plane[entry['plane']].append(entry)
    
    for plane in ['Control Plane', 'Data Plane']:
        plane_entries = by_plane.get(plane, [])
        if not plane_entries:
            continue
        
        lines.append(f"### {plane}")
        lines.append("")
        
        by_role = defaultdict(list)
        for entry in plane_entries:
            by_role[entry['role_name']].append(entry)
        
        for role_name in sorted(by_role.keys()):
            role_entries = by_role[role_name]
            risk_level = role_entries[0]['risk_level']
            
            lines.append(f"#### {role_name} ({risk_level})")
            lines.append("")
            lines.append("| Resource | Resource Type | Principal | Type | Inherited | Scopes |")
            lines.append("|----------|---------------|-----------|------|-----------|--------|")
            
            for entry in role_entries:
                inherited_str = "Yes" if entry['is_inherited'] else "No"
                scope_info = f"{entry['scope_count']} scopes" if entry['scope_count'] > 1 else "1 scope"
                lines.append(f"| {entry['resource_name']} | {entry['resource_type']} | {entry['display_name']} | {entry['principal_type']} | {inherited_str} | {scope_info} |")
            
            lines.append("")
        
        lines.append("")
    
    # Inherited assignments
    inherited = [e for e in grouped.values() if e['is_inherited']]
    if inherited:
        lines.append("## Inherited Role Assignments")
        lines.append("")
        lines.append(f"Total inherited assignments: {len(inherited)}")
        lines.append("")
        
        by_source = defaultdict(list)
        for entry in inherited:
            scope = entry['scope']
            if '/subscriptions/' in scope and '/resourcegroups/' not in scope:
                source = 'Subscription'
            elif '/resourcegroups/' in scope:
                source = 'Resource Group'
            else:
                source = 'Management Group'
            by_source[source].append(entry)
        
        for source in sorted(by_source.keys()):
            source_entries = by_source[source]
            lines.append(f"### From {source} ({len(source_entries)} assignments)")
            lines.append("")
            for entry in source_entries:
                lines.append(f"- {entry['role_name']}: {entry['display_name']}")
            lines.append("")
    
    # Complete summary table
    lines.append("## Appendix: Complete Assignment Summary")
    lines.append("")
    lines.append("| Resource | Role | Principal | Type | Plane | Risk | Inherited | Scopes |")
    lines.append("|----------|------|-----------|------|-------|------|-----------|--------|")
    for entry in sorted(grouped.values(), key=lambda x: x['resource_name']):
        inherited_str = "Yes" if entry['is_inherited'] else "No"
        scope_info = f"{entry['scope_count']} scopes" if entry['scope_count'] > 1 else "1 scope"
        lines.append(f"| {entry['resource_name']} | {entry['role_name']} | {entry['display_name']} | {entry['principal_type']} | {entry['plane']} | {entry['risk_level']} | {inherited_str} | {scope_info} |")
    lines.append("")
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def generate_html_report(rbac_data: Dict[str, Any], entries: List[Dict[str, Any]], grouped: Dict[str, Any], output_path: Path, filter_type: str = 'all'):
    """Generate HTML report."""
    html = []
    metadata = rbac_data.get('metadata', {})
    
    # HTML header
    html.append("""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Azure RBAC Assignment Report</title>
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
            color: #2a4b8d;
            border-bottom: 3px solid #2a4b8d;
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
        .risk-high { color: #d13438; font-weight: bold; }
        .risk-medium { color: #ff6b00; font-weight: bold; }
        .risk-standard { color: #107c10; font-weight: bold; }
        .assignment-card {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
            background-color: #fafafa;
        }
        .assignment-card.high-risk { border-left: 5px solid #d13438; }
        .assignment-card.medium-risk { border-left: 5px solid #ff6b00; }
        .assignment-card.standard-risk { border-left: 5px solid #107c10; }
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
        .badge-standard {
            background-color: #dffcf0;
            color: #107c10;
        }
        .badge-control { background-color: #e7eef9; color: #2a4b8d; }
        .badge-data { background-color: #f1ebe0; color: #8a4d00; }
        .inherited { font-style: italic; color: #666; }
        .members-list {
            background-color: #f5f5f5;
            border-left: 3px solid #0078d4;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
        }
        .members-list ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .scopes-list {
            background-color: #f0f0f0;
            border-left: 3px solid #107c10;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
        }
        .scopes-list ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .scope-badge {
            background-color: #e8f4f8;
            color: #004b50;
            padding: 2px 6px;
            border-radius: 2px;
            font-size: 0.8em;
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
            border-radius: 2px;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="container">
""")
    
    # Title
    html.append("<h1>🔐 Azure RBAC Assignment Report</h1>")
    html.append(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
    
    # Summary box
    html.append('<div class="summary-box">')
    html.append('<h2>Executive Summary</h2>')
    html.append('<ul>')
    html.append(f'<li><strong>Subscription:</strong> {metadata.get("subscriptionName", "Unknown")} ({metadata.get("subscriptionId", "Unknown")})</li>')
    html.append(f'<li><strong>Resource Group:</strong> {metadata.get("resourceGroup", "Unknown")}</li>')
    html.append(f'<li><strong>Resources Analyzed:</strong> {metadata.get("resourceCount", 0)}</li>')
    html.append(f'<li><strong>Filter:</strong> {filter_type.capitalize()} assignments only</li>')
    html.append(f'<li><strong>Total Role Assignments (Raw):</strong> {len(entries)}</li>')
    html.append(f'<li><strong>Unique Assignments:</strong> {len(grouped)}</li>')
    html.append(f'<li><strong>Include Inherited:</strong> {"Yes" if metadata.get("includeInherited") else "No"}</li>')
    html.append(f'<li><strong>Include Group Members:</strong> {"Yes" if metadata.get("listMembers") else "No"}</li>')
    html.append('</ul>')
    html.append('</div>')
    
    # Calculate risk counts early for index
    risk_counts = defaultdict(int)
    for entry in grouped.values():
        risk_counts[entry['risk_level']] += 1
    
    # Table of Contents / Index
    html.append('<div class="summary-box" style="background-color: #f9f9f9; border-left-color: #666;">')
    html.append('<h2>📑 Quick Navigation</h2>')
    html.append('<ul style="list-style: none; padding-left: 0;">')
    html.append(f'<li>📊 <a href="#risk-summary">Risk Summary</a></li>')
    html.append(f'<li>🔴 <a href="#high-risk">High Risk Assignments</a> ({risk_counts.get("High Risk", 0)})</li>')
    html.append(f'<li>🟠 <a href="#medium-risk">Medium Risk Assignments</a> ({risk_counts.get("Medium Risk", 0)})</li>')
    html.append(f'<li>🟢 <a href="#standard-risk">Standard Assignments</a> ({risk_counts.get("Standard", 0)})</li>')
    html.append(f'<li>📋 <a href="#by-resource">Role Assignments by Resource</a></li>')
    html.append(f'<li>🎭 <a href="#by-role">Role Assignments by Role</a></li>')
    html.append('</ul>')
    html.append('</div>')
    
    # Risk summary
    
    html.append('<h2 id="risk-summary">Risk Summary</h2>')
    html.append('<ul>')
    html.append(f'<li><span class="risk-high">High Risk Roles:</span> {risk_counts["High Risk"]}</li>')
    html.append(f'<li><span class="risk-medium">Medium Risk Roles:</span> {risk_counts["Medium Risk"]}</li>')
    html.append(f'<li><span class="risk-standard">Standard Roles:</span> {risk_counts["Standard"]}</li>')
    html.append('</ul>')
    
    # High risk assignments
    high_risk = [e for e in grouped.values() if e['risk_level'] == 'High Risk']
    if high_risk:
        html.append('<details class="section-collapsible" open>')
        html.append('<summary><h2 id="high-risk">⚠️ High Risk Role Assignments</h2></summary>')
        for entry in high_risk:
            inherited_class = 'inherited' if entry['is_inherited'] else ''
            html.append(f'<div class="assignment-card high-risk">')
            html.append(f'<h3>{entry["role_name"]}</h3>')
            html.append(f'<p><strong>Resource:</strong> {entry["resource_name"]} <em>({entry["resource_type"]})</em></p>')
            html.append(f'<p><strong>Principal:</strong> {entry["display_name"]} ({entry["principal_type"]})</p>')
            
            # Show scopes
            if entry['scope_count'] > 1:
                html.append(f'<div class="scopes-list">')
                html.append(f'<strong>Scopes ({entry["scope_count"]}):</strong>')
                html.append('<ul>')
                for scope in entry['scopes']:
                    html.append(f'<li><span class="scope-badge">{scope}</span></li>')
                html.append('</ul>')
                html.append('</div>')
            else:
                html.append(f'<p><strong>Scope:</strong> <span class="{inherited_class}">{entry["scope"]}</span></p>')
            
            html.append(f'<p><strong>Plane:</strong> <span class="badge badge-{entry["plane"].lower().replace(" ", "-")}">{entry["plane"]}</span></p>')
            html.append(f'<p><strong>Inherited:</strong> {"Yes" if entry["is_inherited"] else "No"}</p>')
            
            # Show members if available
            if entry['members']:
                html.append('<div class="members-list">')
                html.append('<strong>Group Members:</strong>')
                html.append('<ul>')
                for member in entry['members']:
                    html.append(f'<li>{format_member(member)}</li>')
                html.append('</ul>')
                html.append('</div>')
            
            html.append('</div>')
        html.append('</details>')
    
    # Medium risk assignments
    medium_risk = [e for e in grouped.values() if e['risk_level'] == 'Medium Risk']
    if medium_risk:
        html.append('<details class="section-collapsible" open>')
        html.append('<summary><h2 id="medium-risk">🟠 Medium Risk Role Assignments</h2></summary>')
        for entry in medium_risk:
            inherited_class = 'inherited' if entry['is_inherited'] else ''
            html.append(f'<div class="assignment-card medium-risk">')
            html.append(f'<h3>{entry["role_name"]}</h3>')
            html.append(f'<p><strong>Resource:</strong> {entry["resource_name"]} <em>({entry["resource_type"]})</em></p>')
            html.append(f'<p><strong>Principal:</strong> {entry["display_name"]} ({entry["principal_type"]})</p>')
            
            # Show scopes
            if entry['scope_count'] > 1:
                html.append(f'<div class="scopes-list">')
                html.append(f'<strong>Scopes ({entry["scope_count"]}):</strong>')
                html.append('<ul>')
                for scope in entry['scopes']:
                    html.append(f'<li><span class="scope-badge">{scope}</span></li>')
                html.append('</ul>')
                html.append('</div>')
            else:
                html.append(f'<p><strong>Scope:</strong> <span class="{inherited_class}">{entry["scope"]}</span></p>')
            
            html.append(f'<p><strong>Plane:</strong> <span class="badge badge-{entry["plane"].lower().replace(" ", "-")}">{entry["plane"]}</span></p>')
            html.append(f'<p><strong>Inherited:</strong> {"Yes" if entry["is_inherited"] else "No"}</p>')
            
            # Show members if available
            if entry['members']:
                html.append('<div class="members-list">')
                html.append('<strong>Group Members:</strong>')
                html.append('<ul>')
                for member in entry['members']:
                    html.append(f'<li>{format_member(member)}</li>')
                html.append('</ul>')
                html.append('</div>')
            
            html.append('</div>')
        html.append('</details>')
    
    # Standard assignments
    standard = [e for e in grouped.values() if e['risk_level'] == 'Standard']
    if standard:
        html.append('<details class="section-collapsible">')
        html.append('<summary><h2 id="standard-risk">🟢 Standard Role Assignments</h2></summary>')
        for entry in standard:
            inherited_class = 'inherited' if entry['is_inherited'] else ''
            html.append(f'<div class="assignment-card standard-risk">')
            html.append(f'<h3>{entry["role_name"]}</h3>')
            html.append(f'<p><strong>Resource:</strong> {entry["resource_name"]} <em>({entry["resource_type"]})</em></p>')
            html.append(f'<p><strong>Principal:</strong> {entry["display_name"]} ({entry["principal_type"]})</p>')
            
            # Show scopes
            if entry['scope_count'] > 1:
                html.append(f'<div class="scopes-list">')
                html.append(f'<strong>Scopes ({entry["scope_count"]}):</strong>')
                html.append('<ul>')
                for scope in entry['scopes']:
                    html.append(f'<li><span class="scope-badge">{scope}</span></li>')
                html.append('</ul>')
                html.append('</div>')
            else:
                html.append(f'<p><strong>Scope:</strong> <span class="{inherited_class}">{entry["scope"]}</span></p>')
            
            html.append(f'<p><strong>Plane:</strong> <span class="badge badge-{entry["plane"].lower().replace(" ", "-")}">{entry["plane"]}</span></p>')
            html.append(f'<p><strong>Inherited:</strong> {"Yes" if entry["is_inherited"] else "No"}</p>')
            
            # Show members if available
            if entry['members']:
                html.append('<div class="members-list">')
                html.append('<strong>Group Members:</strong>')
                html.append('<ul>')
                for member in entry['members']:
                    html.append(f'<li>{format_member(member)}</li>')
                html.append('</ul>')
                html.append('</div>')
            
            html.append('</div>')
        html.append('</details>')
    
    # By resource
    html.append('<details class="section-collapsible" open>')
    html.append('<summary><h2 id="by-resource">📋 Role Assignments by Resource</h2></summary>')
    by_resource = defaultdict(list)
    for entry in grouped.values():
        by_resource[entry['resource_name']].append(entry)
    
    for resource_name in sorted(by_resource.keys()):
        resource_entries = by_resource[resource_name]
        resource_type = resource_entries[0]['resource_type']
        html.append(f'<h3>{resource_name} <em style="font-size: 0.8em; color: #666;">({resource_type})</em></h3>')
        
        by_plane = defaultdict(list)
        for entry in resource_entries:
            by_plane[entry['plane']].append(entry)
        
        for plane in ['Control Plane', 'Data Plane']:
            plane_entries = by_plane.get(plane, [])
            if not plane_entries:
                continue
            
            html.append(f'<h4>{plane}</h4>')
            html.append('<table>')
            html.append('<tr><th>Role</th><th>Principal</th><th>Type</th><th>Risk</th><th>Inherited</th><th>Scopes</th></tr>')
            
            for entry in plane_entries:
                risk_class = entry['risk_level'].lower().replace(' ', '-')
                inherited_str = "Yes" if entry['is_inherited'] else "No"
                scope_info = f"{entry['scope_count']}" if entry['scope_count'] > 1 else "1"
                html.append(f'<tr>')
                html.append(f'<td>{entry["role_name"]}</td>')
                html.append(f'<td>{entry["display_name"]}</td>')
                html.append(f'<td>{entry["principal_type"]}</td>')
                html.append(f'<td><span class="badge badge-{risk_class}">{entry["risk_level"]}</span></td>')
                html.append(f'<td>{inherited_str}</td>')
                html.append(f'<td>{scope_info}</td>')
                html.append(f'</tr>')
            
            html.append('</table>')
    html.append('</details>')
    
    # By role
    html.append('<details class="section-collapsible" open>')
    html.append('<summary><h2 id="by-role">🎭 Role Assignments by Role</h2></summary>')
    
    by_plane = defaultdict(list)
    for entry in grouped.values():
        by_plane[entry['plane']].append(entry)
    
    for plane in ['Control Plane', 'Data Plane']:
        plane_entries = by_plane.get(plane, [])
        if not plane_entries:
            continue
        
        html.append(f'<h3>{plane}</h3>')
        
        by_role = defaultdict(list)
        for entry in plane_entries:
            by_role[entry['role_name']].append(entry)
        
        for role_name in sorted(by_role.keys()):
            role_entries = by_role[role_name]
            risk_level = role_entries[0]['risk_level']
            risk_class = risk_level.lower().replace(' ', '-')
            
            html.append(f'<h4>{role_name} <span class="badge badge-{risk_class}">{risk_level}</span></h4>')
            html.append('<table>')
            html.append('<tr><th>Resource</th><th>Resource Type</th><th>Principal</th><th>Type</th><th>Inherited</th><th>Scopes</th></tr>')
            
            for entry in role_entries:
                inherited_str = "Yes" if entry['is_inherited'] else "No"
                scope_info = f"{entry['scope_count']}" if entry['scope_count'] > 1 else "1"
                html.append(f'<tr>')
                html.append(f'<td>{entry["resource_name"]}</td>')
                html.append(f'<td>{entry["resource_type"]}</td>')
                html.append(f'<td>{entry["display_name"]}</td>')
                html.append(f'<td>{entry["principal_type"]}</td>')
                html.append(f'<td>{inherited_str}</td>')
                html.append(f'<td>{scope_info}</td>')
                html.append(f'</tr>')
            
            html.append('</table>')
    
    html.append('</details>')
    
    # Inherited assignments
    inherited = [e for e in grouped.values() if e['is_inherited']]
    if inherited:
        html.append('<details class="section-collapsible">')
        html.append(f'<summary><h2 id="inherited">🔗 Inherited Role Assignments ({len(inherited)} total)</h2></summary>')
        
        by_source = defaultdict(list)
        for entry in inherited:
            scope = entry['scope']
            if '/subscriptions/' in scope and '/resourcegroups/' not in scope:
                source = 'Subscription'
            elif '/resourcegroups/' in scope:
                source = 'Resource Group'
            else:
                source = 'Management Group'
            by_source[source].append(entry)
        
        for source in sorted(by_source.keys()):
            source_entries = by_source[source]
            html.append(f'<h3>From {source} ({len(source_entries)} assignments)</h3>')
            html.append('<ul>')
            for entry in source_entries:
                html.append(f'<li>{entry["role_name"]}: {entry["display_name"]}</li>')
            html.append('</ul>')
    
    # Complete table
    html.append('<h2>Appendix: Complete Assignment Summary</h2>')
    html.append('<table>')
    html.append('<tr><th>Resource</th><th>Role</th><th>Principal</th><th>Type</th><th>Plane</th><th>Risk</th><th>Inherited</th><th>Scopes</th></tr>')
    for entry in sorted(grouped.values(), key=lambda x: x['resource_name']):
        inherited_str = "Yes" if entry['is_inherited'] else "No"
        risk_class = entry['risk_level'].lower().replace(' ', '-')
        plane_class = entry['plane'].lower().replace(' ', '-')
        scope_info = f"{entry['scope_count']}"
        html.append(f'<tr>')
        html.append(f'<td>{entry["resource_name"]}</td>')
        html.append(f'<td>{entry["role_name"]}</td>')
        html.append(f'<td>{entry["display_name"]}</td>')
        html.append(f'<td>{entry["principal_type"]}</td>')
        html.append(f'<td><span class="badge badge-{plane_class}">{entry["plane"]}</span></td>')
        html.append(f'<td><span class="badge badge-{risk_class}">{entry["risk_level"]}</span></td>')
        html.append(f'<td>{inherited_str}</td>')
        html.append(f'<td>{scope_info}</td>')
        html.append(f'</tr>')
    html.append('</table>')
    if inherited:
        html.append('</details>')
    
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
        description='Generate RBAC reports from Azure RBAC JSON files',
        epilog='Examples:\n  python rbac_report.py report.json\n  python rbac_report.py report.json --filter inherited\n  python rbac_report.py report.json --filter direct --output-dir ./reports'
    )
    parser.add_argument(
        'input',
        type=str,
        help='Path to RBAC JSON file'
    )
    parser.add_argument(
        '--filter',
        type=str,
        choices=['all', 'direct', 'inherited'],
        default='all',
        help='Filter assignments: all (default), direct (resource-level only), inherited (from parent scopes)'
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
    
    print(f"Loading RBAC file: {input_path}")
    rbac_data = load_rbac_file(input_path)
    
    print(f"Extracting RBAC entries ({args.filter} filter)...")
    entries = extract_rbac_entries(rbac_data, filter_type=args.filter)
    print(f"Found {len(entries)} total role assignments")
    
    print("Grouping and deduplicating assignments...")
    grouped = group_assignments(entries)
    print(f"Found {len(grouped)} unique assignments (after grouping)")
    
    # Extract resource group name for filename
    resource_group = rbac_data.get('metadata', {}).get('resourceGroup', 'rbac')
    
    # Generate reports with filter type and resource group name
    md_path = output_dir / f'rbac_report-{resource_group}-{args.filter}.md'
    html_path = output_dir / f'rbac_report-{resource_group}-{args.filter}.html'
    
    print(f"Generating markdown report: {md_path}")
    generate_markdown_report(rbac_data, entries, grouped, md_path, filter_type=args.filter)
    
    print(f"Generating HTML report: {html_path}")
    generate_html_report(rbac_data, entries, grouped, html_path, filter_type=args.filter)
    
    # Summary
    risk_counts = defaultdict(int)
    for entry in grouped.values():
        risk_counts[entry['risk_level']] += 1
    
    print("\n" + "="*60)
    print("Report Summary:")
    print(f"  - Filter: {args.filter.upper()}")
    print(f"  - Raw Assignments: {len(entries)}")
    print(f"  - Unique Assignments: {len(grouped)}")
    print(f"  - High Risk: {risk_counts.get('High Risk', 0)}")
    print(f"  - Medium Risk: {risk_counts.get('Medium Risk', 0)}")
    print(f"  - Standard: {risk_counts.get('Standard', 0)}")
    print("="*60)


if __name__ == '__main__':
    main()
